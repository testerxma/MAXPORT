"""Traces of what already ran, even after the process is gone.

Every other module here looks at the present: a live connection, a running
process, a port open right now. But the most common intrusion of 2026 does
not linger. ClickFix — a fake CAPTCHA that walks the victim through pasting
a command into the Run box or a terminal — fires in seconds: PowerShell or
mshta or curl downloads a payload, runs it, and exits. By the time a
connection scan arrives, the process that mattered is gone and there is
nothing live to catch.

So this module reads the record instead of the moment. The Run-box history,
the PowerShell operational log and the shell history all remember the exact
command that executed after the process itself has vanished. That turns the
question from "is something connected now?" into "what ran on this machine
in the last hour?" — which is the question that actually catches ClickFix.

Nothing here is inherently malicious: a developer legitimately types
PowerShell. The signal is the shape of the command — a hidden window
fetching and directly executing remote content — not its mere presence.
"""

from __future__ import annotations

import glob
import os
import platform
import re
import subprocess

IS_WINDOWS = platform.system() == "Windows"

# The fingerprints of a paste-and-run payload, shared across platforms.
# Each is a fetch, a decode, or a direct-execute that legitimate interactive
# use almost never combines in a single line.
PAYLOAD_MARKERS = (
    ("iex", "pipes downloaded text straight into execution"),
    ("invoke-expression", "executes a string as code"),
    ("downloadstring", "fetches remote content into memory"),
    ("downloadfile", "downloads a file to disk"),
    ("frombase64string", "decodes a base64 blob"),
    ("-enc", "runs a base64-encoded command, hiding its content"),
    ("-encodedcommand", "runs a base64-encoded command, hiding its content"),
    ("-w hidden", "runs with no visible window"),
    ("-windowstyle hidden", "runs with no visible window"),
    ("bitsadmin", "uses the transfer service to download"),
    ("certutil", "the certificate tool used to fetch or decode"),
    ("mshta", "runs remote script through the HTML host"),
    ("curl ", "downloads content"),
    ("wget ", "downloads content"),
    ("/dev/tcp/", "opens a raw network socket from the shell"),
    ("base64 -d", "decodes a base64 blob"),
    ("base64 --decode", "decodes a base64 blob"),
    ("| sh", "pipes fetched content into a shell"),
    ("|sh", "pipes fetched content into a shell"),
    ("| bash", "pipes fetched content into a shell"),
    ("|bash", "pipes fetched content into a shell"),
)


def _run(cmd: list[str], timeout: int = 25) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        return r.stdout or ""
    except Exception:
        return ""


def _e_entry(kind: str, name: str, value: str, source: str,
           risk: str = "warn") -> dict:
    return {"kind": kind, "name": name, "value": value,
            "source": source, "risk": risk}


def _score(command: str) -> tuple[int, list[str]]:
    """How many payload markers a command contains, and which.

    One marker may be innocent; several together are the signature of a
    fetch-decode-execute one-liner that no one types by hand.
    """
    low = command.lower()
    hits = [why for token, why in PAYLOAD_MARKERS if token in low]
    # de-duplicate reasons while keeping order
    seen, unique = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return len(unique), unique


# ─────────────────────── Windows ───────────────────────

def run_box_history_windows() -> list[dict]:
    """The Win+R Run-box history — where a pasted ClickFix command lands.

    RunMRU records exactly what was typed or pasted into the Run dialog. A
    ClickFix victim's malicious one-liner sits here verbatim, often with long
    leading whitespace so the visible part looked like a harmless
    "verification ID" while the real command scrolled off-screen.
    """
    items = []
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    # reg query separates columns with exactly four spaces. Splitting on
    # whitespace ate the padding this check exists to find, so the test for
    # it could never fire. Everything past the separator is kept verbatim.
    row = re.compile(r"^\s*(\S+)\s+(REG_\w+)\s{4}(.*)$")
    for line in _run(["reg", "query", key]).splitlines():
        m = row.match(line.rstrip("\n"))
        if not m:
            continue
        name, raw = m.group(1), m.group(3)
        # RunMRU appends a "\1" ordering suffix to every entry
        raw = raw.removesuffix("\\1")
        value = raw.strip()
        if not value:
            continue

        n, reasons = _score(value)
        lead = len(raw) - len(raw.lstrip())
        # Padding pushes the real command off the right of the Run box, so
        # the victim reads a short harmless-looking string and presses Enter.
        padded = lead > 8
        if n >= 1 or padded:
            risk = "critical" if (n >= 2 or padded) else "warn"
            if padded:
                reasons = [f"padded with {lead} spaces so the real command sat "
                           "off-screen in the Run box — a hallmark of ClickFix"
                           ] + reasons
            items.append(_e_entry("Run-box command", name,
                                  f"{value[:200]} — {'; '.join(reasons)}", key,
                                  risk=risk))
    return items


def powershell_log_windows() -> list[dict]:
    """PowerShell script-block log (event 4104) — what actually executed.

    This is the record that survives the process. Even a one-liner that ran
    and exited leaves its full text here, so a ClickFix payload is visible
    long after nothing is connected. Requires script-block logging, which is
    on by default from PowerShell 5.1.
    """
    items = []
    ps = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-"
        "PowerShell/Operational'; Id=4104} -MaxEvents 200 "
        "-ErrorAction SilentlyContinue | ForEach-Object "
        "{ $_.TimeCreated.ToString('s') + '|' + "
        "($_.Message -replace '\\s+',' ') }"
    )
    seen = set()
    for line in _run(["powershell", "-NoProfile", "-Command", ps], timeout=45).splitlines():
        ts, _, msg = line.partition("|")
        n, reasons = _score(msg)
        if n < 2:
            continue          # need several markers to call it a payload
        # collapse near-duplicates so one script does not flood the report
        sig = msg[:80]
        if sig in seen:
            continue
        seen.add(sig)
        items.append(_e_entry("PowerShell execution", ts or "recent",
                            f"{msg[:200]} — {'; '.join(reasons[:3])}",
                            "event 4104", risk="critical"))
    return items


# ─────────────────────── Linux / Kali ───────────────────────

def shell_history_linux() -> list[dict]:
    """Shell history across every user — the terminal ClickFix equivalent.

    The macOS and Linux ClickFix variant lures the user into a curl-pipe-bash
    line in a terminal instead of the Run box. Whatever they pasted stays in
    the shell history file, so it is recoverable after the shell has closed.
    """
    items = []
    from .persistence import all_homes
    hist_files = (".bash_history", ".zsh_history", ".sh_history",
                  ".local/share/fish/fish_history")
    for home in all_homes():
        for name in hist_files:
            path = os.path.join(home, name)
            try:
                with open(path, errors="replace") as f:
                    lines = f.readlines()
            except Exception:
                continue
            for i, raw in enumerate(lines[-500:], 1):
                cmd = raw.strip()
                if not cmd or cmd.startswith("#"):
                    continue
                n, reasons = _score(cmd)
                if n < 2:
                    continue
                items.append(_e_entry(
                    "Shell command", f"{os.path.basename(name)}",
                    f"{cmd[:200]} — {'; '.join(reasons[:3])}",
                    path, risk="critical"))
    return items


def recent_downloads_linux() -> list[dict]:
    """Executables freshly written to temp and download directories.

    A fetch-and-run payload usually stages its second stage in /tmp or the
    user's Downloads folder before executing it. A recently created,
    executable file there is not proof of anything, but paired with a
    matching history line it completes the picture.
    """
    items = []
    from .persistence import all_homes
    import time
    now = time.time()
    dirs = ["/tmp", "/dev/shm", "/var/tmp"]
    for home in all_homes():
        dirs.append(os.path.join(home, "Downloads"))
    for d in dirs:
        try:
            entries = os.scandir(d)
        except Exception:
            continue
        for e in entries:
            try:
                if not e.is_file():
                    continue
                st = e.stat()
                # executable bit set and created within the last day
                if not (st.st_mode & 0o111):
                    continue
                if now - st.st_mtime > 86400:
                    continue
            except Exception:
                continue
            items.append(_e_entry(
                "Recent executable", e.name,
                f"executable file written to {d} within the last day",
                e.path, risk="warn"))
    return items


def clipboard_hint_linux() -> list[dict]:
    """A best-effort peek at the clipboard for a poisoned command sitting ready.

    If the user has reached a ClickFix page but not yet pasted, the malicious
    command may still be on the clipboard. Needs xclip/xsel/wl-paste and a
    graphical session, so its absence is normal rather than a failure.
    """
    items = []
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return items
    import shutil
    for tool, args in (("xclip", ["xclip", "-selection", "clipboard", "-o"]),
                       ("xsel", ["xsel", "--clipboard", "--output"]),
                       ("wl-paste", ["wl-paste", "--no-newline"])):
        if not shutil.which(tool):
            continue
        content = _run(args, timeout=5)
        if content:
            score, why = _score(content)
            if score >= 1:
                items.append(_e_entry(
                    "Clipboard contents", "current clipboard",
                    f"{content[:180]}  —  {', '.join(why[:3])}",
                    f"clipboard via {tool}", risk="critical"))
        break
    return items


def scan_exectrace(errors: list[str] | None = None) -> list[dict]:
    """All execution-trace checks available on this system."""
    def sub(label: str, fn) -> list[dict]:
        """A failing sub-check becomes a reported gap, not a shorter list."""
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = []
    if IS_WINDOWS:
        items += sub("Run box history", run_box_history_windows)
        items += sub("PowerShell log", powershell_log_windows)
    else:
        items += sub("shell history", shell_history_linux)
        items += sub("recent downloads", recent_downloads_linux)
        items += sub("clipboard", clipboard_hint_linux)
    return items
