"""Persistence points — how a controller guarantees a return after reboot.

Cutting the connection is not enough: if the persistence point survives,
"""

from __future__ import annotations

import glob
import os
import platform
import subprocess

IS_WINDOWS = platform.system() == "Windows"

RUN_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return r.stdout or ""
    except Exception:
        return ""


def _entry(kind: str, name: str, value: str, source: str, risk: str = "info") -> dict:
    return {"kind": kind, "name": name, "value": value, "source": source, "risk": risk}


def real_home() -> str:
    """The real user's home directory, not root's.

    The tool asks for sudo, and sudo makes expanduser('~') return /root, so
    we would audit root's files instead of the owner's and miss the point.
    """
    user = os.environ.get("SUDO_USER")
    if user and not IS_WINDOWS:
        try:
            import pwd
            return pwd.getpwnam(user).pw_dir
        except Exception:
            cand = f"/home/{user}"
            if os.path.isdir(cand):
                return cand
    return os.path.expanduser("~")


def all_homes() -> list[str]:
    """Every user home — the backdoor may sit in a different account."""
    homes = [real_home()]
    if not IS_WINDOWS:
        homes += sorted(glob.glob("/home/*")) + ["/root"]
    seen, out = set(), []
    for h in homes:
        if h and h not in seen and os.path.isdir(h):
            seen.add(h)
            out.append(h)
    return out


def autoruns_windows() -> list[dict]:
    items: list[dict] = []
    for key in RUN_KEYS:
        out = _run(["reg", "query", key])
        for line in out.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3 and parts[1].startswith("REG_"):
                items.append(_entry("Autostart", parts[0], parts[2], key))
    return items


def scheduled_tasks_windows() -> list[dict]:
    """Scheduled tasks not belonging to Microsoft."""
    out = _run([
        "powershell", "-NoProfile", "-Command",
        "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*' "
        "-and $_.State -ne 'Disabled'} | ForEach-Object "
        "{ $_.TaskPath + $_.TaskName + '|' + "
        "($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ' }",
    ], timeout=40)
    items = []
    for line in out.splitlines():
        if "|" in line:
            name, _, action = line.partition("|")
            items.append(_entry("Scheduled task", name.strip(), action.strip(),
                                "Task Scheduler"))
    return items


def services_windows() -> list[dict]:
    """Services running from paths outside the system directories."""
    out = _run([
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_Service | Where-Object {$_.State -eq 'Running'} "
        "| ForEach-Object { $_.Name + '|' + $_.PathName }",
    ], timeout=40)
    items = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        name, _, path = line.partition("|")
        low = path.lower()
        if any(low.lstrip('"').startswith(p) for p in
               (r"c:\windows", r"c:\program files")):
            continue
        items.append(_entry("Service", name.strip(), path.strip(), "Services",
                            risk="warn"))
    return items


def wmi_subscriptions_windows() -> list[dict]:
    """WMI event subscriptions — the best-hidden persistence on Windows.

    They appear in no task manager, no startup list and no scheduled task
    view, and survive reboots. A CommandLineEventConsumer means a command
    runs automatically whenever an attacker-defined event fires.
    """
    items = []
    ps = (
        "Get-CimInstance -Namespace root\\Subscription -ClassName "
        "__FilterToConsumerBinding -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Filter.ToString() + '||' + $_.Consumer.ToString() }"
    )
    for line in _run(["powershell", "-NoProfile", "-Command", ps], timeout=40).splitlines():
        if "||" not in line:
            continue
        filt, _, consumer = line.partition("||")
        low = consumer.lower()
        # Consumers that execute commands are the danger: ActiveScript and
        risk = ("critical" if ("commandline" in low or "activescript" in low)
                else "warn")
        items.append(_entry("WMI event subscription", consumer.strip()[:120],
                            f"Filter: {filt.strip()[:160]}",
                            "root\\Subscription", risk=risk))

    ps2 = (
        "Get-CimInstance -Namespace root\\Subscription -ClassName "
        "CommandLineEventConsumer -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Name + '||' + $_.CommandLineTemplate }"
    )
    for line in _run(["powershell", "-NoProfile", "-Command", ps2], timeout=40).splitlines():
        if "||" not in line:
            continue
        name, _, cmd = line.partition("||")
        items.append(_entry("Automatic WMI command", name.strip(), cmd.strip()[:200],
                            "CommandLineEventConsumer", risk="critical"))
    return items


def winlogon_shell_windows() -> list[dict]:
    """Winlogon keys — replacing the shell or appending to it runs at every login."""
    items = []
    key = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    expected = {"shell": "explorer.exe", "userinit": "c:\\windows\\system32\\userinit.exe,"}
    for line in _run(["reg", "query", key]).splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3 or not parts[1].startswith("REG_"):
            continue
        name, value = parts[0].lower(), parts[2].strip()
        if name in expected and value.lower().rstrip(",") != expected[name].rstrip(","):
            items.append(_entry("Winlogon modified", parts[0], value, key,
                                risk="critical"))
    return items


def cron_linux() -> list[dict]:
    items = []
    out = _run(["crontab", "-l"])
    for line in out.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            items.append(_entry("cron (user)", "crontab", s, "crontab -l"))
    for path in glob.glob("/etc/cron.d/*") + ["/etc/crontab"]:
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#") and not s.startswith("SHELL"):
                        items.append(_entry("cron (system)", os.path.basename(path),
                                            s, path))
        except Exception:
            pass
    return items


def systemd_linux() -> list[dict]:
    """Only systemd units installed by hand.

    Distribution units live in /usr/lib/systemd and /lib/systemd. Listing
    them all yields dozens of ordinary lines that bury the real finding.
    What matters is what was written into /etc/systemd/system or the user's
    own directory, because that is what someone installing something does.
    """
    items = []
    home = real_home()
    roots = [
        ("/etc/systemd/system", "systemd (system)", "info"),
        (os.path.join(home, ".config", "systemd", "user"),
         "systemd (user)", "warn"),
    ]
    for root, src, base_risk in roots:
        for path in glob.glob(os.path.join(root, "**", "*.service"),
                              recursive=True):
            if os.path.islink(path):
                # A symlink to a packaged unit is ordinary enabling, not a manual install
                target = os.path.realpath(path)
                if target.startswith(("/usr/lib/", "/lib/", "/usr/local/lib/")):
                    continue
            exec_line = ""
            try:
                with open(path, errors="replace") as f:
                    for line in f:
                        if line.strip().startswith("ExecStart"):
                            exec_line = line.split("=", 1)[-1].strip()
                            break
            except Exception:
                continue

            low = exec_line.lower()
            risk = base_risk
            if any(k in low for k in ("curl ", "wget ", "/dev/tcp/", "base64 -d",
                                      "bash -i", "nc ", "ncat ", "python -c")):
                risk = "critical"
            elif any(h in low for h in ("/tmp/", "/dev/shm/", "/var/tmp/")):
                risk = "critical"

            items.append(_entry("systemd service", os.path.basename(path),
                                exec_line or "(no ExecStart)", path, risk=risk))
    return items


def shell_rc_linux() -> list[dict]:
    """Lines executed on every terminal launch — a common hiding place."""
    items = []
    names = (".bashrc", ".bash_profile", ".profile", ".zshrc",
             ".zprofile", ".bash_logout")
    triggers = ("curl ", "wget ", "nc ", "ncat ", "/dev/tcp/",
                "base64 -d", "base64 --decode", "bash -i", "eval $(")
    for home in all_homes():
        for name in names:
            path = os.path.join(home, name)
            try:
                with open(path, errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        line = line.strip()
                        if line.startswith("#"):
                            continue
                        if any(k in line for k in triggers):
                            items.append(_entry(
                                "Shell startup line", f"{name}:{i}",
                                line[:200], path, risk="critical"))
            except Exception:
                pass
        # .desktop files that autostart on desktop login
        for path in glob.glob(os.path.join(home, ".config", "autostart", "*.desktop")):
            try:
                with open(path, errors="replace") as f:
                    exec_line = next(
                        (l.split("=", 1)[1].strip() for l in f
                         if l.startswith("Exec=")), "")
            except Exception:
                continue
            low = exec_line.lower()
            risk = "critical" if any(
                h in low for h in ("/tmp/", "/dev/shm/", "curl ", "wget ",
                                   "/dev/tcp/", "base64 -d")) else "info"
            items.append(_entry("Autostart (desktop)",
                                os.path.basename(path), exec_line, path, risk=risk))
    return items


def ssh_authorized_keys() -> list[dict]:
    """Authorised SSH keys — the backdoor most often forgotten during cleanup."""
    items = []
    paths = []
    paths += [os.path.join(h, ".ssh", "authorized_keys") for h in all_homes()]
    if IS_WINDOWS:
        paths.append(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                  "ssh", "administrators_authorized_keys"))
    else:
        paths += glob.glob("/home/*/.ssh/authorized_keys")
        paths.append("/root/.ssh/authorized_keys")

    for path in dict.fromkeys(paths):
        try:
            with open(path, errors="replace") as f:
                for i, line in enumerate(f, 1):
                    s = line.strip()
                    if s and not s.startswith("#"):
                        parts = s.split()
                        comment = parts[2] if len(parts) > 2 else "no comment"
                        fp = parts[1][-24:] if len(parts) > 1 else ""
                        items.append(_entry(
                            "SSH key", comment, f"…{fp}", path, risk="warn"))
        except Exception:
            pass
    return items


def scan(errors: list[str] | None = None) -> list[dict]:
    """Every persistence point we can read.

    Each sub-scanner is isolated. One of them failing used to remove its
    whole category from the results with no trace, so a registry read that
    threw looked exactly like a machine with no autostart entries — the
    difference between "nothing there" and "never looked" is the difference
    between a report and a false reassurance.

    Failures inside a sub-scanner, at the level of a single unreadable file,
    stay quiet on purpose: being unable to read another user's crontab
    without privileges is ordinary, not a finding.
    """
    def sub(label: str, fn) -> list[dict]:
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items: list[dict] = []
    if IS_WINDOWS:
        items += sub("registry autostart", autoruns_windows)
        items += sub("scheduled tasks", scheduled_tasks_windows)
        items += sub("services", services_windows)
        items += sub("WMI subscriptions", wmi_subscriptions_windows)
        items += sub("Winlogon shell", winlogon_shell_windows)
    else:
        items += sub("cron", cron_linux)
        items += sub("systemd units", systemd_linux)
        items += sub("shell startup files", shell_rc_linux)
    items += sub("authorised SSH keys", ssh_authorized_keys)
    return items
