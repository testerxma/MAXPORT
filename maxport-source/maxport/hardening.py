"""Backdoors that connections and processes cannot reveal.

What makes these dangerous is that they are dormant: no process running, no
port open, no session established. They sleep until the attacker wakes
them. No amount of connection scanning will ever surface one. They require
static-state inspection instead: who holds an account, what changed in
system files, and whether protection was switched off.

The classic example is the Sticky Keys backdoor: an accessibility binary on
the login screen is replaced with cmd.exe, so pressing a key five times
opens a SYSTEM shell before anyone has logged in — with no password.
"""

from __future__ import annotations

import glob
import hashlib
import os
import platform
import subprocess
import time

IS_WINDOWS = platform.system() == "Windows"

# Accessibility binaries that run as SYSTEM on the login screen
ACCESSIBILITY_BINARIES = (
    "sethc.exe",        # Sticky Keys — five Shift presses
    "utilman.exe",      # Utility Manager — Win+U
    "osk.exe",          # On-screen keyboard
    "magnify.exe",      # Magnifier
    "displayswitch.exe",
    "atbroker.exe",
    "narrator.exe",
)

SHELL_BINARIES = ("cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe")


def _run(cmd: list[str], timeout: int = 25) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        return r.stdout or ""
    except Exception:
        return ""


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _h_entry(kind: str, name: str, value: str, source: str,
           risk: str = "info") -> dict:
    return {"kind": kind, "name": name, "value": value,
            "source": source, "risk": risk}


# ─────────────────────── Windows ───────────────────────

def sticky_keys_windows() -> list[dict]:
    """Compares accessibility binary hashes against shell binary hashes.

    A match means the file was replaced with a terminal: SYSTEM access from
    the lock screen with no password. We also check IFEO debugger keys,
    which achieve the same thing without modifying any file, leaving size
    and signature intact.
    """
    items = []
    sys32 = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")

    shell_hashes = {}
    for s in SHELL_BINARIES:
        h = _sha256(os.path.join(sys32, s))
        if h:
            shell_hashes[h] = s

    for exe in ACCESSIBILITY_BINARIES:
        path = os.path.join(sys32, exe)
        h = _sha256(path)
        if not h:
            continue
        if h in shell_hashes:
            items.append(_h_entry(
                "Sticky Keys backdoor", exe,
                f"byte-identical to {shell_hashes[h]} — replaced with a shell",
                path, risk="critical"))

    # Second route: an IFEO debugger runs a different program in its place
    ifeo = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\Image File Execution Options")
    for exe in ACCESSIBILITY_BINARIES + SHELL_BINARIES:
        out = _run(["reg", "query", f"{ifeo}\\{exe}", "/v", "Debugger"])
        for line in out.splitlines():
            if "Debugger" in line and "REG_" in line:
                val = line.split(None, 2)[-1].strip()
                items.append(_h_entry(
                    "IFEO debugger", exe,
                    f"runs {val} instead of the original program",
                    f"{ifeo}\\{exe}", risk="critical"))
    return items


def rdp_settings_windows() -> list[dict]:
    """Remote Desktop state: enabled? protected by NLA? on which port?"""
    items = []
    ts = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
    rdp = ts + r"\WinStations\RDP-Tcp"

    def val(key: str, name: str) -> str:
        for line in _run(["reg", "query", key, "/v", name]).splitlines():
            if name.lower() in line.lower() and "REG_" in line:
                return line.split(None, 2)[-1].strip()
        return ""

    deny = val(ts, "fDenyTSConnections")
    if deny and deny.lower() in ("0x0", "0"):
        items.append(_h_entry("RDP enabled", "fDenyTSConnections", "incoming sessions allowed",
                            ts, risk="warn"))
        nla = val(rdp, "UserAuthentication")
        if nla and nla.lower() in ("0x0", "0"):
            # Without NLA anyone reaches the login screen before authenticating,
            # which is precisely what makes Sticky Keys remotely exploitable
            items.append(_h_entry(
                "Network Level Authentication disabled", "UserAuthentication",
                "login screen reachable without authenticating — the Sticky Keys precondition",
                rdp, risk="critical"))

        port = val(rdp, "PortNumber")
        if port and port.lower() not in ("0xd3d", "3389"):
            items.append(_h_entry("non-standard RDP port", "PortNumber", port,
                                rdp, risk="warn"))
    return items


def local_accounts_windows() -> list[dict]:
    """Local accounts and their privileges — the simplest overlooked backdoor."""
    items = []
    ps = (
        "Get-LocalUser | ForEach-Object { $_.Name + '|' + $_.Enabled + '|' + "
        "$_.LastLogon + '|' + $_.Description }")
    users = {}
    for line in _run(["powershell", "-NoProfile", "-Command", ps], timeout=40).splitlines():
        p = line.split("|")
        if len(p) >= 2:
            users[p[0].strip()] = {"enabled": p[1].strip(),
                                   "last": p[2].strip() if len(p) > 2 else "",
                                   "desc": p[3].strip() if len(p) > 3 else ""}

    for group, risk in (("Administrators", "warn"), ("Remote Desktop Users", "warn")):
        ps2 = (f"Get-LocalGroupMember -Group '{group}' -ErrorAction "
               "SilentlyContinue | ForEach-Object { $_.Name }")
        for line in _run(["powershell", "-NoProfile", "-Command", ps2],
                         timeout=40).splitlines():
            name = line.strip()
            if not name:
                continue
            short = name.split("\\")[-1]
            # An account ending in $ is hidden from the login screen and user lists
            hidden = short.endswith("$")
            items.append(_h_entry(
                f"member of {group}", short,
                ("hidden from the login screen" if hidden
                 else users.get(short, {}).get("desc", "") or "local account"),
                group, risk="critical" if hidden else risk))

    for name, info in users.items():
        if name.endswith("$"):
            items.append(_h_entry("hidden account", name,
                                "name ends in $, so it does not appear at login",
                                "Get-LocalUser", risk="critical"))
    return items


def defender_status_windows() -> list[dict]:
    """Tampering precedes nearly every attack — exclusions are the quietest way."""
    items = []
    ps = ("$p = Get-MpPreference; $s = Get-MpComputerStatus; "
          "'RT|' + $s.RealTimeProtectionEnabled; "
          "'TP|' + $s.IsTamperProtected; "
          "$p.ExclusionPath | ForEach-Object { 'EX|' + $_ }; "
          "$p.ExclusionProcess | ForEach-Object { 'EP|' + $_ }")
    for line in _run(["powershell", "-NoProfile", "-Command", ps], timeout=45).splitlines():
        tag, _, val = line.partition("|")
        tag, val = tag.strip(), val.strip()
        if tag == "RT" and val.lower() == "false":
            items.append(_h_entry("real-time protection disabled", "RealTimeProtection",
                                "Defender is scanning nothing right now", "Defender",
                                risk="critical"))
        elif tag == "TP" and val.lower() == "false":
            items.append(_h_entry("tamper protection disabled", "TamperProtection",
                                "any admin can disable Defender programmatically",
                                "Defender", risk="warn"))
        elif tag == "EX" and val:
            low = val.lower()
            broad = low.rstrip("\\").endswith(":") or low in ("c:\\", "/")
            risky = any(h in low for h in ("\\temp", "\\downloads", "\\appdata",
                                           "\\programdata", "\\users\\public"))
            items.append(_h_entry(
                "Defender exclusion", val,
                ("whole-drive exclusion — effectively disables protection" if broad else
                 "a path commonly used to stage payloads" if risky else
                 "path excluded from scanning"),
                "ExclusionPath",
                risk="critical" if (broad or risky) else "warn"))
        elif tag == "EP" and val:
            items.append(_h_entry("excluded process", val,
                                "this process is never scanned",
                                "ExclusionProcess", risk="warn"))
    return items


def smartscreen_windows() -> list[dict]:
    items = []
    checks = [
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
         "EnableSmartScreen", ("0x0", "0"), "SmartScreen disabled by policy"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
         "SmartScreenEnabled", ("off",), "SmartScreen turned off"),
    ]
    for key, name, bad, label in checks:
        for line in _run(["reg", "query", key, "/v", name]).splitlines():
            if name.lower() in line.lower() and "REG_" in line:
                val = line.split(None, 2)[-1].strip().lower()
                if val in bad:
                    items.append(_h_entry("protection disabled", label, val, key,
                                        risk="warn"))
    return items


# ─────────────────────── Linux ───────────────────────

def accounts_linux() -> list[dict]:
    """Root-privileged or passwordless accounts, and sudoers additions."""
    items = []
    try:
        with open("/etc/passwd", errors="replace") as f:
            for line in f:
                p = line.strip().split(":")
                if len(p) < 7:
                    continue
                name, uid, shell = p[0], p[2], p[6]
                # Any UID 0 account other than root is a second root by definition
                if uid == "0" and name != "root":
                    items.append(_h_entry(
                        "root-privileged account", name,
                        f"UID 0, identical to root (shell: {shell})",
                        "/etc/passwd", risk="critical"))
    except Exception:
        pass

    try:
        with open("/etc/shadow", errors="replace") as f:
            for line in f:
                p = line.split(":")
                if len(p) > 1 and p[1] == "" :
                    items.append(_h_entry("passwordless account", p[0],
                                        "can be logged into without authenticating",
                                        "/etc/shadow", risk="critical"))
    except Exception:
        pass      # requires root; its absence is not an error

    for path in ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*")):
        try:
            with open(path, errors="replace") as f:
                for i, line in enumerate(f, 1):
                    s = line.strip()
                    if s.startswith("#") or not s:
                        continue
                    if "NOPASSWD" in s and "ALL" in s:
                        items.append(_h_entry(
                            "passwordless sudo", f"{os.path.basename(path)}:{i}",
                            s[:160], path, risk="warn"))
        except Exception:
            pass
    return items


def ssh_config_linux() -> list[dict]:
    """SSH settings that leave the door wide open."""
    items = []
    risky = {
        "permitrootlogin": (("yes", "without-password", "prohibit-password"),
                            "direct root login is permitted"),
        "passwordauthentication": (("yes",),
                                   "password login allowed — open to guessing"),
        "permitemptypasswords": (("yes",), "empty passwords are accepted"),
        "gatewayports": (("yes", "clientspecified"),
                         "allows reverse tunnels to be published to the network"),
        "allowtcpforwarding": (("yes",), "port forwarding allowed — enables tunnels"),
    }
    paths = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*"))
    for path in paths:
        try:
            with open(path, errors="replace") as f:
                for i, line in enumerate(f, 1):
                    s = line.strip()
                    if s.startswith("#") or not s:
                        continue
                    parts = s.split(None, 1)
                    if len(parts) != 2:
                        continue
                    k, v = parts[0].lower(), parts[1].strip().lower()
                    if k in risky and v in risky[k][0]:
                        sev = "critical" if k in ("permitemptypasswords",) else "warn"
                        items.append(_h_entry("SSH setting", f"{parts[0]} {parts[1]}",
                                            risky[k][1], f"{path}:{i}", risk=sev))
        except Exception:
            pass
    return items


def scan_hardening(errors: list[str] | None = None) -> list[dict]:
    """Every static-state check available on this system."""
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
        items += sub("Sticky Keys", sticky_keys_windows)
        items += sub("RDP settings", rdp_settings_windows)
        items += sub("local accounts", local_accounts_windows)
        items += sub("Defender status", defender_status_windows)
        items += sub("SmartScreen", smartscreen_windows)
    else:
        items += sub("accounts", accounts_linux)
        items += sub("SSH configuration", ssh_config_linux)
    return items

