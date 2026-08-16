"""Remote-access tools configured to let someone back in without asking.

Finding AnyDesk on a machine says little. The owner may have installed it
for a relative. What separates that from a backdoor is the configuration:
whether the tool has been set up to accept a session with nobody present to
approve it.

That is the state ransomware operators create before they leave. They
install a legitimate remote-access client, set an unattended access
password, and now hold a signed, vendor-trusted way back in that no
signature check will ever object to — one that survives reboots, password
changes and antivirus scans, because nothing about it is malware.

So this module reads the tools' own configuration files. It reports what
the setting is, never guesses why: someone who genuinely uses unattended
access on their own machine should see it listed and recognise it, and
someone who does not should see it and understand immediately what it means.
"""

from __future__ import annotations

import glob
import os
import platform

IS_WINDOWS = platform.system() == "Windows"


def _rmm_entry(tool: str, setting: str, detail: str, path: str,
           risk: str = "warn") -> dict:
    return {"tool": tool, "setting": setting, "detail": detail,
            "path": path, "risk": risk}


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _config_dirs() -> list[str]:
    """Where remote-access tools keep configuration, per platform."""
    dirs = []
    if IS_WINDOWS:
        for var in ("PROGRAMDATA", "APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(var)
            if base:
                dirs.append(base)
        dirs += [os.environ.get("PROGRAMFILES") or r"C:\Program Files",
                 os.environ.get("PROGRAMFILES(X86)") or
                 r"C:\Program Files (x86)"]
    else:
        dirs += ["/etc", "/opt", "/usr/local/etc"]
        home = os.path.expanduser("~")
        dirs += [os.path.join(home, ".anydesk"), os.path.join(home, ".config")]
    return [d for d in dirs if d and os.path.isdir(d)]


def anydesk_unattended() -> list[dict]:
    """AnyDesk stores an unattended password hash in its service config.

    Its presence means a session can be accepted with nobody at the keyboard.
    """
    out = []
    names = ("service.conf", "system.conf", "user.conf")
    for base in _config_dirs():
        for name in names:
            for path in glob.glob(os.path.join(base, "**", "AnyDesk", name),
                                  recursive=True)[:20] + \
                        glob.glob(os.path.join(base, name)):
                text = _read(path)
                if not text:
                    continue
                low = text.lower()
                if "ad.anynet.pwd_hash" in low or "ad.security.password" in low:
                    out.append(_rmm_entry(
                        "AnyDesk", "Unattended access password is set",
                        "Someone holding this password can connect and take "
                        "control with nobody present to approve it. Set by "
                        "the owner, this is a convenience; set by someone "
                        "else, it is a way back in that needs no malware.",
                        path, risk="critical"))
                if "ad.features.file_manager=false" in low.replace(" ", ""):
                    out.append(_rmm_entry(
                        "AnyDesk", "File transfer disabled",
                        "Unusual for ordinary use; sometimes set to reduce "
                        "traces.", path, risk="info"))
    return out


def screenconnect_config() -> list[dict]:
    """ScreenConnect clients record the server they answer to.

    The relay address is the single most useful fact about an installed
    client: a company's own server is one thing, an address nobody
    recognises is another.
    """
    out = []
    for base in _config_dirs():
        pattern = os.path.join(base, "**", "ScreenConnect*", "*.config")
        for path in glob.glob(pattern, recursive=True)[:30]:
            text = _read(path)
            if not text:
                continue
            for marker in ("h=", "&h=", "relay", "WebServerAddress"):
                if marker in text:
                    break
            else:
                continue
            out.append(_rmm_entry(
                "ScreenConnect", "Client is bound to a relay server",
                "This client answers to whichever server is named in its "
                "configuration. Confirm the address belongs to an IT "
                "provider you actually use.",
                path, risk="warn"))
            break
    return out


def vnc_no_auth() -> list[dict]:
    """A VNC server with no password is an open door, not a risk."""
    out = []
    candidates = ["/etc/vnc.conf", "/root/.vnc", "/etc/x11vnc.conf"]
    for home in (os.path.expanduser("~"),):
        candidates.append(os.path.join(home, ".vnc"))
    for path in candidates:
        if os.path.isdir(path):
            if not glob.glob(os.path.join(path, "passwd*")):
                out.append(_rmm_entry(
                    "VNC", "No password file found",
                    "A VNC server without authentication accepts anyone who "
                    "can reach the port.", path, risk="critical"))
        elif os.path.isfile(path):
            low = _read(path).lower()
            if "nopw" in low or "-nopw" in low:
                out.append(_rmm_entry(
                    "VNC", "Configured to run without a password",
                    "Anyone who can reach the port gets the screen.",
                    path, risk="critical"))
    return out


def rdp_unrestricted() -> list[dict]:
    """RDP with network-level authentication off accepts more attempts."""
    if not IS_WINDOWS:
        return []
    import subprocess
    out = []
    try:
        r = subprocess.run(
            ["reg", "query",
             r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
             r"\WinStations\RDP-Tcp", "/v", "UserAuthentication"],
            capture_output=True, text=True, timeout=15, errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if "0x0" in (r.stdout or ""):
            out.append(_rmm_entry(
                "RDP", "Network-level authentication is off",
                "Connections reach the login screen before proving who they "
                "are, which is what password-guessing needs.",
                "HKLM\\...\\RDP-Tcp", risk="warn"))
    except Exception:
        pass
    return out


def scan_unattended(errors: list[str] | None = None) -> list[dict]:
    """Every remote-access setting that permits entry without a person."""
    def sub(label, fn):
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = sub("AnyDesk configuration", anydesk_unattended)
    items += sub("ScreenConnect configuration", screenconnect_config)
    items += sub("VNC configuration", vnc_no_auth)
    items += sub("RDP configuration", rdp_unrestricted)
    return items
