"""Machine profiles.

The same observation means different things on different machines. A chisel
process holding a live session is alarming on a family laptop and entirely
routine on a penetration tester's workstation, where offensive tooling is
the reason the machine exists.

Without this distinction the tool is unusable on Kali: a stock install
carries chisel, socat, proxychains, iodine, dnscat2 and a Metasploit
handler that listens on 4444, so a scan returns a screen of critical
findings that are all correct and all useless. The user learns in one
session that the alerts mean nothing.

Suppression here is never silent. Findings are downgraded and annotated so
they remain visible and reviewable, because "expected on this machine" is a
judgement about likelihood, not proof of innocence — a real intruder would
happily hide behind exactly these tools.
"""

from __future__ import annotations

import os
import platform
import re
import shutil

DESKTOP = "desktop"
SECURITY = "security"

# Files present on offensive distributions and almost nowhere else
KALI_MARKERS = (
    "/etc/os-release",          # checked for content, see detect()
    "/usr/share/kali-menu",
    "/usr/share/metasploit-framework",
    "/etc/kali_version",
)

PARROT_MARKERS = ("/usr/share/parrot-menu", "/etc/parrot_version")

# Tooling expected on a security workstation. Its presence is not a finding
# there; the same names on an ordinary machine remain one.
EXPECTED_TOOLS = {
    "chisel", "frpc", "frps", "gost", "iodine", "dnscat2", "socat",
    "ncat", "nc", "netcat", "proxychains", "proxychains4", "sshuttle",
    "msfconsole", "msfvenom", "ruby", "responder", "bettercap",
    "ettercap", "mitmproxy", "mitmdump", "burpsuite", "zaproxy",
    "empire", "sliver", "sliver-client", "havoc", "villain",
    "ligolo", "ligolo-ng", "revsocks", "pwncat", "evil-winrm",
}

# Ports these tools habitually listen on during normal work
EXPECTED_PORTS = {4444, 4445, 5555, 8080, 8081, 8443, 1080, 9050, 9051,
                  1337, 31337, 4443, 8000, 8888}


def detect() -> str:
    """Identifies the machine profile from what the system actually is."""
    if platform.system() == "Windows":
        return DESKTOP

    for marker in PARROT_MARKERS:
        if os.path.exists(marker):
            return SECURITY
    for marker in KALI_MARKERS[1:]:
        if os.path.exists(marker):
            return SECURITY

    try:
        with open("/etc/os-release", errors="replace") as f:
            content = f.read().lower()
        if any(d in content for d in ("kali", "parrot", "blackarch",
                                      "pentoo", "athena")):
            return SECURITY
    except Exception:
        pass

    # A stock install of several offensive tools is itself the signal
    found = sum(1 for t in ("msfconsole", "chisel", "responder", "bettercap",
                            "proxychains", "sqlmap", "hydra")
                if shutil.which(t))
    return SECURITY if found >= 3 else DESKTOP


# Names are matched as whole tokens, never as substrings. The list contains
# "nc", and a substring test made it match any text containing those two
# letters — "ScreenConnect", "VNC", "unencrypted", a path with "Sync" in it.
# The effect was the exact opposite of the intent: real remote-control
# findings were downgraded on precisely the machines this module targets.
_TOKEN_SPLIT = re.compile(r"[^a-z0-9+]+")


def _tokens(text: str) -> set[str]:
    """Words in a string, lowercased, punctuation and separators removed."""
    return {t for t in _TOKEN_SPLIT.split((text or "").lower()) if t}


def is_expected(profile: str, name: str = "", port: int = 0) -> bool:
    """Is this tool or port ordinary for this kind of machine?"""
    if profile != SECURITY:
        return False
    if name:
        base = os.path.basename(name).lower().removesuffix(".exe")
        if base in EXPECTED_TOOLS:
            return True
        # A path such as /usr/share/sliver/sliver-server: match on any
        # component, still as a whole token.
        if _tokens(base) & EXPECTED_TOOLS:
            return True
    return bool(port) and port in EXPECTED_PORTS


# Categories where "expected on this machine" is never a sufficient
# explanation, so they keep their severity on every profile.
NEVER_DOWNGRADED = {"Remote control", "Hijacked tool", "Vulnerable version",
                    "Silent install"}

NOTE = ("Downgraded: expected on a security workstation. Reviewed rather "
        "than hidden, because an intruder would happily hide behind exactly "
        "these tools.")


def adjust(findings: list, profile: str) -> tuple[list, int]:
    """Downgrades findings that are routine for this profile.

    Returns (findings, count downgraded). Nothing is removed: severity drops
    and a note is appended, so the finding stays on screen and the user can
    still judge it.
    """
    if profile != SECURITY:
        return findings, 0

    lowered = 0
    for f in findings:
        # Some categories are never routine, whatever the machine is. A live
        # commercial remote-control session or a hijacked tool means someone
        # is on the machine now; "the owner runs offensive tooling" explains
        # neither, and downgrading them defeats the purpose of the scan.
        if f.category in NEVER_DOWNGRADED:
            continue

        name = ""
        for key in ("Process", "Program", "Path"):
            if f.evidence.get(key):
                name = f.evidence[key]
                break
        # The tunnel category carries the tool name in the title instead
        hit = bool(_tokens(f"{name} {f.title}") & EXPECTED_TOOLS)

        if not hit and f.port:
            hit = f.port in EXPECTED_PORTS

        if hit and f.severity == "critical":
            f.severity = "warn"
            f.detail += " " + NOTE
            lowered += 1
        elif hit and f.severity == "warn":
            f.severity = "info"
            f.detail += " " + NOTE
            lowered += 1
    return findings, lowered
