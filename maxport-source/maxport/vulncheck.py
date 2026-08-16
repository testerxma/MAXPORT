"""Known-vulnerable versions of remote-access software.

Detecting that AnyDesk is installed is only half the question. The other
half is which build, because attackers increasingly do not bother stealing
credentials — they exploit an unpatched flaw in the remote-access tool
itself. That path is cheaper and works against machines whose owners
believed they were safe precisely because the software was legitimate.

Every entry below is a flaw with confirmed exploitation in the wild. The
list is deliberately short: speculative CVEs would produce noise, and an
alert the user ignores is worse than no alert.

Data is static and ages. `advisory_note()` says so out loud rather than
letting a silent "clean" result be mistaken for a guarantee.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess

IS_WINDOWS = platform.system() == "Windows"

# Compiled: 2026-08. Each entry is (fixed_version, CVE, severity, summary).
# `below` means every build strictly older than this string is affected.
KNOWN_VULNERABLE = {
    "SimpleHelp": [
        {"below": "5.5.16", "cve": "CVE-2026-48558", "severity": "critical",
         "note": "OIDC authentication bypass. An unauthenticated attacker can "
                 "create a Technician account and remote into every managed "
                 "endpoint, bypassing MFA. In CISA's Known Exploited "
                 "Vulnerabilities catalogue."},
        {"below": "5.5.8", "cve": "CVE-2024-57727", "severity": "critical",
         "note": "Path traversal exposing serverconfig.xml, which holds "
                 "hashed admin and technician passwords. Chained with "
                 "CVE-2024-57726 (privilege escalation) and CVE-2024-57728 "
                 "(arbitrary file upload). Used by ransomware operators."},
    ],
    "ScreenConnect": [
        {"below": "25.2.4", "cve": "CVE-2025-3935", "severity": "critical",
         "note": "ViewState code injection allowing arbitrary code execution "
                 "on the server. Multiple threat groups exploited it while "
                 "unpatched instances remained widespread."},
        {"below": "23.9.8", "cve": "CVE-2024-1709", "severity": "critical",
         "note": "Authentication bypass giving full administrative access. "
                 "Mass-exploited within days of disclosure."},
    ],
    "BeyondTrust Remote Support": [
        {"below": "24.3.1", "cve": "CVE-2024-12356", "severity": "critical",
         "note": "Command injection. Exploited against government targets."},
    ],
}

# ScreenConnect Client is the same product under a different process name
KNOWN_VULNERABLE["ScreenConnect Client"] = KNOWN_VULNERABLE["ScreenConnect"]
KNOWN_VULNERABLE["ConnectWise Control"] = KNOWN_VULNERABLE["ScreenConnect"]

DATA_DATE = "2026-08"

VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")


def parse_version(text: str) -> tuple[int, ...] | None:
    """Pulls a dotted version out of arbitrary text."""
    m = VERSION_RE.search(text or "")
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compares versions of differing length by zero-padding the shorter."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _safe_to_execute(path: str) -> bool:
    """May we run this binary just to ask its version?

    Only if the system vouches for it: owned by root, not writable by anyone
    else, and living in a package-managed directory. Anything the user or an
    attacker could have placed is read about, never run.
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    if st.st_uid != 0:
        return False
    if st.st_mode & 0o022:          # group- or world-writable
        return False
    low = path.lower()
    return any(low.startswith(p) for p in
               ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
                "/bin/", "/sbin/", "/opt/", "/snap/"))


def _package_version(path: str) -> str:
    """Asks the package manager which version owns this file. Never executes it."""
    for query, fmt in ((["dpkg", "-S", path], "dpkg"), (["rpm", "-qf", path], "rpm")):
        try:
            r = subprocess.run(query, capture_output=True, text=True,
                               timeout=8, errors="replace")
        except Exception:
            continue
        out = (r.stdout or "").strip()
        if r.returncode != 0 or not out:
            continue
        if fmt == "dpkg":
            pkg = out.split(":")[0].strip()
            if not pkg:
                continue
            try:
                v = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Version}", pkg],
                    capture_output=True, text=True, timeout=8, errors="replace")
                if v.returncode == 0 and (v.stdout or "").strip():
                    return v.stdout.strip()
            except Exception:
                continue
        else:
            return out          # rpm -qf already prints name-version-release
    return ""


def file_version(path: str) -> str:
    """Reads the version of an executable without trusting it.

    Windows keeps the version in the PE resource block, so it is read, never
    run. On Linux there is no equivalent block; the package manager is asked
    first, and the binary itself is only invoked when the system vouches for
    it (see _safe_to_execute). Running an unverified executable to find out
    whether it is malicious would hand it exactly what it wants.

    An empty result is normal and means "unknown", never "safe".
    """
    if not path or not os.path.exists(path):
        return ""

    if IS_WINDOWS:
        # The path travels in the environment, not in the command text, so a
        # filename containing quotes cannot break out and run its own code.
        ps = ("(Get-Item -LiteralPath $env:MAXPORT_TARGET)"
              ".VersionInfo.FileVersion")
        try:
            env = dict(os.environ, MAXPORT_TARGET=path)
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=20, env=env,
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW)
            return (r.stdout or "").strip()
        except Exception:
            return ""

    pkg = _package_version(path)
    if pkg and VERSION_RE.search(pkg):
        return pkg

    if not _safe_to_execute(path):
        return ""

    for flag in ("--version", "-version", "-v"):
        try:
            r = subprocess.run([path, flag], capture_output=True, text=True,
                               timeout=6, errors="replace")
            out = (r.stdout or "") + (r.stderr or "")
            if VERSION_RE.search(out):
                return out.strip().splitlines()[0][:120]
        except Exception:
            continue
    return ""


def check(tool: str, exe: str) -> dict | None:
    """Returns vulnerability details if this build has a known exploited flaw.

    Returns None both when the tool is patched and when the version could not
    be read. Those two cases are genuinely different, so callers that need to
    distinguish them should call file_version() themselves rather than
    treating None as proof of safety.
    """
    entries = KNOWN_VULNERABLE.get(tool)
    if not entries:
        return None

    raw = file_version(exe)
    current = parse_version(raw)
    if not current:
        return None

    for entry in entries:
        fixed = parse_version(entry["below"])
        if fixed and _cmp(current, fixed) < 0:
            return {
                "tool": tool,
                "version": ".".join(str(x) for x in current),
                "fixed_in": entry["below"],
                "cve": entry["cve"],
                "severity": entry["severity"],
                "note": entry["note"],
            }
    return None


def advisory_note() -> str:
    return (f"Vulnerability data compiled {DATA_DATE}. A clean result means "
            "no match in this list, not that the software is current — "
            "check the vendor's advisories for anything newer.")
