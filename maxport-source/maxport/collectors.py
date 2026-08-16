"""Collecting live connections and listening ports, tied back to processes."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field, asdict

import psutil

from . import signatures

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

_trust_cache: dict[str, tuple[str, str]] = {}
_hash_cache: dict[str, str] = {}


@dataclass
class ProcInfo:
    pid: int = -1
    name: str = "?"
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    started: float = 0.0
    trust: str = "unknown"        # trusted | untrusted | unknown
    trust_note: str = ""
    sha256: str = ""
    ppid: int = 0
    parent: str = ""
    ancestry: str = ""          # parent chain — who launched what
    accessible: bool = True


@dataclass
class Conn:
    laddr: str = ""
    lport: int = 0
    raddr: str = ""
    rport: int = 0
    status: str = ""
    family: str = "tcp"
    proc: ProcInfo = field(default_factory=ProcInfo)
    tool: str | None = None       # name of a known remote-control tool
    tunnel: str | None = None     # tunnelling tool carrying this session
    mesh: str | None = None       # mainstream mesh VPN (Tailscale, ZeroTier…)
    rhost: str = ""               # reverse DNS name of the other party
    port_note: str = ""
    port_confidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["proc"] = asdict(self.proc)
        return d


def _run(cmd: list[str], timeout: int = 12, env: dict | None = None) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace", env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return r.stdout or ""
    except Exception:
        return ""


def file_sha256(path: str, max_bytes: int = 80 * 1024 * 1024) -> str:
    """Hash of the executable, for looking it up on VirusTotal by hand."""
    if not path or path in _hash_cache:
        return _hash_cache.get(path, "")
    try:
        if os.path.getsize(path) > max_bytes:
            _hash_cache[path] = ""
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        _hash_cache[path] = h.hexdigest()
    except Exception:
        _hash_cache[path] = ""
    return _hash_cache[path]


def _trust_windows(exe: str) -> tuple[str, str]:
    """Reads the Authenticode signature without letting the path become code.

    The path travels in the environment rather than inside the command text.
    Interpolating it into the script meant a file named with a quote could
    close the string and have the rest run — as administrator, by the tool
    that was scanning it. The signature is also fetched once and reused,
    where the previous version called the cmdlet twice per file.

    Revocation is checked explicitly. Campaigns have shipped remote-access
    clients signed with a certificate the vendor had already revoked, and
    the default check does not consult revocation, so the file came back
    "Valid" — the scanner reassuring the owner about the very thing that
    was wrong.
    """
    ps = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "$p = $env:MAXPORT_TARGET; "
        "$s = Get-AuthenticodeSignature -LiteralPath $p; "
        "$status = $s.Status.ToString(); "
        "$revoked = 'unknown'; "
        "if ($s.SignerCertificate) { "
        "  $c = New-Object System.Security.Cryptography.X509Certificates."
        "X509Chain; "
        "  $c.ChainPolicy.RevocationMode = 'Online'; "
        "  $c.ChainPolicy.RevocationFlag = 'EntireChain'; "
        "  $c.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(8); "
        "  $null = $c.Build($s.SignerCertificate); "
        "  $flags = ($c.ChainStatus | ForEach-Object "
        "{ $_.Status.ToString() }) -join ','; "
        "  if ($flags -match 'Revoked') { $revoked = 'yes' } "
        "  elseif ($flags -match 'RevocationStatusUnknown|OfflineRevocation')"
        " { $revoked = 'unknown' } else { $revoked = 'no' } "
        "} "
        "$status + '|' + $s.SignerCertificate.Subject + '|' + $revoked"
    )
    env = dict(os.environ, MAXPORT_TARGET=exe)
    out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
               timeout=30, env=env).strip()
    if not out:
        return "unknown", "could not check the signature"

    parts = out.split("|")
    status = parts[0].strip() if parts else ""
    subject = parts[1] if len(parts) > 1 else ""
    revoked = parts[2].strip() if len(parts) > 2 else "unknown"
    cn = subject.split(",")[0].replace("CN=", "").strip()

    if revoked == "yes":
        # A revoked certificate is worse than an unsigned file: the signature
        # still looks right to anything that does not check.
        return "untrusted", (f"signed by {cn or 'an issuer'} with a "
                             "certificate the issuer has REVOKED")
    if status == "Valid":
        if revoked == "unknown":
            return "trusted", (f"digitally signed: {cn or 'a known authority'}"
                               " (revocation could not be checked)")
        return "trusted", f"digitally signed: {cn or 'a known authority'}"
    if status == "NotSigned":
        return "untrusted", "not digitally signed"
    return "untrusted", f"invalid signature ({status})"


def _trust_linux(exe: str) -> tuple[str, str]:
    """Classifies an executable on Linux.

    "untrusted" must mean genuinely suspicious, not merely unrecognised. If
    snap, flatpak, AppImage and /usr/local were all called suspicious, every
    real machine would fill with false alarms, the user would stop reading
    them, and the tool would be worse than nothing. Hence "unknown" as its
    own answer, distinct from both trust and suspicion.
    """
    low = exe.lower()

    # Modern packaging: signed and sandboxed, not outside the ecosystem
    if low.startswith("/snap/") or "/snap/" in low:
        return "trusted", "snap package"
    if "/flatpak/" in low or low.startswith("/var/lib/flatpak"):
        return "trusted", "flatpak package"

    # Is the file owned by the package manager?
    for cmd in (["dpkg", "-S", exe], ["rpm", "-qf", exe]):
        out = _run(cmd, timeout=8)
        if out and "no path found" not in out.lower() and "not owned" not in out.lower():
            pkg = out.split(":")[0].strip()
            if pkg:
                return "trusted", f"from system package: {pkg}"

    try:
        st = os.stat(exe)
        root_owned = st.st_uid == 0
        world_writable = bool(st.st_mode & 0o002)
        group_writable = bool(st.st_mode & 0o020)
    except Exception:
        root_owned = world_writable = group_writable = False

    # A file any user can write to can be swapped for something malicious.
    # Group-writable is separate: it is ordinary on many systems, so it is a
    # question rather than an accusation.
    if world_writable:
        return "untrusted", "file is writable by any user on this machine"

    # Legitimate programs do not live in temp directories wiped on reboot
    if any(low.startswith(d) for d in ("/tmp/", "/dev/shm/", "/var/tmp/")):
        return "untrusted", "runs from a temp directory — abnormal for installed software"

    if any(low.startswith(p) for p in signatures.TRUSTED_DIR_PREFIXES_NIX):
        if group_writable:
            return "unknown", "in a system path but writable by its group"
        if root_owned:
            return "trusted", "in a system path and owned by root"
        return "unknown", "in a system path but not owned by root"

    # Usually installed by an admin: common and legitimate, but unverifiable
    if low.startswith("/usr/local/") and root_owned:
        return "unknown", "hand-installed in /usr/local — cannot be verified"

    if low.endswith(".appimage") or "/.mount_" in low:
        return "unknown", "AppImage — self-contained, its origin cannot be verified"

    # An interpreter is legitimate itself; what matters is the script it runs
    base = os.path.basename(low)
    if any(base.startswith(i) for i in ("python", "node", "ruby", "perl", "java",
                                        "php", "sh", "bash", "dash")):
        return "unknown", "language interpreter — judge the script in the command line, not this"

    if _in_home(exe):
        return "untrusted", "runs from a user directory outside any package system"

    return "unknown", "outside system packages — worth a look"


def _in_home(path: str) -> bool:
    for home in ("/home/", "/root/", os.path.expanduser("~")):
        if home and path.startswith(home):
            return True
    return False


def check_trust(exe: str) -> tuple[str, str]:
    """Checks whether an executable is trusted. Cached to keep scans fast."""
    if not exe:
        return "unknown", "executable path unavailable"
    if exe in _trust_cache:
        return _trust_cache[exe]
    if not os.path.exists(exe):
        res = ("untrusted", "the executable is deleted or hidden")
    elif IS_WINDOWS:
        res = _trust_windows(exe)
    else:
        res = _trust_linux(exe)
    _trust_cache[exe] = res
    return res


def path_looks_suspicious(exe: str) -> str:
    """Does the executable live somewhere installed software does not?

    Separators are normalised to backslashes before matching. The previous
    version replaced each separator with itself, so the normalisation did
    nothing and a Windows path written with forward slashes matched none of
    the Windows hints.
    """
    low = (exe or "").lower().replace("/", "\\")
    for hint in signatures.SUSPICIOUS_DIR_HINTS:
        if hint.replace("/", "\\") in low:
            return hint
    return ""


def _proc_info(pid: int | None, deep: bool) -> ProcInfo:
    if not pid:
        return ProcInfo(pid=-1, name="unknown", accessible=False,
                        trust_note="run as administrator to see this process")
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = ProcInfo(
                pid=pid,
                name=p.name(),
                exe=(p.exe() or ""),
                cmdline=" ".join(p.cmdline() or [])[:400],
                username=(p.username() or ""),
                started=p.create_time(),
                ppid=p.ppid() or 0,
            )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ProcInfo(pid=pid, name="access denied", accessible=False,
                        trust_note="run as administrator")
    except Exception:
        return ProcInfo(pid=pid, name="unknown", accessible=False)

    if deep and info.exe:
        info.trust, info.trust_note = check_trust(info.exe)
        info.sha256 = file_sha256(info.exe)
    info.parent, info.ancestry = _ancestry(pid)
    return info


def _ancestry(pid: int, limit: int = 6) -> tuple[str, str]:
    """The parent process chain — more telling than the process name itself.

    A remote-control program the user launched is one thing; one launched by
    a document macro, a shell or an unknown service is another entirely.
    """
    chain, seen = [], set()
    try:
        p = psutil.Process(pid)
        for _ in range(limit):
            p = p.parent()
            if p is None or p.pid in seen:
                break
            seen.add(p.pid)
            chain.append(f"{p.name()}({p.pid})")
    except Exception:
        pass
    return (chain[0].split("(")[0] if chain else ""), " ← ".join(chain)


SUSPICIOUS_PARENTS = (
    "winword", "excel", "powerpnt", "outlook", "acrobat", "acrord32",
    "wscript", "cscript", "mshta", "powershell", "pwsh", "cmd", "rundll32",
    "regsvr32", "curl", "wget", "bash", "sh", "zsh", "dash", "python",
)

_ANCESTRY_ENTRY = re.compile(r"([^\s←]+?)\((\d+)\)")


def _ancestry_names(ancestry: str) -> list[str]:
    """Process names from an ancestry string, without their PIDs."""
    return [m.group(1).lower().removesuffix(".exe")
            for m in _ANCESTRY_ENTRY.finditer(ancestry or "")]


def parent_is_suspicious(info: "ProcInfo") -> str:
    """Was this process launched by something that should not start network programs?

    Names are compared whole. Testing for the substring "sh(" matched
    "flush(12)" and raised a critical alert on it, while "python(" failed to
    match "python3(4321)" and missed the real case — wrong in both
    directions at once. Version suffixes are stripped so python3.12 still
    counts as python.
    """
    for name in _ancestry_names(info.ancestry):
        stem = re.sub(r"[\d.]+$", "", name) or name
        if name in SUSPICIOUS_PARENTS or stem in SUSPICIOUS_PARENTS:
            return name
    return ""


def collect_connections(deep: bool = True) -> tuple[list[Conn], str | None]:
    """Collects all TCP/UDP connections and ties them to processes.

    Returns (connection list, privilege warning if any).
    """
    warning = None
    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return [], "Access denied — run as administrator/root to see all connections."
    except Exception as e:
        return [], f"Could not read connections: {e}"

    seen_pids: dict[int, ProcInfo] = {}
    out: list[Conn] = []
    denied = 0

    for c in raw:
        pid = c.pid
        if pid in seen_pids:
            info = seen_pids[pid]
        else:
            info = _proc_info(pid, deep)
            if pid:
                seen_pids[pid] = info
        if not info.accessible:
            denied += 1

        conn = Conn(
            laddr=c.laddr.ip if c.laddr else "",
            lport=c.laddr.port if c.laddr else 0,
            raddr=c.raddr.ip if c.raddr else "",
            rport=c.raddr.port if c.raddr else 0,
            status=c.status or "",
            family="udp" if c.type == 2 else "tcp",
            proc=info,
        )
        conn.tool = signatures.identify_tool(info.name)
        conn.tunnel = signatures.identify_tunnel(info.name, info.cmdline)
        conn.mesh = signatures.identify_mesh_vpn(info.name)
        desc = signatures.describe_port(conn.rport or conn.lport)
        if desc:
            conn.port_note, conn.port_confidence = desc
        out.append(conn)

    if denied and not warning:
        warning = f"{denied} connections without process details — run as administrator/root."
    return out, warning


def listening_ports(conns: list[Conn]) -> list[Conn]:
    """Listening ports — every open door into this machine."""
    return [c for c in conns if c.status == "LISTEN" or (c.family == "udp" and not c.raddr)]


def established(conns: list[Conn]) -> list[Conn]:
    return [c for c in conns if c.status == "ESTABLISHED" and c.raddr]


def uptime_of(proc: ProcInfo) -> str:
    if not proc.started:
        return ""
    secs = int(time.time() - proc.started)
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"
