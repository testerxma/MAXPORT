"""Response actions — every one reversible and logged.

Design principle: never delete anything. Block, isolate and halt, leaving
the evidence in place, because you may need it for a formal report later.
"""

from __future__ import annotations

import ctypes
import threading
import time
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass

import psutil

IS_WINDOWS = platform.system() == "Windows"
RULE_PREFIX = "MaxPort"


@dataclass
class ActionResult:
    ok: bool
    message: str


def is_elevated() -> bool:
    """Is the tool running with administrator/root privileges?

    Delegates to the elevate module so the check lives in one place; both
    files need it and two copies would eventually drift apart.
    """
    from . import elevate
    return elevate.is_elevated()


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, "command not present on this system"
    except Exception as e:
        return 1, str(e)


NFT_TABLE = RULE_PREFIX.lower()

# The project was renamed. These are the names a previous release used, kept
# only so its leftovers can be found and cleaned up — never written.
LEGACY_NAME = "NetGuard"
LEGACY_RULE_PREFIX = "NetGuard"
LEGACY_NFT_TABLE = "netguard"
LEGACY_WATCHDOG_UNIT = "netguard-isolate-revert"


def _ip_version(ip: str) -> int:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return 0


def _nft_set_for(ip: str) -> str:
    """Which set the address belongs in — IPv4 or IPv6."""
    v = _ip_version(ip)
    return {4: "blocked4", 6: "blocked6"}.get(v, "")


def _iptables_for(ip: str) -> str:
    """iptables handles IPv4 only; IPv6 needs ip6tables.

    Sending a v6 address to iptables fails, and a failure that only prints a
    message leaves the address reachable while the interface says "blocked".
    """
    return {4: "iptables", 6: "ip6tables"}.get(_ip_version(ip), "")


def _nft_ensure() -> None:
    """Creates the nft table with sets that support add and delete.

    Sets rather than individual rules, because removing an element from a
    set is direct, while deleting a rule means tracking its handle and
    breaks easily. Safe to call repeatedly — each command is a no-op if
    """
    # "nft add" is idempotent, so we no longer skip on an existing table: a
    # table left by an older version can be missing sets this version needs,
    # and the early return meant every later add silently failed.
    _run(["nft", "add", "table", "inet", NFT_TABLE])
    for name, typ in (("blocked4", "ipv4_addr"), ("blocked6", "ipv6_addr"),
                      ("closed_tcp", "inet_service"),
                      ("closed_udp", "inet_service")):
        _run(["nft", "add", "set", "inet", NFT_TABLE, name,
              "{ type " + typ + " ; flags interval ; }"])
    # Negative priority so these precede other system rules
    _run(["nft", "add", "chain", "inet", NFT_TABLE, "ngin",
          "{ type filter hook input priority -10 ; policy accept ; }"])
    _run(["nft", "add", "chain", "inet", NFT_TABLE, "ngout",
          "{ type filter hook output priority -10 ; policy accept ; }"])
    for chain, rule in (
        ("ngin", ["ip", "saddr", "@blocked4", "drop"]),
        ("ngin", ["ip6", "saddr", "@blocked6", "drop"]),
        ("ngout", ["ip", "daddr", "@blocked4", "drop"]),
        ("ngout", ["ip6", "daddr", "@blocked6", "drop"]),
        ("ngin", ["tcp", "dport", "@closed_tcp", "drop"]),
        ("ngin", ["udp", "dport", "@closed_udp", "drop"]),
    ):
        _run(["nft", "add", "rule", "inet", NFT_TABLE, chain] + rule)


def _firewall_backend() -> str:
    if IS_WINDOWS:
        return "netsh"
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    if shutil.which("ufw"):
        return "ufw"
    return ""


# ------------------------- stopping processes -------------------------

def _verify_identity(p: "psutil.Process", started: float, name: str) -> str:
    """Is this still the process the scan saw, or has the PID been recycled?

    A finding carries the PID as it was during the scan. The user may act on
    it minutes later, by which time the process can have exited and the
    kernel handed the number to something else — possibly something the
    system needs. Killing by a stale number as root is how a security tool
    becomes the incident, so identity is confirmed before anything is done.
    """
    if started:
        try:
            if abs(p.create_time() - started) > 1.0:
                return ("PID {} no longer belongs to that process — it exited "
                        "and the number was reused. Re-scan before acting."
                        ).format(p.pid)
        except Exception:
            return ""
    if name:
        try:
            if p.name() != name:
                return ("PID {} is now '{}', not '{}'. Re-scan before acting."
                        ).format(p.pid, p.name(), name)
        except Exception:
            return ""
    return ""


def stop_process(pid: int, force: bool = False,
                 started: float = 0.0, expect_name: str = "") -> ActionResult:
    """Stops a process. Graceful first, so no data is lost.

    started/expect_name come from the scan that produced the finding and are
    used to prove the PID still refers to the same process.
    """
    try:
        p = psutil.Process(pid)
        mismatch = _verify_identity(p, started, expect_name)
        if mismatch:
            return ActionResult(False, mismatch)
        name = p.name()
        p.kill() if force else p.terminate()
        try:
            p.wait(timeout=5)
        except psutil.TimeoutExpired:
            if not force:
                return ActionResult(False, f"{name} did not respond — use a forced stop")
        return ActionResult(True, f"Stopped {name} (PID {pid})")
    except psutil.NoSuchProcess:
        return ActionResult(True, "the process had already exited")
    except psutil.AccessDenied:
        return ActionResult(False, "Access denied — run as administrator")
    except Exception as e:
        return ActionResult(False, f"Could not stop it: {e}")


def suspend_process(pid: int, started: float = 0.0,
                    expect_name: str = "") -> ActionResult:
    """Freezes rather than kills — halts activity while preserving memory."""
    try:
        p = psutil.Process(pid)
        mismatch = _verify_identity(p, started, expect_name)
        if mismatch:
            return ActionResult(False, mismatch)
        p.suspend()
        return ActionResult(True, f"Froze {p.name()} — memory preserved for analysis")
    except psutil.AccessDenied:
        return ActionResult(False, "Access denied — run as administrator")
    except Exception as e:
        return ActionResult(False, f"Could not freeze it: {e}")


# ------------------------- blocking addresses -------------------------

def block_ip(ip: str) -> ActionResult:
    """Blocks the address in both directions at the firewall."""
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")
    backend = _firewall_backend()

    if backend == "netsh":
        for direction in ("in", "out"):
            code, out = _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={RULE_PREFIX}-Block-{ip}-{direction}",
                f"dir={direction}", "action=block", f"remoteip={ip}",
            ])
            if code != 0:
                return ActionResult(False, f"Block failed: {out.strip()[:160]}")
        return ActionResult(True, f"Blocked {ip} inbound and outbound")

    if backend == "nft":
        _nft_ensure()
        st = _nft_set_for(ip)
        if not st:
            return ActionResult(False, f"Not a valid address: {ip}")
        code, out = _run(["nft", "add", "element", "inet", NFT_TABLE, st,
                          "{ " + ip + " }"])
        return (ActionResult(True, f"Blocked {ip} inbound and outbound") if code == 0
                else ActionResult(False, out.strip()[:160]))

    if backend == "iptables":
        tool = _iptables_for(ip)
        if not tool:
            return ActionResult(False, f"Not a valid address: {ip}")
        if not shutil.which(tool):
            return ActionResult(
                False, f"{tool} is not installed — cannot block {ip}. "
                       "Without it the address stays reachable over IPv6.")
        c1, o1 = _run([tool, "-I", "INPUT", "-s", ip, "-j", "DROP"])
        c2, o2 = _run([tool, "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
        if c1 == 0 and c2 == 0:
            return ActionResult(True, f"Blocked {ip} — rule lasts until reboot")
        return ActionResult(False, (o1 + o2).strip()[:160])

    if backend == "ufw":
        code, out = _run(["ufw", "deny", "from", ip])
        return (ActionResult(True, f"Blocked {ip}") if code == 0
                else ActionResult(False, out.strip()[:160]))

    return ActionResult(False, "No supported firewall found")


def unblock_ip(ip: str) -> ActionResult:
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")
    backend = _firewall_backend()
    if backend == "netsh":
        for direction in ("in", "out"):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                  f"name={RULE_PREFIX}-Block-{ip}-{direction}"])
        return ActionResult(True, f"Unblocked {ip}")
    if backend == "nft":
        st = _nft_set_for(ip)
        if not st:
            return ActionResult(False, f"Not a valid address: {ip}")
        code, out = _run(["nft", "delete", "element", "inet", NFT_TABLE, st,
                          "{ " + ip + " }"])
        return (ActionResult(True, f"Unblocked {ip}") if code == 0
                else ActionResult(False, out.strip()[:160] or "the address was not blocked"))
    if backend == "iptables":
        tool = _iptables_for(ip)
        if not tool:
            return ActionResult(False, f"Not a valid address: {ip}")
        _run([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"])
        _run([tool, "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        return ActionResult(True, f"Unblocked {ip}")
    if backend == "ufw":
        _run(["ufw", "delete", "deny", "from", ip])
        return ActionResult(True, f"Unblocked {ip}")
    return ActionResult(False, "Unblocking is not supported on this system")


# ------------------------- closing ports -------------------------

def close_port(port: int, proto: str = "tcp", pid: int | None = None,
               started: float = 0.0, expect_name: str = "") -> ActionResult:
    """Closes a port at the firewall, optionally stopping the listener too."""
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")

    backend = _firewall_backend()
    notes = []

    if backend == "netsh":
        code, out = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={RULE_PREFIX}-ClosePort-{port}", "dir=in", "action=block",
            f"protocol={proto.upper()}", f"localport={port}",
        ])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked inbound port {port}/{proto}")
    elif backend == "nft":
        _nft_ensure()
        code, out = _run(["nft", "add", "element", "inet", NFT_TABLE,
                          f"closed_{proto.lower()}", "{ " + str(port) + " }"])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked inbound port {port}/{proto}")
    elif backend == "iptables":
        code, out = _run(["iptables", "-I", "INPUT", "-p", proto,
                          "--dport", str(port), "-j", "DROP"])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked port {port}/{proto}")
    elif backend == "ufw":
        code, out = _run(["ufw", "deny", f"{port}/{proto}"])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked port {port}/{proto}")
    else:
        return ActionResult(False, "No supported firewall found")

    if pid:
        res = stop_process(pid, started=started, expect_name=expect_name)
        notes.append(res.message)

    return ActionResult(True, " — ".join(notes))


# ------------------------- isolation -------------------------

_isolate_timer: "threading.Timer | None" = None
_isolate_deadline: float = 0.0

WATCHDOG_UNIT = "maxport-isolate-revert"
WATCHDOG_TASK = "MaxPort-IsolateRevert"


def _state_path() -> str:
    """Where the isolation state lives — beside the database, owned by root."""
    if IS_WINDOWS:
        base = os.environ.get("PROGRAMDATA") or os.path.expanduser("~")
    else:
        base = "/var/lib" if os.path.isdir("/var/lib") else os.path.expanduser("~")
    d = os.path.join(base, "MaxPort")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.expanduser("~")
    return os.path.join(d, "isolation.json")


def _write_state(deadline: float, keep_lan: bool) -> None:
    import json
    try:
        with open(_state_path(), "w", encoding="utf-8") as f:
            json.dump({"deadline": deadline, "keep_lan": keep_lan,
                       "pid": os.getpid()}, f)
    except Exception:
        pass


def _read_state() -> dict:
    import json
    try:
        with open(_state_path(), encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _clear_state() -> None:
    try:
        os.remove(_state_path())
    except Exception:
        pass


def _revert_shell_command() -> str:
    """The revert, expressed as one shell command an external scheduler can run.

    It must not depend on this program, its interpreter or its files, because
    the whole point is that it still fires when none of them are around.

    The former name is cleaned up alongside the current one. Renaming the
    project renamed the firewall rules and the nftables table, so a machine
    isolated by a version built under the old name would have been left with
    rules this code could no longer see — sealed, with the tool reporting
    nothing to lift.
    """
    if IS_WINDOWS:
        return " & ".join(
            f'netsh advfirewall firewall delete rule name={prefix}-Isolate-{d}'
            for prefix in (RULE_PREFIX, LEGACY_RULE_PREFIX)
            for d in ("in", "out"))
    backend = _firewall_backend()
    if backend == "nft":
        return "; ".join(
            f"nft delete chain inet {table} {chain}"
            for table in (NFT_TABLE, LEGACY_NFT_TABLE)
            for chain in ("ngiso", "ngisoin")) + "; true"
    parts = []
    for tool in ("iptables", "ip6tables"):
        for chain in ("OUTPUT", "INPUT"):
            parts.append(f"{tool} -D {chain} -j DROP")
    return "; ".join(parts) + "; true"


def _state_paths_legacy() -> list[str]:
    """Where a previous release under the old name kept its isolation state."""
    bases = []
    if IS_WINDOWS:
        bases.append(os.environ.get("PROGRAMDATA") or os.path.expanduser("~"))
    else:
        bases += ["/var/lib", os.path.expanduser("~")]
    return [os.path.join(b, LEGACY_NAME, "isolation.json")
            for b in bases if b]


def adopt_legacy_state() -> str:
    """Takes over isolation state written under the previous project name.

    Without this, upgrading while a machine is isolated strands it: the old
    state file is never read, so the automatic revert never happens and
    nothing reports that the machine is still cut off.
    """
    if _read_state():
        return ""
    for old in _state_paths_legacy():
        if not os.path.isfile(old):
            continue
        try:
            import json
            with open(old, encoding="utf-8") as f:
                data = json.load(f) or {}
            if data.get("deadline"):
                _write_state(float(data["deadline"]),
                             bool(data.get("keep_lan", True)))
                os.remove(old)
                return (f"Adopted isolation state left by an earlier version "
                        f"under the previous name ({LEGACY_NAME}).")
        except Exception:
            continue
    return ""


def _arm_watchdog(seconds: int) -> str:
    """Schedules the revert outside this process. Returns the mechanism used.

    An in-process timer is not a dead-man's switch: it dies with the man. If
    the application crashes, is killed, or the user closes it while isolated,
    the firewall rules stay and a machine reached remotely is lost for good.
    The scheduler is the only thing that survives that, so the in-process
    timer becomes the fast path and this becomes the guarantee.
    """
    cmd = _revert_shell_command()

    if IS_WINDOWS:
        when = time.localtime(time.time() + max(60, seconds))
        code, _ = _run([
            "schtasks", "/create", "/tn", WATCHDOG_TASK,
            "/tr", f'cmd /c "{cmd}"', "/sc", "once",
            "/st", time.strftime("%H:%M", when),
            "/sd", time.strftime("%d/%m/%Y", when),
            "/ru", "SYSTEM", "/rl", "HIGHEST", "/f",
        ])
        return "schtasks" if code == 0 else ""

    if shutil.which("systemd-run"):
        code, _ = _run([
            "systemd-run", "--collect", f"--unit={WATCHDOG_UNIT}",
            f"--on-active={max(5, seconds)}",
            "/bin/sh", "-c", cmd,
        ])
        if code == 0:
            return "systemd"

    if shutil.which("at"):
        mins = max(1, round(seconds / 60))
        try:
            p = subprocess.run(["at", f"now + {mins} minutes"],
                               input=cmd, capture_output=True, text=True,
                               timeout=15)
            if p.returncode == 0:
                return "at"
        except Exception:
            pass
    return ""


def _clear_legacy_rules() -> None:
    """Removes isolation rules a release under the previous name left behind.

    Silent by design: on the overwhelming majority of machines there is
    nothing to remove, and a message about a name the user never saw would
    only confuse. What matters is that the rules cannot outlive the rename.
    """
    if IS_WINDOWS:
        for d in ("in", "out"):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                  f"name={LEGACY_RULE_PREFIX}-Isolate-{d}"])
        return
    if _firewall_backend() == "nft":
        for chain in ("ngiso", "ngisoin"):
            _run(["nft", "delete", "chain", "inet", LEGACY_NFT_TABLE, chain])


def _disarm_watchdog() -> None:
    if IS_WINDOWS:
        _run(["schtasks", "/delete", "/tn", WATCHDOG_TASK, "/f"])
        return
    # The second name is what a release under the previous project
    # name registered; stopping it here keeps a rename from
    # stranding a scheduled revert.
    for unit in (WATCHDOG_UNIT, LEGACY_WATCHDOG_UNIT):
        _run(["systemctl", "stop", f"{unit}.timer"])
        _run(["systemctl", "stop", f"{unit}.service"])
        _run(["systemctl", "reset-failed", f"{unit}.service"])


def isolate_status() -> tuple[bool, int]:
    """(is isolation on a timer, seconds left before automatic revert)."""
    deadline = _isolate_deadline or _read_state().get("deadline", 0.0)
    if not deadline:
        return False, 0
    left = int(deadline - time.time())
    return (left > 0), max(0, left)


def resume_or_revert() -> ActionResult | None:
    """Called at startup: deals with isolation left behind by a previous run.

    If the deadline has passed while the program was not running, the machine
    is still isolated and nothing is going to lift it, so we lift it now. If
    time remains, the in-process timer is re-armed for the remainder.
    """
    global _isolate_timer, _isolate_deadline
    adopt_legacy_state()
    state = _read_state()
    deadline = state.get("deadline", 0.0)
    if not deadline:
        return None
    keep_lan = bool(state.get("keep_lan", True))
    left = deadline - time.time()

    if left <= 0:
        if not is_elevated():
            return ActionResult(
                False, "This machine was left isolated by an earlier run and "
                       "the revert is overdue. Restart with administrator/root "
                       "privileges to lift it.")
        res = _isolate_apply(False, keep_lan)
        _disarm_watchdog()
        if res.ok:
            _clear_state()
            return ActionResult(True, "Isolation left over from an earlier run "
                                      "has been lifted automatically")
        # The state file stays, so the next run tries again rather than
        # forgetting that this machine is still sealed.
        return ActionResult(
            False, "This machine was left isolated by an earlier run and the "
                   f"revert failed: {res.message}. Lift it manually with: "
                   f"{_revert_shell_command()}")

    _isolate_deadline = deadline
    _isolate_timer = threading.Timer(left, _auto_revert)
    _isolate_timer.daemon = True
    _isolate_timer.start()
    return ActionResult(True, f"Isolation still active — reverts in "
                              f"{int(left // 60)} minutes unless confirmed")


def _auto_revert() -> None:
    """What the in-process timer runs. Clears the state so nothing lingers."""
    _isolate_apply(False, bool(_read_state().get("keep_lan", True)))
    _disarm_watchdog()
    _clear_state()


def confirm_isolation() -> ActionResult:
    """Cancels the automatic revert once you have confirmed you are not locked out."""
    global _isolate_timer, _isolate_deadline
    if _isolate_timer:
        _isolate_timer.cancel()
        _isolate_timer = None
    _isolate_deadline = 0.0
    _disarm_watchdog()
    _clear_state()
    return ActionResult(True, "Isolation pinned — it will not revert automatically")


def isolate(enable: bool = True, auto_revert: int = 600,
            keep_lan: bool = True) -> ActionResult:
    """Cuts external connections while keeping the retreat open.

    We block at the firewall rather than disabling the adapter, because
    disabling it destroys live evidence.

    Paired with a dead-man's switch, because isolation may be triggered on a
    machine you reach remotely and would otherwise cut your own access with
    no way back. The switch has two layers: an in-process timer for the
    normal case, and a scheduled task outside this process that still fires
    if the application crashes or is closed. A timer alone dies with the
    program and would leave the machine sealed for good.

    keep_lan preserves the local network so you retain access from inside it.
    """
    global _isolate_timer, _isolate_deadline
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")

    if not enable:
        if _isolate_timer:
            _isolate_timer.cancel()
            _isolate_timer = None
        _isolate_deadline = 0.0
        _disarm_watchdog()
        _clear_state()
        _clear_legacy_rules()
        return _isolate_apply(False, keep_lan)

    res = _isolate_apply(True, keep_lan)
    if res.ok and auto_revert > 0:
        if _isolate_timer:
            _isolate_timer.cancel()
        _isolate_timer = threading.Timer(auto_revert, _auto_revert)
        _isolate_timer.daemon = True
        _isolate_timer.start()
        _isolate_deadline = time.time() + auto_revert
        _write_state(_isolate_deadline, keep_lan)

        mechanism = _arm_watchdog(auto_revert)
        span = (f"{auto_revert // 60} minutes" if auto_revert >= 60
                else f"{auto_revert} seconds")
        res.message += f" — reverts automatically in {span} unless confirmed"
        if mechanism:
            res.message += f" (survives a crash, via {mechanism})"
        else:
            res.message += (". No scheduler available, so the revert only "
                            "happens while this program keeps running — do "
                            "not close it until you have confirmed access")
    elif res.ok:
        _write_state(0.0, keep_lan)
    return res


def _isolate_apply(enable: bool, keep_lan: bool = True) -> ActionResult:
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")

    # Local ranges, excluded so you keep access from inside your own network
    LAN = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
    LAN6 = ["fe80::/10", "fc00::/7"]
    scope = "external only (LAN still works)" if keep_lan else "all"

    if IS_WINDOWS:
        if enable:
            # remoteip accepts a list; block everything but local when keep_lan.
            # 127.0.0.0/8 and 169.254.0.0/16 are excluded alongside the private
            # ranges so loopback and link-local keep working, matching Linux.
            remote = ("1.0.0.0-9.255.255.255,11.0.0.0-126.255.255.255,"
                      "128.0.0.0-169.253.255.255,169.255.0.0-172.15.255.255,"
                      "172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255"
                      if keep_lan else "any")
            for d in ("in", "out"):
                _run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={RULE_PREFIX}-Isolate-{d}", f"dir={d}",
                        "action=block", f"remoteip={remote}"])
            return ActionResult(True, f"Machine isolated — {scope} connections blocked")
        for d in ("in", "out"):
            _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={RULE_PREFIX}-Isolate-{d}"])
        return ActionResult(True, "Isolation lifted")

    backend = _firewall_backend()

    if backend == "nft":
        if enable:
            _nft_ensure()
            # Both directions. An output-only chain leaves every listening
            # backdoor reachable while the interface claims the machine is
            # isolated, which is worse than not isolating at all.
            for chain, hook in (("ngiso", "output"), ("ngisoin", "input")):
                _run(["nft", "add", "chain", "inet", NFT_TABLE, chain,
                      "{ type filter hook " + hook +
                      " priority -5 ; policy accept ; }"])
            _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso",
                    "oifname", "lo", "accept"])
            _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin",
                    "iifname", "lo", "accept"])
            if keep_lan:
                _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso",
                        "ip", "daddr", "{ " + ", ".join(LAN) + " }", "accept"])
                _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso",
                        "ip6", "daddr", "{ " + ", ".join(LAN6) + " }", "accept"])
                _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin",
                        "ip", "saddr", "{ " + ", ".join(LAN) + " }", "accept"])
                _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin",
                        "ip6", "saddr", "{ " + ", ".join(LAN6) + " }", "accept"])
            _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso", "drop"])
            _run(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin", "drop"])
            return ActionResult(True, f"Machine isolated — {scope} connections blocked")
        _run(["nft", "delete", "chain", "inet", NFT_TABLE, "ngiso"])
        _run(["nft", "delete", "chain", "inet", NFT_TABLE, "ngisoin"])
        return ActionResult(True, "Isolation lifted")

    if backend == "iptables":
        # iptables covers IPv4 only. On a dual-stack machine that leaves IPv6
        # wide open while the message says "isolated", so ip6tables is driven
        # in parallel and its absence is reported rather than swallowed.
        gaps = []
        for tool, lan in (("iptables", LAN), ("ip6tables", LAN6)):
            if not shutil.which(tool):
                gaps.append(tool)
                continue
            rules = [["OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                     ["INPUT", "-i", "lo", "-j", "ACCEPT"]]
            if keep_lan:
                for net in lan:
                    rules += [["OUTPUT", "-d", net, "-j", "ACCEPT"],
                              ["INPUT", "-s", net, "-j", "ACCEPT"]]
            rules += [["OUTPUT", "-j", "DROP"], ["INPUT", "-j", "DROP"]]
            # -I inserts in reverse, so we walk backwards to put the accepts first
            for r in reversed(rules):
                _run([tool, "-I" if enable else "-D", r[0]] + r[1:])
        if not enable:
            return ActionResult(True, "Isolation lifted")
        msg = f"Machine isolated — {scope} connections blocked"
        if "ip6tables" in gaps:
            msg += (". Warning: ip6tables is missing, so IPv6 traffic is NOT "
                    "blocked — the machine is only half isolated")
        return ActionResult(True, msg)

    return ActionResult(False, "No supported firewall found")


def reopen_port(port: int, proto: str = "tcp") -> ActionResult:
    """Reopens a port, so close_port is never a one-way action."""
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")
    backend = _firewall_backend()

    if backend == "netsh":
        _run(["netsh", "advfirewall", "firewall", "delete", "rule",
              f"name={RULE_PREFIX}-ClosePort-{port}"])
    elif backend == "nft":
        code, out = _run(["nft", "delete", "element", "inet", NFT_TABLE,
                          f"closed_{proto.lower()}", "{ " + str(port) + " }"])
        if code != 0:
            return ActionResult(False, out.strip()[:160] or "the port was not blocked")
    elif backend == "iptables":
        _run(["iptables", "-D", "INPUT", "-p", proto,
              "--dport", str(port), "-j", "DROP"])
    elif backend == "ufw":
        _run(["ufw", "delete", "deny", f"{port}/{proto}"])
    else:
        return ActionResult(False, "No supported firewall found")
    return ActionResult(True, f"Reopened port {port}/{proto}")


def list_our_rules() -> list[str]:
    """Rules this tool added — so nothing is left behind and forgotten."""
    if _firewall_backend() == "nft":
        _, out = _run(["nft", "list", "table", "inet", NFT_TABLE])
        return [l.strip() for l in out.splitlines()
                if "elements" in l or "@blocked" in l or "@closed" in l]
    if IS_WINDOWS:
        _, out = _run(["netsh", "advfirewall", "firewall", "show", "rule",
                       "name=all"])
        return [l.split(":", 1)[1].strip() for l in out.splitlines()
                if l.strip().startswith("Rule Name") and RULE_PREFIX in l]
    rules = []
    for tool in ("iptables", "ip6tables"):
        if not shutil.which(tool):
            continue
        _, out = _run([tool, "-S"])
        rules += [f"{tool}: {l}" for l in out.splitlines() if "DROP" in l]
    return rules
