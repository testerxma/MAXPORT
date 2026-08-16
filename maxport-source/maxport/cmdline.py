"""Terminal interface, usable by a person and by an automated caller.

Two audiences with different needs share one entry point here. A person
wants a readable report and sensible defaults. A program — a script, a CI
job, or an agent such as Claude Code — wants structured output, an exit code
it can branch on, and above all no surprises.

Three decisions shape this module:

**Nothing destructive happens by default.** Scanning, watching and reporting
are open. Stopping a process, blocking an address and isolating the machine
sit behind explicit flags, and isolation behind a second one. An automated
caller that misreads a finding and stops a system process, or seals a
machine it reaches over the network, causes damage no report is worth. The
gate costs a human one flag and costs a runaway loop everything.

**Elevation is never attempted without someone there to consent.** The
graphical path opens a polkit dialog and returns success immediately; with
nobody to click it, the caller sees exit code 0 and no output and concludes
the machine is clean. That is the worst failure this tool can produce, so
without a terminal we refuse and say what to run instead.

**A failure is never silent.** Every path returns a documented exit code,
and in JSON mode every path emits a JSON object — including the failures.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
import time

from . import elevate, engine, respond
from .store import Store

SCHEMA_VERSION = 1
VERSION = "2.0.0"

# Exit codes. Documented, stable, and meaningful enough that a caller never
# has to parse prose to find out what happened.
EXIT_CLEAR = 0           # scan completed, nothing found
EXIT_FINDINGS = 1        # scan completed, something worth reviewing
EXIT_CONTROLLED = 2      # a remote-control session is active right now
EXIT_INCOMPLETE = 3      # the scan ran but part of it could not
EXIT_NEEDS_PRIVILEGE = 4 # cannot see enough, and cannot ask for consent here
EXIT_USAGE = 5           # bad arguments
EXIT_REFUSED = 6         # an action was blocked by a safety gate
EXIT_ERROR = 7           # unexpected failure

VERDICT_EXIT = {
    engine.VERDICT_CLEAR: EXIT_CLEAR,
    engine.VERDICT_EXPOSED: EXIT_FINDINGS,
    engine.VERDICT_CONTROLLED: EXIT_CONTROLLED,
}


# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------

def is_interactive() -> bool:
    """Is a person present to answer a prompt?

    Both streams are checked. An agent typically has neither, a redirected
    run has one, and only a real terminal session has both.
    """
    try:
        return bool(sys.stdin and sys.stdin.isatty()
                    and sys.stdout and sys.stdout.isatty())
    except Exception:
        return False


def _host_info() -> dict:
    return {
        "name": socket.gethostname(),
        "os": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "elevated": elevate.is_elevated(),
        "interactive": is_interactive(),
    }


def _emit(payload: dict, as_json: bool, human: str = "") -> None:
    """One object on stdout in JSON mode, prose otherwise."""
    if as_json:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2,
                  default=str)
        sys.stdout.write("\n")
    elif human:
        print(human)


def _fail(message: str, code: int, as_json: bool, **extra) -> int:
    """A failure the caller can act on, in whichever format they asked for.

    Errors go to stdout in JSON mode so a caller reading only stdout still
    receives a parseable object rather than an empty stream.
    """
    payload = {"schema": SCHEMA_VERSION, "tool": "maxport", "ok": False,
               "error": message, "exit_code": code}
    payload.update(extra)
    if as_json:
        _emit(payload, True)
    else:
        print(message, file=sys.stderr)
    return code


# --------------------------------------------------------------------------
# privilege handling
# --------------------------------------------------------------------------

def ensure_privilege(as_json: bool, allow_partial: bool,
                     no_elevate: bool) -> int | None:
    """Returns an exit code if the caller must act, or None to continue.

    Without privileges the scan cannot name the process behind a connection,
    which is most of its value. With a person present we offer the OS
    consent prompt. Without one we stop, because the alternative — spawning
    a dialog nobody will see and exiting successfully — reports a clean
    machine that was never examined.
    """
    if elevate.is_elevated():
        return None
    if allow_partial:
        return None

    if is_interactive() and not no_elevate:
        started, status = elevate.try_elevate()
        if started:
            # An elevated instance has taken over this run.
            return EXIT_CLEAR
        hint = elevate.instruction()
    else:
        hint = elevate.instruction()

    return _fail(
        "Not running with administrator/root privileges, so connections "
        "cannot be tied to processes and several checks return nothing. "
        f"{hint} Add --allow-partial to scan anyway and accept a blind spot.",
        EXIT_NEEDS_PRIVILEGE, as_json,
        remedy=hint, allow_partial_flag="--allow-partial")


# --------------------------------------------------------------------------
# serialisation
# --------------------------------------------------------------------------

def finding_id(f) -> str:
    """A stable identifier, so a caller can follow one finding across scans.

    Derived from what the finding *is* rather than where it appeared in a
    list, so it survives reordering and unrelated changes elsewhere.
    """
    import hashlib
    basis = f.key or f"{f.category}|{f.title}|{f.ip}|{f.port}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:12]


def finding_to_dict(f) -> dict:
    return {
        "id": finding_id(f),
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "detail": f.detail,
        "evidence": f.evidence,
        "pid": f.pid,
        "process": f.proc_name or None,
        "ip": f.ip or None,
        "port": f.port or None,
        "key": f.key,
    }


def _conn_to_dict(c) -> dict:
    return {
        "local_port": getattr(c, "lport", 0),
        "remote_address": getattr(c, "raddr", ""),
        "remote_port": getattr(c, "rport", 0),
        "remote_host": getattr(c, "rhost", ""),
        "status": getattr(c, "status", ""),
        "family": getattr(c, "family", ""),
        "tool": getattr(c, "tool", None),
        "tunnel": getattr(c, "tunnel", None),
        "mesh_vpn": getattr(c, "mesh", None),
        "pid": getattr(c.proc, "pid", None),
        "process": getattr(c.proc, "name", ""),
        "path": getattr(c.proc, "exe", ""),
        "trust": getattr(c.proc, "trust", ""),
        "launched_by": getattr(c.proc, "ancestry", ""),
    }


def result_to_dict(res, full: bool = False) -> dict:
    """The scan as data. `full` adds the raw inventories as well as findings."""
    incomplete = [f.title for f in res.findings
                  if f.category == "Incomplete scan"]
    payload = {
        "schema": SCHEMA_VERSION,
        "tool": "maxport",
        "version": VERSION,
        "ok": True,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": _host_info(),
        "verdict": {
            "code": res.verdict,
            "text": res.verdict_text,
            "exit_code": VERDICT_EXIT.get(res.verdict, EXIT_FINDINGS),
        },
        "profile": res.profile,
        "duration_seconds": round(res.duration, 3),
        "counts": {
            "critical": len(res.by_severity(engine.CRITICAL)),
            "warn": len(res.by_severity(engine.WARN)),
            "info": len(res.by_severity(engine.INFO)),
            "connections": len(res.connections),
            "listening": len(res.listening),
            "suppressed": res.suppressed,
            "downgraded": res.downgraded,
        },
        "complete": not incomplete,
        "incomplete_checks": incomplete,
        "warnings": res.warnings,
        "findings": [finding_to_dict(f) for f in res.findings],
        # The timeline and the revocation list are the parts an agent can act
        # on directly, so they are always present rather than gated behind
        # the inventory flag.
        "timeline": res.timeline,
        "exposure": res.exposure,
    }
    if full:
        payload["connections"] = [_conn_to_dict(c) for c in res.connections]
        payload["listening"] = [_conn_to_dict(c) for c in res.listening]
        payload["persistence"] = res.persistence
        payload["browser_extensions"] = res.extensions
        payload["unattended_access"] = res.unattended
        payload["hardening"] = res.hardening
        payload["execution_trace"] = res.exectrace
        payload["network"] = {"arp": res.arp, "dns": res.dns,
                              "hosts": res.hosts, "interfaces": res.interfaces}
    return payload


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def capabilities() -> list[dict]:
    """What this machine actually lets the tool do, and why not otherwise.

    Exists because "the scan found nothing" and "the scan could not look"
    are indistinguishable from the outside. A caller planning what to trust
    should be able to ask first rather than infer from silence.
    """
    import shutil

    is_windows = platform.system() == "Windows"
    elevated = elevate.is_elevated()
    caps: list[dict] = []

    def add(name, ok, detail, remedy=""):
        caps.append({"capability": name, "available": bool(ok),
                     "detail": detail, "remedy": remedy})

    add("privileges", elevated,
        "running as administrator/root" if elevated
        else "unprivileged — connections will have no process names",
        "" if elevated else elevate.instruction())

    try:
        import psutil
        conns = psutil.net_connections(kind="inet")
        named = sum(1 for c in conns if c.pid)
        add("connection ownership", named > 0,
            f"{named} of {len(conns)} connections resolve to a process",
            "" if named else "run with administrator/root privileges")
    except Exception as e:
        add("connection ownership", False, f"psutil failed: {e}",
            "pip install --upgrade psutil")

    if is_windows:
        ps = bool(shutil.which("powershell"))
        add("signature verification", ps,
            "Authenticode checks via PowerShell" if ps
            else "no PowerShell — executables cannot be checked for a valid "
                 "signature",
            "" if ps else "PowerShell not found on PATH")
        netsh = bool(shutil.which("netsh"))
        add("firewall control", netsh,
            "netsh advfirewall" if netsh else "no netsh — cannot block or "
                                              "isolate",
            "" if netsh else "netsh not found on PATH")
        task = bool(shutil.which("schtasks"))
        add("scheduled revert", task,
            "isolation dead-man's switch survives a crash" if task
            else "isolation would revert only while this program keeps "
                 "running",
            "" if task else "schtasks not found on PATH")
    else:
        backend = respond._firewall_backend()
        add("firewall control", bool(backend),
            f"backend: {backend}" if backend else "no nft, iptables or ufw",
            "" if backend else "install nftables or iptables")
        v6 = bool(shutil.which("ip6tables") or backend == "nft")
        add("IPv6 blocking", v6,
            "IPv6 addresses can be blocked and isolated" if v6
            else "no ip6tables and no nft — IPv6 traffic will NOT be blocked, "
                 "so an isolated machine is only half isolated",
            "" if v6 else "install ip6tables or nftables")
        sched = shutil.which("systemd-run") or shutil.which("at")
        add("scheduled revert", bool(sched),
            f"dead-man's switch via {os.path.basename(sched)}, survives a "
            "crash" if sched else "isolation would revert only while this "
                                  "program keeps running",
            "" if sched else "install systemd or at")
        pkg = bool(shutil.which("dpkg") or shutil.which("rpm"))
        add("package version lookup", pkg,
            "versions read from the package manager, without executing the "
            "binary" if pkg else "no dpkg or rpm — versions can only be read "
                                 "for binaries the system vouches for",
            "" if pkg else "expected on Debian/Kali and RHEL; unusual to lack")

    try:
        from . import netcheck
        # An empty table is a legitimate state on an isolated host, so the
        # capability is whether it could be read, not whether it had rows.
        entries = netcheck.arp_table()
        add("ARP table", True, f"readable, {len(entries)} entries")
    except Exception as e:
        add("ARP table", False, f"unreadable: {type(e).__name__}: {e}",
            "ARP and MITM detection will not run")

    try:
        import PySide6  # noqa: F401
        add("graphical interface", True, "PySide6 present")
    except ImportError:
        add("graphical interface", False, "PySide6 not installed",
            "pip install PySide6-Essentials (not needed for terminal use)")

    return caps


def cmd_doctor(args) -> int:
    caps = capabilities()
    missing = [c for c in caps if not c["available"]]
    if args.json:
        _emit({"schema": SCHEMA_VERSION, "tool": "maxport", "ok": True,
               "host": _host_info(), "capabilities": caps,
               "degraded": bool(missing)}, True)
    else:
        print(f"\n  MaxPort {VERSION} on {platform.system()} "
              f"{platform.release()}\n")
        for c in caps:
            mark = "ok  " if c["available"] else "MISS"
            print(f"  [{mark}] {c['capability']}: {c['detail']}")
            if c["remedy"]:
                print(f"         -> {c['remedy']}")
        print()
    return EXIT_CLEAR if not missing else EXIT_INCOMPLETE


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def cmd_scan(args) -> int:
    gate = ensure_privilege(args.json, args.allow_partial, args.no_elevate)
    if gate is not None:
        return gate

    store = None
    if not args.no_history:
        try:
            store = Store()
        except Exception as e:
            if args.json:
                pass          # recorded in warnings below, not fatal
            else:
                print(f"  ! history unavailable: {e}", file=sys.stderr)

    def progress(pct, text):
        if not args.json and not args.quiet:
            print(f"  {pct:3d}%  {text}", file=sys.stderr)

    try:
        res = engine.run_scan(deep=not args.fast, store=store,
                              progress=progress)
    except Exception as e:
        return _fail(f"The scan failed: {type(e).__name__}: {e}",
                     EXIT_ERROR, args.json)

    if args.json:
        _emit(result_to_dict(res, full=args.full), True)
    else:
        from .cli import report
        print(report(res, show_all=args.all))

    code = VERDICT_EXIT.get(res.verdict, EXIT_FINDINGS)
    # An incomplete scan never reports success, whatever it happened to find.
    if any(f.category == "Incomplete scan" for f in res.findings):
        code = max(code, EXIT_INCOMPLETE)
    return code


def cmd_status(args) -> int:
    """Cheap state query — no scan, safe to poll."""
    isolated, seconds_left = respond.isolate_status()
    payload = {
        "schema": SCHEMA_VERSION, "tool": "maxport", "ok": True,
        "host": _host_info(),
        "isolation": {"active": isolated, "seconds_until_revert": seconds_left},
        "firewall_rules": respond.list_our_rules(),
    }
    if args.json:
        _emit(payload, True)
    else:
        print(f"  host       : {payload['host']['name']} "
              f"({payload['host']['os']})")
        print(f"  privileges : "
              f"{'elevated' if payload['host']['elevated'] else 'limited'}")
        print(f"  isolation  : "
              f"{'ACTIVE, reverts in %ds' % seconds_left if isolated else 'off'}")
        for rule in payload["firewall_rules"]:
            print(f"  rule       : {rule}")
    return EXIT_CLEAR


# --------------------------------------------------------------------------
# actions
# --------------------------------------------------------------------------

ACTION_GATE = (
    "Refused: this changes the state of the machine. Re-run with "
    "--allow-actions to permit it. Actions are opt-in because an automated "
    "caller acting on a misread finding can stop a process the system needs."
)

ISOLATE_GATE = (
    "Refused: isolation cuts network access and can lock you out of a "
    "machine you reach remotely. It needs --allow-actions and "
    "--i-am-at-this-machine together."
)


def cmd_act(args) -> int:
    """Response actions, each behind an explicit grant."""
    as_json = args.json

    if not args.allow_actions:
        return _fail(ISOLATE_GATE if args.action == "isolate" else ACTION_GATE,
                     EXIT_REFUSED, as_json, action=args.action)

    if args.action == "isolate" and not args.i_am_at_this_machine:
        return _fail(ISOLATE_GATE, EXIT_REFUSED, as_json, action=args.action)

    if not elevate.is_elevated():
        return _fail(
            f"'{args.action}' needs administrator/root privileges. "
            f"{elevate.instruction()}", EXIT_NEEDS_PRIVILEGE, as_json)

    if args.dry_run:
        preview = {
            "isolate": respond._revert_shell_command(),
            "block": f"block {args.target} at the firewall, both directions",
            "unblock": f"remove the firewall block for {args.target}",
            "stop": f"terminate process {args.target} after verifying identity",
            "confirm-isolation": "cancel the automatic revert",
        }.get(args.action, "")
        return _fail_ok({"action": args.action, "dry_run": True,
                         "would_run": preview}, as_json)

    try:
        if args.action == "block":
            res = respond.block_ip(args.target)
        elif args.action == "unblock":
            res = respond.unblock_ip(args.target)
        elif args.action == "stop":
            res = respond.stop_process(int(args.target), force=args.force)
        elif args.action == "isolate":
            res = respond.isolate(True, auto_revert=args.revert_after)
        elif args.action == "release":
            res = respond.isolate(False)
        elif args.action == "confirm-isolation":
            res = respond.confirm_isolation()
        else:
            return _fail(f"Unknown action: {args.action}", EXIT_USAGE, as_json)
    except ValueError:
        return _fail(f"'{args.target}' is not valid for {args.action}",
                     EXIT_USAGE, as_json)
    except Exception as e:
        return _fail(f"{args.action} failed: {type(e).__name__}: {e}",
                     EXIT_ERROR, as_json)

    try:
        Store().log_action(args.action, str(args.target or ""), res.ok,
                           res.message)
    except Exception:
        pass          # an unrecordable action still happened; do not hide it

    payload = {"schema": SCHEMA_VERSION, "tool": "maxport", "ok": res.ok,
               "action": args.action, "target": args.target,
               "message": res.message}
    if as_json:
        _emit(payload, True)
    else:
        print(("  " if res.ok else "  ! ") + res.message)
    return EXIT_CLEAR if res.ok else EXIT_ERROR


def _fail_ok(payload: dict, as_json: bool) -> int:
    """A successful no-op, such as a dry run."""
    payload = {"schema": SCHEMA_VERSION, "tool": "maxport", "ok": True,
               **payload}
    if as_json:
        _emit(payload, True)
    else:
        print(f"  would run: {payload.get('would_run')}")
    return EXIT_CLEAR


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="maxport",
        description="Detects remote control, backdoors and exposure on this "
                    "machine.",
        epilog="Exit codes: 0 clear · 1 findings · 2 remote session active · "
               "3 incomplete · 4 needs privileges · 5 usage · 6 refused · "
               "7 error",
    )
    p.add_argument("--version", action="version",
                   version=f"maxport {VERSION} (schema {SCHEMA_VERSION})")

    def common(sp):
        sp.add_argument("--json", action="store_true",
                        help="structured output for programs")
        sp.add_argument("--quiet", action="store_true",
                        help="suppress progress on stderr")
        return sp

    sub = p.add_subparsers(dest="command")

    s = common(sub.add_parser("scan", help="run a full scan"))
    s.add_argument("--fast", action="store_true",
                   help="skip hashing and network lookups")
    s.add_argument("--full", action="store_true",
                   help="include raw inventories in JSON output")
    s.add_argument("--all", action="store_true",
                   help="include informational findings in the report")
    s.add_argument("--allow-partial", action="store_true",
                   help="scan without privileges and accept the blind spot")
    s.add_argument("--no-elevate", action="store_true",
                   help="never offer to relaunch with privileges")
    s.add_argument("--no-history", action="store_true",
                   help="do not read or write the local database")
    s.set_defaults(func=cmd_scan)

    d = common(sub.add_parser(
        "doctor", help="report what this machine lets the tool do"))
    d.set_defaults(func=cmd_doctor)

    st = common(sub.add_parser(
        "status", help="isolation state and active rules — no scan"))
    st.set_defaults(func=cmd_status)

    a = common(sub.add_parser("act", help="response actions (opt-in)"))
    a.add_argument("action", choices=["block", "unblock", "stop", "isolate",
                                      "release", "confirm-isolation"])
    a.add_argument("target", nargs="?", default="",
                   help="an IP address, or a PID for stop")
    a.add_argument("--allow-actions", action="store_true",
                   help="required: permit changing the machine's state")
    a.add_argument("--i-am-at-this-machine", action="store_true",
                   help="required for isolate: confirms you have physical "
                        "or console access and can recover from a lockout")
    a.add_argument("--force", action="store_true",
                   help="kill rather than terminate")
    a.add_argument("--revert-after", type=int, default=600, metavar="SECONDS",
                   help="automatic revert delay for isolate (default 600)")
    a.add_argument("--dry-run", action="store_true",
                   help="print what would happen and change nothing")
    a.set_defaults(func=cmd_act)

    return p


def run_cmdline(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # The interface and the older flag style keep working; anything that is
    # not a subcommand falls through to the legacy path so existing scripts
    # and documentation do not break.
    legacy = {"--cli", "--watch", "--all", "--no-elevate"}
    known = {"scan", "doctor", "status", "act", "--help", "-h", "--version"}
    if argv and argv[0] not in known and set(argv) & legacy:
        from .cli import run
        return run(["maxport"] + argv)

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n  interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(run_cmdline())
