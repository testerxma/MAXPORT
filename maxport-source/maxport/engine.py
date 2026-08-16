"""Scan engine — runs every check and produces one clear verdict.

The verdict is the point of the whole tool: is someone controlling this
machine right now? Everything else is evidence supporting that line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict

from . import (collectors, exectrace, extensions, hardening, intel, lolbins,
               netcheck, persistence, profiles, rmmconfig, signatures,
               triage, vulncheck)
from .monitor import conn_key
from .store import Store

CRITICAL, WARN, INFO = "critical", "warn", "info"

VERDICT_CONTROLLED = "controlled"
VERDICT_EXPOSED = "exposed"
VERDICT_CLEAR = "clear"


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)
    pid: int | None = None
    ip: str = ""
    port: int = 0
    key: str = ""            # suppression key — silences this finding alone
    # Identity of the process at scan time. The user may act minutes later,
    # by which point the PID can belong to something else entirely.
    proc_started: float = 0.0
    proc_name: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    started: float = 0.0
    duration: float = 0.0
    verdict: str = VERDICT_CLEAR
    verdict_text: str = ""
    findings: list[Finding] = field(default_factory=list)
    connections: list = field(default_factory=list)
    listening: list = field(default_factory=list)
    persistence: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    unattended: list = field(default_factory=list)
    exposure: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    arp: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    suppressed: int = 0          # findings hidden by the known-good list
    hardening: list = field(default_factory=list)
    exectrace: list = field(default_factory=list)
    profile: str = "desktop"     # desktop | security workstation
    downgraded: int = 0          # findings routine for this profile

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]


# ------------------------- the checks -------------------------

def _check_remote_tools(conns) -> list[Finding]:
    out, seen = [], set()
    for c in conns:
        if not c.tool or c.proc.pid in seen:
            continue
        seen.add(c.proc.pid)
        live = c.status == "ESTABLISHED" and c.raddr
        out.append(Finding(
            severity=CRITICAL if live else WARN,
            category="Remote control",
            title=(f"{c.tool} has an active session" if live
                   else f"{c.tool} is running in the background"),
            detail=(f"Live session with {c.raddr}:{c.rport} — this is an active "
                    if live else
                    "The program is running and ready to accept a session, but none is open."),
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "User": c.proc.username,
                      "Uptime": collectors.uptime_of(c.proc),
                      "Launched by": c.proc.ancestry or "—",
                      "Other party": f"{c.raddr}:{c.rport}" if c.raddr else "—"},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
        ))
    return out


def _check_listening(listening) -> list[Finding]:
    out = []
    for c in listening:
        desc = signatures.describe_port(c.lport)
        exposed = c.laddr in ("0.0.0.0", "::", "")
        if desc:
            note, conf = desc
            if conf == "noisy":
                sev = INFO
            elif conf == "admin" and exposed:
                sev = CRITICAL
            else:
                sev = WARN
            out.append(Finding(
                severity=sev,
                category="Open port",
                title=f"Port {c.lport} is open — {note}",
                detail=("Reachable from any network; anything that can reach you can try to get in."
                        if exposed else
                        "Open on a limited interface only."),
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Address": f"{c.laddr}:{c.lport}",
                          "Launched by": c.proc.ancestry or "—",
                          "Protocol": c.family},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, port=c.lport, key=conn_key(c),
            ))
        elif exposed and c.proc.trust == "untrusted" and c.family == "tcp":
            out.append(Finding(
                severity=WARN,
                category="Open port",
                title=f"An untrusted program is listening on port {c.lport}",
                detail=c.proc.trust_note or "The executable is unsigned and not part of the system.",
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Launched by": c.proc.ancestry or "—",
                          "SHA-256": c.proc.sha256 or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, port=c.lport, key=conn_key(c),
            ))
    return out


def _check_untrusted_outbound(conns) -> list[Finding]:
    out, seen = [], set()
    for c in conns:
        if c.status != "ESTABLISHED" or not c.raddr:
            continue
        if c.proc.pid in seen or c.tool:
            continue
        hint = collectors.path_looks_suspicious(c.proc.exe)
        parent = collectors.parent_is_suspicious(c.proc)
        # "unknown" alone is not enough to alert on, or false alarms would flood
        if c.proc.trust == "untrusted" or hint or parent:
            seen.add(c.proc.pid)
            if parent:
                title = f"{c.proc.name} is calling out, launched by {parent}"
                detail = ("The launch chain is abnormal: this kind of program "
                          "is not expected to start a network program.")
                sev = CRITICAL
            elif hint:
                title = f"{c.proc.name} is calling out from a temporary path"
                detail = (f"Running from {hint} — installed software does not live there.")
                sev = WARN
            else:
                title = f"{c.proc.name} is calling out and is untrusted"
                detail = c.proc.trust_note
                sev = WARN
            out.append(Finding(
                severity=sev, category="Outbound connection",
                title=title, detail=detail,
                evidence={"Path": c.proc.exe, "Destination": f"{c.raddr}:{c.rport}",
                          "Launched by": c.proc.ancestry or "—",
                          "Command": c.proc.cmdline[:200],
                          "SHA-256": c.proc.sha256 or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
    return out


def _check_network(arp, dns, hosts, proxy) -> list[Finding]:
    out = []

    for alert in netcheck.detect_arp_spoof(arp):
        out.append(Finding(
            severity=CRITICAL, category="Network",
            title="Sign of a man-in-the-middle attack",
            detail=(f"The hardware address {alert['mac']} is answering for "
                    f"{alert.get('count', len(alert['ips']))} different hosts on "
                    "the same subnet. One device claiming to be several is how "
                    "traffic gets intercepted."),
            evidence={"MAC": alert["mac"], "Addresses": ", ".join(alert["ips"]),
                      "Vendor": alert.get("vendor") or "unknown"},
            key=f"arp|{alert['mac']}",
        ))

    for h in hosts:
        if h["blocks_security"]:
            out.append(Finding(
                severity=CRITICAL, category="Network",
                title="hosts file is blocking security sites",
                detail="Redirecting antivirus or update sites is something "
                       "malware does to avoid being found.",
                evidence={"Line": str(h["line"]), "Address": h["ip"],
                          "Domains": h["names"]},
                key=f"hosts|{h['ip']}|{h['names']}",
            ))
        elif h["redirect"]:
            out.append(Finding(
                severity=WARN, category="Network",
                title="Redirect in the hosts file",
                detail="A domain pointed at an external address instead of resolving normally.",
                evidence={"Address": h["ip"], "Domains": h["names"]},
                key=f"hosts|{h['ip']}|{h['names']}",
            ))

    if proxy.get("enabled"):
        out.append(Finding(
            severity=WARN, category="Network",
            title="A proxy is enabled on this machine",
            detail="All browsing passes through this server. Make sure you set it.",
            evidence={"Server": proxy.get("server", ""),
                      "Source": proxy.get("source", "")},
            key=f"proxy|{proxy.get('server','')}",
        ))

    known = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
             "208.67.222.222", "208.67.220.220", "127.0.0.1", "127.0.0.53"}
    unknown = [d for d in dns if d not in known
               and not d.startswith(("192.168.", "10.", "172.16.", "fe80"))]
    if unknown:
        out.append(Finding(
            severity=INFO, category="Network",
            title="Unfamiliar DNS servers",
            detail="Not from common providers and not your router. "
                   "Confirm they belong to your ISP.",
            evidence={"Servers": ", ".join(unknown)},
            key=f"dns|{','.join(sorted(unknown))}",
        ))
    return out


def _check_persistence(items) -> list[Finding]:
    out = []
    for it in items:
        if it["risk"] == "critical":
            out.append(Finding(
                severity=CRITICAL, category="Persistence",
                title=f"Suspicious command in {it['name']}",
                detail="A line that runs automatically and contains a download or reverse shell.",
                evidence={"Source": it["source"], "Content": it["value"]},
                key=f"persist|{it['source']}|{it['name']}",
            ))
        elif it["kind"] == "SSH key":
            out.append(Finding(
                severity=WARN, category="Persistence",
                title=f"Authorised SSH key: {it['name']}",
                detail="Anyone holding the matching key logs in without a password. "
                       "Remove any you do not recognise.",
                evidence={"File": it["source"], "Fingerprint": it["value"]},
                key=f"persist|{it['source']}|{it['name']}",
            ))
        elif it["risk"] == "warn":
            out.append(Finding(
                severity=INFO, category="Persistence",
                title=f"{it['kind']}: {it['name']}",
                detail="Runs automatically from outside the system paths — review it.",
                evidence={"Path": it["value"], "Source": it["source"]},
                key=f"persist|{it['source']}|{it['name']}",
            ))
    return out


# ------------------------- the verdict -------------------------

def _decide(findings: list[Finding]) -> tuple[str, str]:
    live = [f for f in findings
            if f.severity == CRITICAL and f.category == "Remote control"]
    if live:
        names = ", ".join(sorted({f.title.split(" has an")[0] for f in live}))
        return VERDICT_CONTROLLED, f"A control session is active right now: {names}"

    crit = [f for f in findings if f.severity == CRITICAL]
    if crit:
        return VERDICT_EXPOSED, f"{len(crit)} critical issues need a decision now"

    warns = [f for f in findings if f.severity == WARN]
    if warns:
        return VERDICT_EXPOSED, f"{len(warns)} items worth reviewing, nothing critical"

    # A clean sheet only counts if every check actually ran
    gaps = [f for f in findings if f.category == "Incomplete scan"]
    if gaps:
        return VERDICT_EXPOSED, (f"{len(gaps)} checks failed to run — the "
                                 "result is incomplete, not clean")

    return VERDICT_CLEAR, "No remote control session and no exposed admin ports"


# ------------------------- execution -------------------------

def _check_hijacked_tool(conns: list) -> list[Finding]:
    """A legitimate control tool talking to a server that is not its vendor's.

    This is the practical difference between "the user installed it" and "it
    was hijacked": the official tool routes through vendor servers, a hijacked
    one is driven from a private one. We resolve the reverse name to tell them apart.
    """
    out = []
    for c in conns:
        if not c.tool or c.status != "ESTABLISHED" or not c.raddr:
            continue
        if intel.classify(c.raddr) != "internet":
            continue
        if not c.rhost:
            c.rhost = intel.reverse_dns(c.raddr)
        match = signatures.vendor_match(c.tool, c.rhost)
        if match is None:
            continue          # no domain on record, or no reverse name — do not accuse
        if match:
            # The name claims the vendor. Confirm it forward, because a PTR
            # record is set by whoever owns the address block.
            if intel.forward_confirmed(c.raddr, c.rhost):
                continue
            detail = ("The address presents a vendor name in reverse DNS, but "
                      "that name does not resolve back to this address. A "
                      "reverse record is set by whoever owns the address "
                      "block, so this is what an operator borrowing the "
                      "vendor's name looks like.")
        else:
            detail = ("The program itself is legitimate, but its session does "
                      "not route through vendor infrastructure — the pattern "
                      "of a sound admin tool being used as a backdoor.")
        out.append(Finding(
            severity=CRITICAL, category="Hijacked tool",
            title=f"{c.tool} is talking to a server that is not the vendor's",
            detail=detail,
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "Destination": f"{c.raddr}:{c.rport}",
                      "Reverse name": c.rhost or "none — raw address",
                      "Launched by": c.proc.ancestry or "—"},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
        ))
    return out


def _check_tunnels(conns: list) -> list[Finding]:
    """Tunnels invert the connection, bypassing firewall and router.

    A tunnel opens no port: the machine dials out, so nothing looks exposed.
    And because the session routes through the tunnel provider, the
    visible address is not the controller's, so IP profiling will not help.
    """
    out, seen = [], set()
    for c in conns:
        # A mesh VPN is a product people install on purpose. It belongs on
        # the report so the user can recognise it, not at a severity that
        # teaches them to ignore the whole tunnel category.
        if c.mesh and c.proc.pid not in seen:
            seen.add(c.proc.pid)
            out.append(Finding(
                severity=INFO, category="Tunnel",
                title=f"{c.mesh} is running on this machine",
                detail=("A mesh VPN, commonly installed deliberately. It does "
                        "give remote access to this machine, so confirm you "
                        "set it up and that you recognise every device on the "
                        "network."),
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—",
                          "Launched by": c.proc.ancestry or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
            continue

        if c.tunnel and c.proc.pid not in seen:
            seen.add(c.proc.pid)
            live = c.status == "ESTABLISHED"
            out.append(Finding(
                severity=CRITICAL if live else WARN,
                category="Tunnel",
                title=(f"{c.tunnel} is running with a live session" if live
                       else f"{c.tunnel} is running on this machine"),
                detail=("A tunnel makes the machine dial outward, passing the "
                        "firewall and router without opening any port. The "
                        "visible address is the provider's, not the controller's."),
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Command": c.proc.cmdline[:220],
                          "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—",
                          "Launched by": c.proc.ancestry or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
            continue

        # A tunnel or dynamic-DNS domain, even when the process is unknown
        if c.status == "ESTABLISHED" and c.raddr and c.proc.pid not in seen:
            if intel.classify(c.raddr) != "internet":
                continue
            if not c.rhost:
                c.rhost = intel.reverse_dns(c.raddr)
            flag = signatures.domain_flags(c.rhost)
            if not flag:
                continue
            seen.add(c.proc.pid)
            kind, domain = flag
            if kind == "tunnel":
                title = f"{c.proc.name} is connected through a tunnel ({domain})"
                detail = ("The destination is a tunnelling service. It may be "
                          "legitimate developer use, or a covert control channel.")
            else:
                title = f"{c.proc.name} is connected to a dynamic domain ({domain})"
                detail = ("Dynamic DNS lets an operator change address without "
                          "changing the malware — common in control channels.")
            out.append(Finding(
                severity=WARN, category="Tunnel",
                title=title, detail=detail,
                evidence={"Path": c.proc.exe, "Reverse name": c.rhost,
                          "Destination": f"{c.raddr}:{c.rport}",
                          "Launched by": c.proc.ancestry or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
    return out


def _check_exectrace(items: list) -> list[Finding]:
    """Commands that already ran — the ClickFix trail after the process exits.

    This is the only check that looks backwards in time. A fetch-and-run
    payload fires in seconds and disappears, so a connection scan finds
    nothing; the Run-box and shell histories still hold the command verbatim.
    """
    sev_map = {"critical": CRITICAL, "warn": WARN, "info": INFO}
    out = []
    for it in items:
        out.append(Finding(
            severity=sev_map.get(it["risk"], WARN),
            category="Executed command",
            title=f"{it['kind']}: {it['name']}",
            detail=("A command matching the shape of a paste-and-run payload "
                    "was recorded. " + it["value"]),
            evidence={"Source": it["source"]},
            key=f"exec|{it['source']}|{it['name']}|{it['value'][:40]}",
        ))
    return out


def _check_hardening(items: list) -> list[Finding]:
    """Dormant doors: no process, port or connection points to them."""
    sev_map = {"critical": CRITICAL, "warn": WARN, "info": INFO}
    out = []
    for it in items:
        out.append(Finding(
            severity=sev_map.get(it["risk"], INFO),
            category="System configuration",
            title=f"{it['kind']}: {it['name']}",
            detail=it["value"],
            evidence={"Source": it["source"]},
            key=f"harden|{it['source']}|{it['name']}",
        ))
    return out


def _check_lolbins(conns: list) -> list[Finding]:
    """Signed system binaries doing work outside their purpose.

    Our trust model treats a valid signature as reassurance, and for these
    binaries that is precisely backwards: they are genuinely signed by the
    vendor and can still fetch and run a payload. An attacker using them
    brings no file of their own, so there is nothing unsigned to catch.
    """
    out, seen = [], set()
    sev_map = {"critical": CRITICAL, "warn": WARN}
    for c in conns:
        if c.proc.pid in seen or c.proc.pid <= 0:
            continue
        live = bool(c.raddr) and c.status == "ESTABLISHED"
        res = lolbins.assess(c.proc.name, c.proc.cmdline,
                             c.proc.ancestry, live)
        if not res:
            continue
        seen.add(c.proc.pid)
        out.append(Finding(
            severity=sev_map.get(res["severity"], WARN),
            category="System binary abuse",
            title=f"{res['binary']} is being used outside its purpose",
            detail=(f"This is the {res['purpose']}, signed by the vendor and "
                    f"present on every machine. It {res['abuse']}. "
                    + "; ".join(res["reasons"]).capitalize() + "."),
            evidence={"Command": c.proc.cmdline[:220],
                      "Launched by": c.proc.ancestry or "—",
                      "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—",
                      "Path": c.proc.exe},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
        ))
    return out


def _check_vulnerable_versions(conns: list) -> list[Finding]:
    """Is an installed remote-access tool on a build with a known exploited flaw?

    Detecting that ScreenConnect is present answers half the question. The
    other half is which build, because an attacker who exploits an unpatched
    flaw needs no credentials at all — and the owner feels safe precisely
    because the software is legitimate and signed.
    """
    out, seen = [], set()
    for c in conns:
        if not c.tool or not c.proc.exe:
            continue
        if c.proc.exe in seen:
            continue
        seen.add(c.proc.exe)
        res = vulncheck.check(c.tool, c.proc.exe)
        if not res:
            continue
        out.append(Finding(
            severity=CRITICAL if res["severity"] == "critical" else WARN,
            category="Vulnerable version",
            title=f"{res['tool']} {res['version']} has an exploited flaw ({res['cve']})",
            detail=(res["note"] + f" Fixed in {res['fixed_in']}; update or "
                    "remove it before anything else."),
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "Installed version": res["version"],
                      "Fixed in": res["fixed_in"],
                      "CVE": res["cve"],
                      "Data compiled": vulncheck.DATA_DATE},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, key=f"vuln|{res['cve']}|{c.proc.exe}",
        ))
    return out


def _check_multiple_rmm(conns: list) -> list[Finding]:
    """More than one remote-access product on one machine.

    Any single one has an innocent explanation. Several rarely do. Operators
    install a second and third deliberately, so that removing the one that
    gets noticed does not remove their access, and so the traces are spread
    across products nobody correlates.

    This costs nothing to check — the tools are already identified — and it
    is the rare signal that grows stronger the more ordinary each individual
    piece looks.
    """
    tools: dict[str, list] = {}
    for c in conns:
        if c.tool:
            tools.setdefault(c.tool, []).append(c)
    if len(tools) < 2:
        return []

    names = sorted(tools)
    return [Finding(
        severity=CRITICAL if len(names) > 2 else WARN,
        category="Remote control",
        title=f"{len(names)} different remote-access tools are running",
        detail=("One remote-access tool is ordinary. Several at once is a "
                "pattern operators create on purpose: if the obvious one is "
                "removed, the others keep the way in, and no single product's "
                "logs show the whole picture. Confirm you installed every one "
                "of these, and remove the ones you did not."),
        evidence={"Tools": ", ".join(names),
                  "Processes": ", ".join(
                      sorted({c.proc.name for group in tools.values()
                              for c in group}))[:300]},
        key="multi-rmm|" + "|".join(names),
    )]


def _check_extensions(items: list[dict]) -> list[Finding]:
    """Browser extensions whose permissions amount to session theft."""
    out = []
    for ext in items:
        concerns = ext.get("concerns") or []
        if not concerns:
            continue
        sideloaded = not ext.get("from_store", True)
        severity = CRITICAL if (sideloaded and concerns) else WARN
        why = concerns[0]
        detail = (f"This extension {why}. That is not proof of anything — a "
                  "password manager needs much the same access — but it is "
                  "the whole capability required to take over an account "
                  "without a password, so it is worth being certain you "
                  "installed it on purpose.")
        if sideloaded:
            detail += (" It also did not come from the browser's store, "
                       "which means something placed it here rather than you "
                       "choosing it from a listing.")
        out.append(Finding(
            severity=severity, category="Browser extension",
            title=f"{ext['name']} can read every session in {ext['browser']}",
            detail=detail,
            evidence={
                "Extension": ext["name"],
                "Browser": f"{ext['browser']} ({ext.get('profile') or '—'})",
                "Identifier": ext.get("id", ""),
                "Version": ext.get("version", ""),
                "Installed from the store": "no" if sideloaded else "yes",
                "It can": "; ".join(
                    extensions.describe_permissions(ext))[:400],
                "Path": ext.get("path", ""),
            },
            key=f"ext|{ext.get('browser')}|{ext.get('id')}",
        ))
    return out


def _check_direct_dns(conns: list, resolvers: list) -> list[Finding]:
    """A program resolving names through a server the system never chose.

    Malware families hard-code their own resolver so that filtering applied
    at the machine's configured DNS never sees the lookup. The system
    resolver is the only thing that should be talking to port 53; anything
    else has gone around the machine's own settings to ask someone
    unaccountable.
    """
    configured = set()
    for r in resolvers or []:
        addr = r.get("server") if isinstance(r, dict) else str(r)
        if addr:
            configured.add(addr.strip())

    out, seen = [], set()
    for c in conns:
        if c.rport != 53 or not c.raddr:
            continue
        if c.raddr in configured:
            continue
        if intel.classify(c.raddr) != "internet":
            continue
        name = (c.proc.name or "").lower()
        # The system's own resolver legitimately talks to whatever it likes
        if name in ("systemd-resolve", "systemd-resolved", "dnsmasq",
                    "unbound", "named", "nscd", "resolvconf", "svchost.exe",
                    "svchost", "dnscache", "connmand", "networkmanager"):
            continue
        if c.proc.pid in seen:
            continue
        seen.add(c.proc.pid)
        out.append(Finding(
            severity=WARN, category="Network",
            title=f"{c.proc.name or 'A program'} is using its own DNS server",
            detail=("This program is asking a name server the machine was "
                    "never configured to use. Going around the system "
                    "resolver is how a lookup avoids any filtering applied "
                    "here, and it is a documented step in current "
                    "paste-and-run campaigns."),
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "Server it asked": c.raddr,
                      "Configured servers": ", ".join(sorted(configured))
                                            or "none detected",
                      "Launched by": c.proc.ancestry or "—"},
            pid=c.proc.pid, proc_started=c.proc.started,
            proc_name=c.proc.name, ip=c.raddr, port=53, key=conn_key(c),
        ))
    return out


def _check_unattended(items: list[dict]) -> list[Finding]:
    """Remote-access tools set up to admit someone with nobody present."""
    out = []
    for item in items:
        sev = {"critical": CRITICAL, "warn": WARN}.get(item.get("risk"), INFO)
        out.append(Finding(
            severity=sev, category="Remote control",
            title=f"{item['tool']}: {item['setting']}",
            detail=item["detail"],
            evidence={"Tool": item["tool"], "Setting": item["setting"],
                      "Configuration file": item.get("path", "")},
            key=f"unattended|{item['tool']}|{item['setting']}",
        ))
    return out


def _check_install_chain(conns: list) -> list[Finding]:
    """Abnormal launch chains — shells do not normally install software."""
    out, seen = [], set()
    for c in conns:
        low = (c.proc.cmdline or "").lower()
        anc = (c.proc.ancestry or "").lower()
        if c.proc.pid in seen:
            continue
        silent = ("msiexec" in low and ("/qn" in low or "/quiet" in low))
        # Whole-name comparison: "sh(" as a substring matched "flush(12)"
        from_shell = bool(
            set(collectors._ancestry_names(c.proc.ancestry)) &
            {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta"})
        if silent and from_shell:
            seen.add(c.proc.pid)
            out.append(Finding(
                severity=CRITICAL, category="Silent install",
                title="A silent install launched by a shell",
                detail=("A command shell ran an installer in silent mode and it "
                        "then reached the network — how a control tool gets "
                        "installed without the user knowing."),
                evidence={"Command": c.proc.cmdline[:220],
                          "Launched by": c.proc.ancestry or "—",
                          "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
    return out


def _safely(res: ScanResult, label: str, fn, *args):
    """Runs one check, turning a crash into a visible gap rather than silence.

    A check that raises used to contribute nothing, and nothing is
    indistinguishable from "found nothing" — the scan then reports a clean
    machine on the strength of a check that never ran. Here the failure
    becomes a warning the user sees and a finding they can act on.
    """
    try:
        return fn(*args)
    except Exception as e:
        res.warnings.append(f"The {label} check failed: {type(e).__name__}: "
                            f"{str(e)[:120]}")
        res.findings.append(Finding(
            severity=WARN, category="Incomplete scan",
            title=f"The {label} check did not run",
            detail=("This part of the scan failed, so anything it would have "
                    "found is missing from the verdict. Treat the result as "
                    "incomplete rather than clean."),
            evidence={"Error": f"{type(e).__name__}: {str(e)[:200]}"},
            key=f"scanfail|{label}",
        ))
        return []


def _build_timeline(res: "ScanResult") -> list[dict]:
    """The findings in the order they happened, when that is knowable.

    A list of findings answers "what is wrong". It does not answer the
    question people actually arrive with, which is "what happened to me".
    Ordering by time does: a remote-access tool installed at 14:02, a
    connection out at 14:03 and an autostart entry at 14:05 is not three
    findings, it is one afternoon, and seeing it laid out is often the
    moment someone recognises the support call they took.
    """
    events = []

    for c in res.connections:
        if c.tool and c.proc.started:
            events.append({
                "when": c.proc.started,
                "what": f"{c.tool} started",
                "detail": c.proc.exe or c.proc.name,
                "severity": CRITICAL if c.status == "ESTABLISHED" else WARN,
            })

    for item in res.persistence or []:
        when = item.get("modified") or item.get("created") or 0
        if when:
            events.append({
                "when": when,
                "what": f"Autostart entry: {item.get('name', '')}",
                "detail": item.get("detail", "")[:160],
                "severity": WARN,
            })

    for item in res.exectrace or []:
        when = item.get("when") or item.get("modified") or 0
        if when:
            events.append({
                "when": when,
                "what": item.get("kind", "Command run"),
                "detail": item.get("detail", "")[:160],
                "severity": CRITICAL if item.get("risk") == "critical" else WARN,
            })

    for ext in res.extensions or []:
        if ext.get("installed") and ext.get("concerns"):
            events.append({
                "when": ext["installed"],
                "what": f"Extension installed: {ext['name']}",
                "detail": f"{ext['browser']} — {ext['concerns'][0][:120]}",
                "severity": WARN,
            })

    events.sort(key=lambda e: e["when"])

    # Events close together are usually one action, not several. Marking the
    # gaps is what turns a list into a story.
    for i, event in enumerate(events):
        gap = 0.0 if i == 0 else event["when"] - events[i - 1]["when"]
        event["seconds_after_previous"] = round(gap, 1)
        event["same_episode"] = bool(i and gap < 600)
    return events


def run_scan(deep: bool = True, store: Store | None = None,
             progress=None, vt_key: str = "") -> ScanResult:
    """Runs the full scan. progress(percent, text) for live updates."""
    def step(pct: int, text: str):
        if progress:
            progress(pct, text)

    res = ScanResult(started=time.time())
    t0 = time.perf_counter()

    step(5, "Reading active connections…")
    conns, warn = collectors.collect_connections(deep=deep)
    res.connections = conns
    if warn:
        res.warnings.append(warn)

    res.listening = collectors.listening_ports(conns)

    step(30, "Matching remote-control signatures…")
    res.findings += _safely(res, "remote-control", _check_remote_tools, conns)
    res.findings += _safely(res, "multiple-tool", _check_multiple_rmm, conns)
    res.findings += _safely(res, "listening-port", _check_listening, res.listening)
    res.findings += _safely(res, "outbound", _check_untrusted_outbound, conns)
    res.findings += _safely(res, "install-chain", _check_install_chain, conns)
    res.findings += _safely(res, "system-binary", _check_lolbins, conns)

    step(38, "Checking remote-access tool versions…")
    res.findings += _safely(res, "vulnerable-version",
                            _check_vulnerable_versions, conns)

    step(42, "Checking tunnels and covert channels…")
    res.findings += _safely(res, "tunnel", _check_tunnels, conns)

    step(50, "Verifying control tool destinations…")
    # Needs reverse DNS over the network, so deep scans only
    if deep:
        res.findings += _safely(res, "hijacked-tool", _check_hijacked_tool, conns)

    step(55, "Inspecting the network…")
    res.arp = _safely(res, "ARP-table", netcheck.arp_table)
    res.arp += _safely(res, "IPv6-neighbour", netcheck.neighbour_table)
    res.dns = _safely(res, "DNS-server", netcheck.dns_servers)
    res.hosts = _safely(res, "hosts-file", netcheck.hosts_entries)
    res.interfaces = _safely(res, "interface", netcheck.interfaces)
    res.findings += _safely(res, "network", _check_network, res.arp, res.dns,
                            res.hosts, netcheck.proxy_settings())
    res.findings += _safely(res, "direct-DNS", _check_direct_dns, conns,
                            res.dns)

    step(72, "Checking persistence points…")
    sub_errors: list[str] = []
    res.persistence = _safely(res, "persistence", persistence.scan, sub_errors)
    res.findings += _safely(res, "persistence", _check_persistence, res.persistence)

    step(78, "Reading what recently executed…")
    res.exectrace = _safely(res, "execution-trace", exectrace.scan_exectrace,
                            sub_errors)
    res.findings += _safely(res, "execution-trace", _check_exectrace, res.exectrace)

    step(80, "Reading browser extensions…")
    res.extensions = _safely(res, "browser-extension",
                             extensions.scan_extensions, sub_errors)
    res.findings += _safely(res, "browser-extension", _check_extensions,
                            res.extensions)

    step(81, "Checking remote-access configuration…")
    res.unattended = _safely(res, "unattended-access",
                             rmmconfig.scan_unattended, sub_errors)
    res.findings += _safely(res, "unattended-access", _check_unattended,
                            res.unattended)

    step(82, "Checking dormant doors and protection settings…")
    res.hardening = _safely(res, "hardening", hardening.scan_hardening,
                            sub_errors)
    res.findings += _safely(res, "hardening", _check_hardening, res.hardening)

    # A sub-check that failed removed its whole category from the results.
    # Reported, so the absence of findings in that area is not read as their
    # absence on the machine.
    for err in sub_errors:
        res.warnings.append(f"Part of the scan did not run — {err}")
        res.findings.append(Finding(
            severity=WARN, category="Incomplete scan",
            title=f"The {err.split(':')[0]} check did not run",
            detail=("This part of the scan failed, so anything it would have "
                    "found is missing. Treat the result as incomplete rather "
                    "than clean."),
            evidence={"Error": err},
            key=f"scanfail|{err.split(':')[0]}",
        ))

    step(86, "Applying the machine profile…")
    res.profile = profiles.detect()
    res.findings, res.downgraded = profiles.adjust(res.findings, res.profile)

    step(88, "Applying the known-good list…")
    if store:
        kept = []
        for f in res.findings:
            if f.key and store.is_approved(f.key):
                res.suppressed += 1
                continue
            kept.append(f)
        res.findings = kept

    if vt_key:
        step(90, "Asking VirusTotal about file hashes…")
        # Critical findings only: the free tier allows 4 queries a minute
        for f in res.findings[:8]:
            h = f.evidence.get("SHA-256", "")
            if not h or h == "—":
                continue
            text, sev = intel.vt_summary(intel.virustotal(h, vt_key))
            if not text:
                continue
            f.evidence["VirusTotal"] = text
            if sev == "critical":
                f.severity = CRITICAL
                f.detail += f" — {text}."

    # Static data ages. A clean result must not be read as a guarantee.
    res.warnings.append(vulncheck.advisory_note())

    step(90, "Assembling the timeline…")
    res.timeline = _safely(res, "timeline", _build_timeline, res)

    # The exposure list is only built when something was actually found.
    # Handing someone a list of credentials to revoke on a clean machine
    # teaches them to ignore it on the day it matters.
    if any(f.severity in (CRITICAL, WARN) and
           f.category not in ("Incomplete scan",) for f in res.findings):
        res.exposure = _safely(res, "exposure", triage.build_checklist,
                               sub_errors)

    step(92, "Assembling the verdict…")
    order = {CRITICAL: 0, WARN: 1, INFO: 2}
    res.findings.sort(key=lambda f: order.get(f.severity, 3))
    res.verdict, res.verdict_text = _decide(res.findings)

    if store:
        store.record(conns)
        store.save_findings(res.findings)

    res.duration = time.perf_counter() - t0
    step(100, "Complete")
    return res
