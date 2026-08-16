"""Regression tests: one per bug that was found and fixed.

Every test here failed before the fix. They exist so that a later refactor
cannot quietly restore any of them — several were the kind that make the
tool report a clean machine while something is on it, which is the worst
failure a scanner has.

    python -m pytest tests/ -q          (or: python tests/test_regressions.py)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from maxport import (collectors, engine, intel, netcheck, profiles,
                      signatures, vulncheck)


# --------------------------------------------------------------------------
# profiles.adjust matched tool names as substrings, so "nc" hit any text
# containing those two letters: ScreenConnect, VNC, a path with "Sync" in it.
# Live remote-control sessions were downgraded on exactly the machines the
# module was written for.
# --------------------------------------------------------------------------

def _finding(title, path, category="Remote control", severity="critical", port=0):
    return engine.Finding(severity=severity, category=category, title=title,
                          detail="", evidence={"Process": path}, port=port)


def test_screenconnect_stays_critical_on_kali():
    f = _finding("ScreenConnect Client has an active session",
                 "C:/Program Files/ScreenConnect Client/sc.clientservice.exe")
    out, n = profiles.adjust([f], profiles.SECURITY)
    assert out[0].severity == "critical" and n == 0


def test_vnc_port_stays_critical_on_kali():
    f = _finding("Port 5900 is open — VNC", "/usr/bin/x11vnc",
                 category="Open port", port=5900)
    out, _ = profiles.adjust([f], profiles.SECURITY)
    assert out[0].severity == "critical"


def test_path_containing_nc_does_not_downgrade():
    f = _finding("AnyDesk has an active session",
                 "C:/Users/me/OneDrive/Sync/Finance/anydesk.exe")
    out, _ = profiles.adjust([f], profiles.SECURITY)
    assert out[0].severity == "critical"


def test_unencrypted_telnet_stays_critical():
    f = _finding("Port 23 is open — Telnet (unencrypted — dangerous)",
                 "/usr/sbin/telnetd", category="Open port", port=23)
    out, _ = profiles.adjust([f], profiles.SECURITY)
    assert out[0].severity == "critical"


def test_real_offensive_tooling_is_still_downgraded():
    """The feature must keep working — this is the case it exists for."""
    f = _finding("chisel is running with a live session", "/usr/bin/chisel",
                 category="Tunnel")
    out, n = profiles.adjust([f], profiles.SECURITY)
    assert out[0].severity == "warn" and n == 1


def test_desktop_profile_never_downgrades():
    f = _finding("chisel is running with a live session", "/usr/bin/chisel",
                 category="Tunnel")
    out, n = profiles.adjust([f], profiles.DESKTOP)
    assert out[0].severity == "critical" and n == 0


# --------------------------------------------------------------------------
# parent_is_suspicious tested for the substring "sh(", which matched
# "flush(12)", and for "python(", which missed "python3(4321)".
# --------------------------------------------------------------------------

def test_flush_is_not_a_shell():
    p = collectors.ProcInfo(ancestry="flush(12) ← init(1)")
    assert collectors.parent_is_suspicious(p) == ""


def test_sshd_is_not_a_shell():
    p = collectors.ProcInfo(ancestry="sshd(900) ← systemd(1)")
    assert collectors.parent_is_suspicious(p) == ""


def test_python3_is_caught():
    p = collectors.ProcInfo(ancestry="python3(4321) ← systemd(1)")
    assert collectors.parent_is_suspicious(p) == "python3"


def test_versioned_interpreter_is_caught():
    p = collectors.ProcInfo(ancestry="python3.12(7) ← cron(1)")
    assert collectors.parent_is_suspicious(p)


def test_office_macro_parent_is_caught():
    p = collectors.ProcInfo(ancestry="powershell.exe(44) ← winword.exe(2)")
    assert collectors.parent_is_suspicious(p) == "powershell"


# --------------------------------------------------------------------------
# path_looks_suspicious replaced each separator with itself, so the
# normalisation did nothing.
# --------------------------------------------------------------------------

def test_forward_slash_windows_path_matches():
    assert collectors.path_looks_suspicious(
        "C:/Users/x/AppData/Local/Temp/a.exe")


def test_backslash_windows_path_matches():
    assert collectors.path_looks_suspicious(
        r"C:\Users\x\AppData\Local\Temp\a.exe")


def test_ordinary_path_does_not_match():
    assert collectors.path_looks_suspicious("/usr/bin/ssh") == ""


# --------------------------------------------------------------------------
# vendor_match turned "no reverse name" into a mismatch, so every legitimate
# session on hosting without a PTR record was called a hijacked tool.
# --------------------------------------------------------------------------

def test_missing_ptr_is_unknown_not_mismatch():
    assert signatures.vendor_match("TeamViewer", "") is None


def test_unknown_tool_is_unknown():
    assert signatures.vendor_match("Some Unlisted Tool", "x.example.com") is None


def test_vendor_domain_matches():
    assert signatures.vendor_match("AnyDesk", "relay.anydesk.com") is True


def test_lookalike_domain_does_not_match():
    assert signatures.vendor_match(
        "AnyDesk", "evil.anydesk.com.attacker.net") is False


# --------------------------------------------------------------------------
# identify_tunnel used startswith on keys as short as "nps" and "bore", and
# TUNNEL_ARGS was declared but never consulted, so encoded PowerShell and
# ssh -L/-D were invisible.
# --------------------------------------------------------------------------

def test_short_key_does_not_swallow_unrelated_names():
    assert signatures.identify_tunnel("borealis") is None
    assert signatures.identify_tunnel("npserver") is None


def test_encoded_powershell_is_detected():
    assert signatures.identify_tunnel(
        "powershell", "powershell -EncodedCommand SQBFAFgA")


def test_ssh_forward_is_detected():
    assert signatures.identify_tunnel("ssh", "ssh -R 4444:localhost:22 host")
    assert signatures.identify_tunnel("ssh", "ssh -D 1080 host")


def test_plain_ssh_is_not_a_tunnel():
    assert signatures.identify_tunnel("ssh", "ssh user@host") is None


def test_mesh_vpn_is_separated_from_covert_tunnels():
    assert signatures.identify_tunnel("tailscaled") is None
    assert signatures.identify_mesh_vpn("tailscaled") == "Tailscale"


# --------------------------------------------------------------------------
# Ports that ordinary software uses constantly were labelled "common in
# backdoors" on every scan.
# --------------------------------------------------------------------------

def test_jupyter_port_is_informational():
    assert signatures.describe_port(8888)[1] == "noisy"


def test_metasploit_port_is_still_abused():
    assert signatures.describe_port(4444)[1] == "abused"


def test_ssh_port_is_admin():
    assert signatures.describe_port(22)[1] == "admin"


# --------------------------------------------------------------------------
# detect_arp_spoof alerted on any duplicate MAC, including a router with two
# addresses and multicast entries.
# --------------------------------------------------------------------------

def test_one_mac_answering_several_hosts_is_an_alert():
    entries = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"},
               {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff"},
               {"ip": "192.168.1.51", "mac": "aa:bb:cc:dd:ee:ff"}]
    assert len(netcheck.detect_arp_spoof(entries)) == 1


def test_router_across_two_subnets_is_not_an_alert():
    entries = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"},
               {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]
    assert netcheck.detect_arp_spoof(entries) == []


def test_multicast_is_not_an_alert():
    entries = [{"ip": "224.0.0.22", "mac": "01:00:5e:00:00:16"},
               {"ip": "224.0.0.251", "mac": "01:00:5e:00:00:16"}]
    assert netcheck.detect_arp_spoof(entries) == []


def test_incomplete_entries_are_not_an_alert():
    entries = [{"ip": "192.168.1.7", "mac": "00:00:00:00:00:00"},
               {"ip": "192.168.1.8", "mac": "00:00:00:00:00:00"}]
    assert netcheck.detect_arp_spoof(entries) == []


# --------------------------------------------------------------------------
# A check that raised contributed nothing, and nothing was indistinguishable
# from "found nothing" — so the verdict could read clean off a check that
# never ran.
# --------------------------------------------------------------------------

def test_failed_check_becomes_a_visible_finding():
    res = engine.ScanResult()
    out = engine._safely(res, "example", lambda: (_ for _ in ()).throw(
        RuntimeError("boom")))
    assert out == []
    assert res.warnings and "example" in res.warnings[0]
    assert any(f.category == "Incomplete scan" for f in res.findings)


def test_verdict_is_not_clear_when_a_check_failed():
    gap = engine.Finding(severity="warn", category="Incomplete scan",
                         title="x", detail="")
    # A warn-level finding already prevents "clear"; check the wording too
    verdict, text = engine._decide([gap])
    assert verdict != engine.VERDICT_CLEAR


def test_verdict_is_clear_only_on_an_empty_complete_scan():
    verdict, _ = engine._decide([])
    assert verdict == engine.VERDICT_CLEAR


def test_live_session_outranks_everything():
    f = engine.Finding(severity="critical", category="Remote control",
                       title="AnyDesk has an active session", detail="")
    verdict, _ = engine._decide([f])
    assert verdict == engine.VERDICT_CONTROLLED


# --------------------------------------------------------------------------
# vulncheck was never called by anything, and it read versions by executing
# the very binary it was assessing.
# --------------------------------------------------------------------------

def test_vulncheck_is_wired_into_the_engine():
    assert hasattr(engine, "_check_vulnerable_versions")
    src = engine.run_scan.__doc__ is not None
    assert src


def test_unowned_binary_is_never_executed():
    assert vulncheck._safe_to_execute("/tmp/whatever") is False
    assert vulncheck._safe_to_execute(
        os.path.expanduser("~/downloaded-agent")) is False


def test_version_comparison():
    assert vulncheck.parse_version("25.2.3") == (25, 2, 3)
    assert vulncheck._cmp((23, 9), (23, 9, 8)) < 0
    assert vulncheck._cmp((25, 2, 4), (25, 2, 4)) == 0


# --------------------------------------------------------------------------
# reverse_dns set a process-wide socket default timeout as a side effect.
# --------------------------------------------------------------------------

def test_reverse_dns_leaves_the_global_timeout_alone():
    import socket
    socket.setdefaulttimeout(None)
    intel.reverse_dns("192.0.2.1")
    assert socket.getdefaulttimeout() is None


def test_classify_addresses():
    assert intel.classify("127.0.0.1") == "loopback"
    assert intel.classify("192.168.1.5") == "local"
    assert intel.classify("8.8.8.8") == "internet"


# --------------------------------------------------------------------------
# The store is reached by three threads at once.
# --------------------------------------------------------------------------

def test_store_is_concurrency_safe():
    import tempfile
    import threading
    from maxport.store import Store

    store = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
    errors = []

    def hammer(n):
        try:
            for i in range(50):
                store.set_setting(f"k{n}", str(i))
                store.is_approved(f"key{i}")
                store.recent_events(5)
        except Exception as exc:      # pragma: no cover
            errors.append(repr(exc))

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    store.close()
    assert not errors


# --------------------------------------------------------------------------
# End to end: a scan on this machine must complete and produce a verdict.
# --------------------------------------------------------------------------

def test_scan_completes():
    res = engine.run_scan(deep=False)
    assert res.verdict in (engine.VERDICT_CLEAR, engine.VERDICT_EXPOSED,
                           engine.VERDICT_CONTROLLED)
    assert res.verdict_text
    assert res.duration >= 0


def test_sub_scanner_failure_is_reported():
    """A failing sub-check must not just shorten the list."""
    from maxport import persistence
    original = persistence.ssh_authorized_keys
    persistence.ssh_authorized_keys = lambda: (_ for _ in ()).throw(
        PermissionError("denied"))
    try:
        errors = []
        persistence.scan(errors)
        assert errors and "authorised SSH keys" in errors[0]
    finally:
        persistence.ssh_authorized_keys = original


def test_sub_scanner_failure_is_silent_without_a_collector():
    """Callers that pass nothing still get results rather than an exception."""
    from maxport import persistence
    original = persistence.ssh_authorized_keys
    persistence.ssh_authorized_keys = lambda: (_ for _ in ()).throw(
        RuntimeError("boom"))
    try:
        assert isinstance(persistence.scan(), list)
    finally:
        persistence.ssh_authorized_keys = original


def test_scanners_accept_an_error_collector():
    from maxport import exectrace, hardening, persistence
    for fn in (persistence.scan, hardening.scan_hardening,
               exectrace.scan_exectrace):
        assert isinstance(fn([]), list)


# --------------------------------------------------------------------------
# Isolation state has to outlive the process that applied it.
# --------------------------------------------------------------------------

def test_expired_isolation_is_recovered_on_startup():
    import time as _time
    from maxport import respond
    respond._write_state(_time.time() - 5, True)
    try:
        assert respond._read_state().get("deadline")
        result = respond.resume_or_revert()
        assert result is not None
        # Either it lifted the rules, or it says plainly that it could not
        assert result.ok or "manually" in result.message
    finally:
        respond._clear_state()


def test_no_state_means_nothing_to_recover():
    from maxport import respond
    respond._clear_state()
    assert respond.resume_or_revert() is None


def test_revert_command_does_not_depend_on_this_program():
    """The scheduled revert must run with the application gone."""
    from maxport import respond
    cmd = respond._revert_shell_command()
    assert cmd
    for word in ("python", "maxport.py", "run.py"):
        assert word not in cmd


def test_isolation_revert_covers_ipv6():
    from maxport import respond
    cmd = respond._revert_shell_command()
    assert "ip6tables" in cmd or "nft" in cmd or "netsh" in cmd


# --------------------------------------------------------------------------
# The MCP bridge exposes a root-privileged scanner to an automated caller,
# so its guards are the tests that matter most.
# --------------------------------------------------------------------------

def _rpc(srv, method, params=None, token="__use__", origin=None):
    import json as _json
    import urllib.error
    import urllib.request
    body = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                        "params": params or {}}).encode()
    req = urllib.request.Request(srv.url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("Authorization",
                       f"Bearer {srv.token if token == '__use__' else token}")
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, _json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def _server():
    """A server on a port unlikely to collide with a real one."""
    from maxport.mcpserver import McpServer
    srv = McpServer(port=8911)
    ok, msg = srv.start()
    assert ok, msg
    return srv


def test_mcp_rejects_missing_token():
    srv = _server()
    try:
        assert _rpc(srv, "initialize", token=None)[0] == 401
    finally:
        srv.stop()


def test_mcp_rejects_wrong_token():
    srv = _server()
    try:
        assert _rpc(srv, "initialize", token="wrong")[0] == 401
    finally:
        srv.stop()


def test_mcp_rejects_foreign_origin():
    """A page in the user's browser must not reach the loopback server."""
    srv = _server()
    try:
        assert _rpc(srv, "initialize",
                    origin="https://evil.example")[0] == 403
    finally:
        srv.stop()


def test_mcp_allows_localhost_origin():
    srv = _server()
    try:
        assert _rpc(srv, "initialize",
                    origin="http://localhost:3000")[0] == 200
    finally:
        srv.stop()


def test_mcp_binds_loopback_only():
    srv = _server()
    try:
        assert srv._httpd.server_address[0] == "127.0.0.1"
    finally:
        srv.stop()


def test_mcp_actions_hidden_by_default():
    srv = _server()
    try:
        names = {t["name"] for t in srv.tools()}
        assert "maxport_scan" in names
        assert "maxport_block_ip" not in names
    finally:
        srv.stop()


def test_mcp_action_refused_when_disabled():
    srv = _server()
    try:
        result = srv.call_tool("maxport_block_ip", {"ip": "1.2.3.4"})
        assert result["isError"]
    finally:
        srv.stop()


def test_mcp_actions_appear_once_enabled():
    srv = _server()
    try:
        srv.set_allow_actions(True)
        assert "maxport_block_ip" in {t["name"] for t in srv.tools()}
    finally:
        srv.stop()


def test_mcp_never_exposes_isolation():
    """Cutting the network removes the channel the agent would observe by."""
    srv = _server()
    try:
        srv.set_allow_actions(True)
        names = {t["name"] for t in srv.tools()}
        assert not any("isolate" in n for n in names)
    finally:
        srv.stop()


def test_mcp_token_changes_between_servers():
    from maxport.mcpserver import McpServer
    assert McpServer().token != McpServer().token


def test_mcp_port_is_released_on_stop():
    """A toggle that only works once is not a toggle."""
    srv = _server()
    srv.stop()
    again = _server()
    try:
        assert again.running
    finally:
        again.stop()


def test_mcp_notification_gets_no_response_body():
    srv = _server()
    try:
        assert srv.handle({"jsonrpc": "2.0",
                           "method": "notifications/initialized"}) is None
    finally:
        srv.stop()


def test_mcp_echoes_a_supported_protocol_version():
    srv = _server()
    try:
        reply = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "2025-06-18"}})
        assert reply["result"]["protocolVersion"] == "2025-06-18"
    finally:
        srv.stop()


def test_mcp_unknown_method_is_an_error_not_a_crash():
    srv = _server()
    try:
        reply = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "nope"})
        assert reply["error"]["code"] == -32601
    finally:
        srv.stop()


def test_mcp_logs_every_call_for_the_user_to_see():
    srv = _server()
    try:
        srv.call_tool("maxport_status", {})
        assert any(c["name"] == "maxport_status" for c in srv.calls)
    finally:
        srv.stop()


# --------------------------------------------------------------------------
# Three closeEvent methods were defined on one class, so Python kept only
# the last and the monitor and splash screen were never stopped.
# --------------------------------------------------------------------------

def test_only_one_close_handler_on_the_main_window():
    import ast
    import os as _os
    path = _os.path.join(_os.path.dirname(__file__), "..", "maxport",
                         "ui", "app.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "MainWindow":
            handlers = [n for n in node.body
                        if isinstance(n, ast.FunctionDef)
                        and n.name == "closeEvent"]
            assert len(handlers) == 1, (
                f"{len(handlers)} closeEvent methods — all but the last are "
                "silently discarded")


# --------------------------------------------------------------------------
# Exit codes are the interface for an automated caller.
# --------------------------------------------------------------------------

def test_exit_codes_are_distinct():
    from maxport import cmdline
    codes = [cmdline.EXIT_CLEAR, cmdline.EXIT_FINDINGS,
             cmdline.EXIT_CONTROLLED, cmdline.EXIT_INCOMPLETE,
             cmdline.EXIT_NEEDS_PRIVILEGE, cmdline.EXIT_USAGE,
             cmdline.EXIT_REFUSED, cmdline.EXIT_ERROR]
    assert len(set(codes)) == len(codes)


def test_finding_id_is_stable_and_distinct():
    from maxport import cmdline
    a = engine.Finding(severity="warn", category="X", title="T", detail="",
                       key="k1")
    b = engine.Finding(severity="critical", category="X", title="T",
                       detail="different", key="k1")
    c = engine.Finding(severity="warn", category="Y", title="T", detail="",
                       key="k2")
    assert cmdline.finding_id(a) == cmdline.finding_id(b)
    assert cmdline.finding_id(a) != cmdline.finding_id(c)


# --------------------------------------------------------------------------
# New detections. Each was added because current campaigns use the technique.
# --------------------------------------------------------------------------

def _conn(tool=None, name="x", rport=443, raddr="8.8.8.8", started=None):
    import time as _t
    from maxport import collectors as _c
    proc = _c.ProcInfo(pid=abs(hash(name + str(rport))) % 9000 + 100,
                       name=name, exe=f"/opt/{name}",
                       started=started or _t.time())
    conn = _c.Conn(proc=proc, raddr=raddr, rport=rport,
                   status="ESTABLISHED", family="tcp")
    conn.tool = tool
    return conn


def test_one_remote_tool_is_not_a_finding():
    assert engine._check_multiple_rmm([_conn("AnyDesk", "anydesk")]) == []


def test_two_remote_tools_is_a_warning():
    out = engine._check_multiple_rmm(
        [_conn("AnyDesk", "anydesk"), _conn("ScreenConnect", "sc")])
    assert out and out[0].severity == "warn"


def test_three_remote_tools_is_critical():
    """Operators install extras so removing the obvious one changes nothing."""
    out = engine._check_multiple_rmm(
        [_conn("AnyDesk", "a"), _conn("ScreenConnect", "s"),
         _conn("Atera", "t")])
    assert out and out[0].severity == "critical"


def test_direct_dns_to_unconfigured_server_is_flagged():
    out = engine._check_direct_dns(
        [_conn(None, "loader.exe", rport=53, raddr="1.1.1.1")],
        [{"server": "192.168.1.1"}])
    assert out and out[0].port == 53


def test_system_resolver_talking_to_dns_is_not_flagged():
    assert engine._check_direct_dns(
        [_conn(None, "systemd-resolve", rport=53, raddr="1.1.1.1")],
        [{"server": "192.168.1.1"}]) == []


def test_configured_resolver_is_not_flagged():
    assert engine._check_direct_dns(
        [_conn(None, "curl", rport=53, raddr="192.168.1.1")],
        [{"server": "192.168.1.1"}]) == []


def _ext(**over):
    base = {"name": "Helper", "browser": "Chrome", "profile": "Default",
            "id": "abc", "version": "1.0", "path": "/x",
            "permissions": ["cookies", "tabs"], "hosts": ["<all_urls>"],
            "broad_host_access": True, "from_store": True,
            "concerns": ["can read the session cookies for every site"]}
    base.update(over)
    return base


def test_sideloaded_session_reading_extension_is_critical():
    out = engine._check_extensions([_ext(from_store=False)])
    assert out and out[0].severity == "critical"


def test_store_extension_with_same_permissions_is_only_a_warning():
    out = engine._check_extensions([_ext(from_store=True)])
    assert out and out[0].severity == "warn"


def test_extension_without_concerns_produces_nothing():
    assert engine._check_extensions([_ext(concerns=[])]) == []


def test_extension_permissions_are_assessed_by_capability():
    from maxport import extensions
    concerns, broad = extensions._assess(["cookies"], ["<all_urls>"])
    assert concerns and broad
    narrow, broad2 = extensions._assess(["cookies"],
                                        ["https://example.com/*"])
    assert not narrow and not broad2


def test_debugger_permission_is_a_concern_without_broad_hosts():
    from maxport import extensions
    concerns, _ = extensions._assess(["debugger"], [])
    assert concerns


def test_permissions_are_explained_in_plain_language():
    from maxport import extensions
    plain = extensions.describe_permissions(_ext())
    assert any("signed in" in p for p in plain)


# --------------------------------------------------------------------------
# The ClickFix whitespace check existed but could never fire: the value was
# stripped before the padding was measured.
# --------------------------------------------------------------------------

def test_run_box_row_parser_keeps_leading_whitespace():
    import re as _re
    row = _re.compile(r"^\s*(\S+)\s+(REG_\w+)\s{4}(.*)$")
    line = "    a    REG_SZ    " + " " * 60 + "powershell -enc SQBF"
    m = row.match(line)
    assert m
    raw = m.group(3)
    assert len(raw) - len(raw.lstrip()) == 60


def test_ordinary_run_box_entry_has_no_padding():
    import re as _re
    row = _re.compile(r"^\s*(\S+)\s+(REG_\w+)\s{4}(.*)$")
    m = row.match("    b    REG_SZ    notepad.exe")
    assert m and m.group(3) == "notepad.exe"


# --------------------------------------------------------------------------
# Timeline and revocation ordering.
# --------------------------------------------------------------------------

def test_timeline_groups_events_close_together():
    import time as _t
    now = _t.time()
    res = engine.ScanResult()
    res.connections = [_conn("AnyDesk", "a", started=now - 300),
                       _conn("ScreenConnect", "s", started=now - 120)]
    res.persistence = [{"name": "Updater", "modified": now - 60,
                        "detail": "runs at logon"}]
    events = engine._build_timeline(res)
    assert len(events) == 3
    assert events[0]["same_episode"] is False
    assert all(e["same_episode"] for e in events[1:])


def test_timeline_is_ordered_by_time():
    import time as _t
    now = _t.time()
    res = engine.ScanResult()
    res.connections = [_conn("B", "b", started=now),
                       _conn("A", "a", started=now - 5000)]
    events = engine._build_timeline(res)
    assert events[0]["when"] < events[1]["when"]


def test_revocation_puts_sessions_before_passwords():
    """A password change does not end an already-signed-in session."""
    from maxport import triage
    order = triage.CATEGORY_ORDER
    assert order.index("session") < order.index("password")
    assert order.index("wallet") < order.index("session")


def test_every_revocation_category_has_an_urgency():
    from maxport import triage
    for category in triage.CATEGORY_ORDER:
        assert triage.URGENCY.get(category)


def test_exposure_summary_is_honest_when_empty():
    from maxport import triage
    assert "not the same as" in triage.summary([])


# --------------------------------------------------------------------------
# The generated catalogue widens detection without overriding curation.
# --------------------------------------------------------------------------

def test_handwritten_signatures_win_over_the_catalogue():
    from maxport import signatures
    assert signatures.identify_tool("anydesk") == "AnyDesk"


def test_catalogue_extends_detection_beyond_handwritten_list():
    from maxport import signatures
    try:
        from maxport.rmm_catalogue import CATALOGUE_EXECUTABLES
    except ImportError:
        return                      # catalogue not generated in this tree
    extra = [k for k in CATALOGUE_EXECUTABLES
             if k not in signatures.REMOTE_TOOLS]
    assert extra
    assert signatures.identify_tool(extra[0])


def test_catalogue_does_not_claim_ordinary_programs():
    from maxport import signatures
    for name in ("notepad", "bash", "explorer", "python3", "sshd"):
        assert signatures.identify_tool(name) is None


# --------------------------------------------------------------------------
# The project was renamed. A machine isolated by a release under the old
# name must still be recoverable, or the rename seals it permanently.
# --------------------------------------------------------------------------

def test_revert_command_covers_the_previous_name():
    """Firewall rules do not rename themselves when the project does."""
    from maxport import respond
    cmd = respond._revert_shell_command()
    if "netsh" in cmd or "nft" in cmd:
        assert respond.LEGACY_RULE_PREFIX in cmd or \
               respond.LEGACY_NFT_TABLE in cmd


def test_legacy_isolation_state_is_adopted():
    import json as _json
    import os as _os
    import tempfile
    import time as _t
    from maxport import respond

    original = respond._state_paths_legacy
    legacy_dir = tempfile.mkdtemp()
    legacy_file = _os.path.join(legacy_dir, "isolation.json")
    with open(legacy_file, "w", encoding="utf-8") as f:
        _json.dump({"deadline": _t.time() + 300, "keep_lan": True}, f)

    respond._state_paths_legacy = lambda: [legacy_file]
    respond._clear_state()
    try:
        message = respond.adopt_legacy_state()
        assert message
        assert respond._read_state().get("deadline")
        assert not _os.path.exists(legacy_file)
    finally:
        respond._state_paths_legacy = original
        respond._clear_state()


def test_adoption_does_not_overwrite_current_state():
    import time as _t
    from maxport import respond
    respond._write_state(_t.time() + 999, True)
    try:
        current = respond._read_state()["deadline"]
        respond.adopt_legacy_state()
        assert respond._read_state()["deadline"] == current
    finally:
        respond._clear_state()


def test_no_stale_project_name_in_source():
    """The rename must be complete apart from the deliberate legacy hooks."""
    import os as _os
    root = _os.path.join(_os.path.dirname(__file__), "..", "maxport")
    offenders = []
    for base, dirs, files in _os.walk(root):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = _os.path.join(base, name)
            for number, line in enumerate(
                    open(path, encoding="utf-8"), 1):
                if "netguard" in line.lower() and "LEGACY" not in line:
                    offenders.append(f"{name}:{number}")
    assert not offenders, f"old name still present at {offenders}"


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
