"""An MCP server, so an agent such as Claude Code can drive the scanner.

Toggled from the interface rather than spawned by the client, which decides
the transport: stdio servers are started *by* the agent, so a button could
not control one. This is Streamable HTTP on a single endpoint, which the
agent connects to by URL.

Written against the standard library alone. The portable single-file build
is the point of this project, and depending on the MCP SDK would end it —
the protocol is JSON-RPC 2.0 over HTTP, which http.server already handles.

Four things guard it, because this exposes a root-privileged scanner to an
automated caller:

**It listens on the loopback interface only.** Never 0.0.0.0. A scanner that
can stop processes should not be reachable from the network it is watching.

**Every request carries a token** generated when the server starts and shown
in the interface. Without it any local process could drive the tool.

**The Origin header is validated**, which the specification requires for
local servers: a page in the user's browser can otherwise POST to localhost
and reach the server through them.

**Actions are off by default and separately enabled.** Reading is open;
stopping a process or blocking an address needs a second switch in the
interface. Isolation is not exposed at all — cutting the network is the one
action whose consequences an agent cannot observe, because the observation
channel is what it just cut.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import cmdline, engine, respond
from .cmdline import VERSION
from .store import Store

# Versions we can speak. The client names one during initialize; anything we
# recognise is echoed back, anything else falls back to our newest.
SUPPORTED_PROTOCOLS = ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26")
PREFERRED_PROTOCOL = "2025-11-25"

SERVER_NAME = "maxport"
DEFAULT_PORT = 8787


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------

READ_TOOLS = [
    {
        "name": "maxport_scan",
        "title": "Scan this machine",
        "description": (
            "Scan for active remote-control sessions, tunnels, exposed "
            "ports, persistence and network interference. Returns a verdict "
            "plus every finding with its evidence. A 'clear' verdict means "
            "these checks found nothing, not that the machine is clean — "
            "check the 'complete' field, because a failed sub-check leaves a "
            "gap rather than a finding."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "fast": {
                    "type": "boolean",
                    "description": "Skip file hashing and reverse DNS. "
                                   "Faster, less thorough.",
                    "default": False,
                },
                "include_inventories": {
                    "type": "boolean",
                    "description": "Include full connection, persistence and "
                                   "network lists as well as findings.",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "maxport_status",
        "title": "Current state",
        "description": ("Isolation state and any firewall rules this tool "
                        "added. Cheap; runs no scan."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "maxport_doctor",
        "title": "Capability report",
        "description": (
            "What this machine actually lets the tool do, and why not "
            "otherwise. Worth calling before trusting a clean scan: it "
            "distinguishes 'looked and found nothing' from 'could not look'."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "maxport_exposure",
        "title": "What to revoke after a compromise",
        "description": (
            "Inventories the credentials, sessions, keys and wallet files "
            "present on this machine and returns them ordered by how quickly "
            "the loss becomes irreversible. Use this after a scan finds "
            "something. Note the ordering: revoking sessions comes before "
            "changing passwords, because a stolen session cookie stays valid "
            "through a password reset."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "maxport_history",
        "title": "Recent events and actions",
        "description": ("What continuous monitoring recorded, and every "
                        "action taken through this tool."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 50,
                          "description": "Maximum records to return."},
            },
        },
    },
]

ACTION_TOOLS = [
    {
        "name": "maxport_block_ip",
        "title": "Block an address",
        "description": ("Blocks an address at the firewall in both "
                        "directions. Reversible with maxport_unblock_ip. "
                        "Lasts until reboot."),
        "inputSchema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "maxport_unblock_ip",
        "title": "Remove a block",
        "description": "Removes a firewall block this tool added.",
        "inputSchema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "maxport_stop_process",
        "title": "Stop a process",
        "description": (
            "Terminates a process. Pass process_name and started_at from the "
            "finding so identity is verified first — a PID from an earlier "
            "scan may belong to something else by now, and the call is "
            "refused if it does."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
                "process_name": {
                    "type": "string",
                    "description": "Expected name, from the finding.",
                },
                "started_at": {
                    "type": "number",
                    "description": "Expected start time, from the finding.",
                },
                "force": {"type": "boolean", "default": False},
            },
            "required": ["pid"],
        },
    },
]


def _ok(payload) -> dict:
    """A tool result. Text content holding JSON, which every client renders."""
    return {
        "content": [{"type": "text",
                     "text": json.dumps(payload, ensure_ascii=False,
                                        indent=2, default=str)}],
        "isError": False,
    }


def _err(message: str) -> dict:
    """A failed tool call.

    Reported through isError rather than a JSON-RPC error so the agent
    receives it as a result it can reason about and correct, which is what
    the specification intends for tool-level failures.
    """
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------

class McpServer:
    """Owns the HTTP server, the token, and the record of what was called."""

    def __init__(self, port: int = DEFAULT_PORT, on_event=None):
        self.port = port
        self.token = secrets.token_urlsafe(24)
        self.allow_actions = False
        self.on_event = on_event          # callback for the interface log
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._sessions: set[str] = set()
        self._lock = threading.Lock()
        self.calls: list[dict] = []

    # -- lifecycle --------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._httpd is not None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def claude_code_command(self) -> str:
        """The one line a user pastes to connect Claude Code to this server."""
        return (f"claude mcp add --transport http {SERVER_NAME} {self.url} "
                f"--header \"Authorization: Bearer {self.token}\"")

    def start(self) -> tuple[bool, str]:
        if self.running:
            return True, f"Already listening on {self.url}"
        server = self

        class Handler(_McpHandler):
            mcp = server

        class Server(ThreadingHTTPServer):
            # Without this, sockets left in TIME_WAIT keep the port claimed
            # after a stop, and the next Start fails with "address already in
            # use" — turning a toggle into something that only works once.
            allow_reuse_address = True
            daemon_threads = True

        try:
            # 127.0.0.1, never 0.0.0.0: a scanner that can stop processes
            # must not be reachable from the network it is watching.
            self._httpd = Server(("127.0.0.1", self.port), Handler)
        except OSError as e:
            self._httpd = None
            return False, (f"Could not listen on port {self.port}: {e}. "
                           "Another program may be using it.")

        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True,
            name="maxport-mcp")
        self._thread.start()
        self._log("server", "started", f"listening on {self.url}")
        return True, f"MCP server listening on {self.url}"

    def stop(self) -> tuple[bool, str]:
        if not self.running:
            return True, "Not running"
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception as e:
            return False, f"Could not stop cleanly: {e}"
        finally:
            self._httpd = None
            self._thread = None
            with self._lock:
                self._sessions.clear()
        self._log("server", "stopped", "no longer accepting connections")
        return True, "MCP server stopped"

    def set_allow_actions(self, allowed: bool) -> None:
        self.allow_actions = bool(allowed)
        self._log("server", "actions",
                  "enabled" if allowed else "disabled")

    # -- record -----------------------------------------------------------

    def _log(self, kind: str, name: str, detail: str = "") -> None:
        """Everything the agent does is recorded and shown, not just done."""
        entry = {"ts": time.time(), "kind": kind, "name": name,
                 "detail": detail}
        with self._lock:
            self.calls.append(entry)
            del self.calls[:-500]
        if self.on_event:
            try:
                self.on_event(entry)
            except Exception:
                pass

    # -- protocol ---------------------------------------------------------

    def tools(self) -> list[dict]:
        return READ_TOOLS + (ACTION_TOOLS if self.allow_actions else [])

    def handle(self, message: dict) -> dict | None:
        """One JSON-RPC message in, one response out. None for notifications."""
        method = message.get("method", "")
        mid = message.get("id")
        params = message.get("params") or {}

        if mid is None:                 # a notification expects no reply
            return None

        try:
            if method == "initialize":
                asked = params.get("protocolVersion", "")
                version = (asked if asked in SUPPORTED_PROTOCOLS
                           else PREFERRED_PROTOCOL)
                client = (params.get("clientInfo") or {}).get("name", "unknown")
                self._log("session", "initialize", f"client: {client}")
                return self._result(mid, {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": SERVER_NAME,
                                   "version": cmdline.VERSION,
                                   "title": "MaxPort"},
                    "instructions": (
                        "Scan this machine for remote control and exposure. "
                        "Call maxport_doctor first if a clean result is "
                        "going to be relied on: it reports which checks "
                        "cannot run here. Response actions appear only when "
                        "the user has enabled them in the MaxPort window."
                    ),
                })

            if method == "ping":
                return self._result(mid, {})

            if method == "tools/list":
                return self._result(mid, {"tools": self.tools()})

            if method == "tools/call":
                name = params.get("name", "")
                args = params.get("arguments") or {}
                return self._result(mid, self.call_tool(name, args))

            return self._error(mid, -32601, f"Unknown method: {method}")

        except Exception as e:
            return self._error(mid, -32603,
                               f"{type(e).__name__}: {str(e)[:200]}")

    @staticmethod
    def _result(mid, result) -> dict:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _error(mid, code, message) -> dict:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": code, "message": message}}

    # -- tools ------------------------------------------------------------

    def call_tool(self, name: str, args: dict) -> dict:
        known = {t["name"] for t in self.tools()}
        if name not in known:
            if name in {t["name"] for t in ACTION_TOOLS}:
                self._log("refused", name, "actions are disabled")
                return _err(
                    "Response actions are switched off. The user enables "
                    "them in the MaxPort window; they are off by default "
                    "because acting on a misread finding can stop a process "
                    "this machine needs.")
            return _err(f"Unknown tool: {name}")

        self._log("tool", name, json.dumps(args, default=str)[:200])

        if name == "maxport_scan":
            res = engine.run_scan(deep=not args.get("fast", False))
            return _ok(cmdline.result_to_dict(
                res, full=bool(args.get("include_inventories"))))

        if name == "maxport_status":
            isolated, left = respond.isolate_status()
            return _ok({"isolation": {"active": isolated,
                                      "seconds_until_revert": left},
                        "firewall_rules": respond.list_our_rules(),
                        "actions_enabled": self.allow_actions})

        if name == "maxport_doctor":
            caps = cmdline.capabilities()
            return _ok({"capabilities": caps,
                        "degraded": any(not c["available"] for c in caps)})

        if name == "maxport_exposure":
            from . import triage
            items = triage.build_checklist()
            return _ok({"summary": triage.summary(items),
                        "order": triage.CATEGORY_ORDER,
                        "items": items})

        if name == "maxport_history":
            limit = int(args.get("limit", 50))
            store = Store()
            try:
                return _ok({"events": store.recent_events(limit),
                            "actions": store.recent_actions(limit)})
            finally:
                store.close()

        # ---- actions ----

        if name == "maxport_block_ip":
            res = respond.block_ip(str(args.get("ip", "")))
            return _ok({"ok": res.ok, "message": res.message})

        if name == "maxport_unblock_ip":
            res = respond.unblock_ip(str(args.get("ip", "")))
            return _ok({"ok": res.ok, "message": res.message})

        if name == "maxport_stop_process":
            res = respond.stop_process(
                int(args.get("pid", 0)),
                force=bool(args.get("force")),
                started=float(args.get("started_at", 0.0) or 0.0),
                expect_name=str(args.get("process_name", "")))
            return _ok({"ok": res.ok, "message": res.message})

        return _err(f"Tool {name} is listed but not implemented")

    # -- auth -------------------------------------------------------------

    def authorised(self, headers) -> bool:
        supplied = (headers.get("Authorization") or "").strip()
        if supplied.lower().startswith("bearer "):
            supplied = supplied[7:].strip()
        # Constant-time, so a caller cannot learn the token byte by byte.
        return secrets.compare_digest(supplied, self.token)

    @staticmethod
    def origin_allowed(headers) -> bool:
        """Rejects cross-origin callers, as the specification requires.

        Without this, a page open in the user's browser can POST to a
        loopback server and reach it with the user's own machine as the
        vehicle. An absent Origin is fine: command-line clients send none.
        """
        origin = headers.get("Origin")
        if not origin:
            return True
        return any(origin.startswith(p) for p in
                   ("http://127.0.0.1", "http://localhost",
                    "https://127.0.0.1", "https://localhost"))


class _McpHandler(BaseHTTPRequestHandler):
    """Streamable HTTP: a single endpoint taking POST, with GET for streams."""

    mcp: McpServer = None            # set by McpServer.start
    protocol_version = "HTTP/1.1"
    # Built from the constant rather than a cross-module attribute: this is
    # evaluated while the class body runs, which in the merged single-file
    # build happens before the module aliases are usable.
    server_version = "MaxPort/" + VERSION

    def log_message(self, fmt, *a):
        pass                          # the interface shows calls; stderr stays quiet

    # -- helpers --

    def _send(self, code: int, body: dict | None, extra: dict | None = None):
        raw = b"" if body is None else json.dumps(
            body, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        if raw:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if raw:
            self.wfile.write(raw)

    def _guard(self) -> bool:
        if not self.mcp.origin_allowed(self.headers):
            self._send(403, {"error": "origin not allowed"})
            return False
        if not self.mcp.authorised(self.headers):
            self._send(401, {"error": "missing or invalid bearer token"},
                       {"WWW-Authenticate": "Bearer"})
            return False
        return True

    # -- verbs --

    def do_POST(self):
        if self.path.rstrip("/") not in ("/mcp", ""):
            self._send(404, {"error": "not found"})
            return
        if not self._guard():
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            self._send(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700,
                                       "message": f"Parse error: {e}"}})
            return

        # A batch is a list; a single message is an object.
        messages = payload if isinstance(payload, list) else [payload]
        responses = [r for r in (self.mcp.handle(m) for m in messages)
                     if r is not None]

        headers = {}
        if any(m.get("method") == "initialize" for m in messages):
            # 2025-11-25 pins the client to a session. The 2026-07-28 draft
            # drops it, so the id is issued but never required — which keeps
            # both generations of client working.
            session = secrets.token_urlsafe(16)
            self.mcp._sessions.add(session)
            headers["Mcp-Session-Id"] = session

        if not responses:
            self._send(202, None, headers)      # notifications only
            return
        self._send(200, responses[0] if len(responses) == 1 else responses,
                   headers)

    def do_GET(self):
        """The optional server-to-client stream. We have nothing to push."""
        if self.path.rstrip("/") not in ("/mcp", ""):
            self._send(404, {"error": "not found"})
            return
        if not self._guard():
            return
        self._send(405, {"error": "this server does not open server-initiated "
                                  "streams; use POST"})

    def do_DELETE(self):
        """Ends a session, per the specification."""
        if not self._guard():
            return
        session = self.headers.get("Mcp-Session-Id")
        if session:
            self.mcp._sessions.discard(session)
        self._send(204, None)
