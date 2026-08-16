"""Main window.

Layout: the verdict bar is pinned to the top at all times, a navigation
rail sits on the left, and the content fills the centre.
"""

from __future__ import annotations

import os
import sys
import time
import webbrowser

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QScrollArea, QStackedWidget,
    QVBoxLayout, QWidget,
)

from .. import collectors, engine, intel, respond
from ..monitor import Monitor
from ..store import Store
from . import theme
from .mcppage import McpPage
from .monitorpage import MonitorPage
from .widgets import DataTable, FindingCard, VerdictBar, hint_label, section_label


# ------------------------- background workers -------------------------

class ScanWorker(QThread):
    progress = Signal(int, str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, store: Store, deep: bool = True, vt_key: str = ""):
        super().__init__()
        self.store, self.deep, self.vt_key = store, deep, vt_key

    def run(self):
        try:
            res = engine.run_scan(
                deep=self.deep, store=self.store, vt_key=self.vt_key,
                progress=lambda p, t: self.progress.emit(p, t))
            self.done.emit(res)
        except Exception as e:
            self.failed.emit(str(e))


class PeerWorker(QThread):
    done = Signal(object)

    def __init__(self, ip: str, abuse_key: str = ""):
        super().__init__()
        self.ip, self.abuse_key = ip, abuse_key

    def run(self):
        self.done.emit(intel.profile_peer(self.ip, online=True,
                                          abuse_key=self.abuse_key))


# ------------------------- pages -------------------------

class OverviewPage(QScrollArea):
    action = Signal(str, object)

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.body = QWidget()
        self.lay = QVBoxLayout(self.body)
        self.lay.setContentsMargins(24, 20, 24, 20)
        self.lay.setSpacing(12)
        self.lay.addStretch(1)
        self.setWidget(self.body)
        self.placeholder = hint_label(
            "No scan yet. The first one takes longer because it verifies the "
            "signature of every executable — results are cached afterwards.")
        self.lay.insertWidget(0, self.placeholder)

    def show_findings(self, findings):
        while self.lay.count() > 1:
            item = self.lay.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)      # stops the widget drawing until deletion
                w.deleteLater()

        if not findings:
            lbl = hint_label(
                "Nothing worth alerting on. No control session, no exposed "
                "admin port, no suspicious persistence point.\n\n"
                "Scan regularly — many control tools connect for seconds every "
                "few minutes, and the History tab is what reveals them.")
            self.lay.insertWidget(0, lbl)
            return

        for f in findings:
            card = FindingCard(f)
            card.action.connect(self.action.emit)
            self.lay.insertWidget(self.lay.count() - 1, card)


class ConnectionsPage(QWidget):
    profile_requested = Signal(str)

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)

        lay.addWidget(section_label("Live connections"))
        lay.addWidget(hint_label(
            "Every live connection between this machine and another party, tied to the program responsible."))

        self.table = DataTable(
            ["Program", "PID", "Other party", "Port", "State",
             "Trust", "Path"], stretch=6)
        self.table.itemSelectionChanged.connect(self._selected)
        lay.addWidget(self.table, 1)

        bar = QHBoxLayout()
        self.info = QLabel("")
        self.info.setObjectName("mono")
        bar.addWidget(self.info, 1)

        self.btn = QPushButton("Who is this?")
        self.btn.setObjectName("ghost")
        self.btn.setEnabled(False)
        self.btn.clicked.connect(self._ask)
        bar.addWidget(self.btn)
        lay.addLayout(bar)

        self._ips: list[str] = []

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        self.btn.setEnabled(bool(rows))
        if rows:
            self.info.setText(self._ips[rows[0].row()])

    def _ask(self):
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.profile_requested.emit(self._ips[rows[0].row()])

    def load(self, conns):
        live = collectors.established(conns)
        live.sort(key=lambda c: (c.tool is None, c.proc.name))
        rows, colors, self._ips = [], {}, []
        trust_label = {"trusted": "trusted", "untrusted": "untrusted",
                       "unknown": "unknown"}
        for i, c in enumerate(live):
            name = f"{c.proc.name}  ⟨{c.tool}⟩" if c.tool else c.proc.name
            rows.append([name, c.proc.pid, c.raddr, c.rport, c.status,
                         trust_label.get(c.proc.trust, "—"), c.proc.exe or "—"])
            self._ips.append(c.raddr)
            if c.tool:
                colors[i] = theme.ALARM
            elif c.proc.trust == "untrusted":
                colors[i] = theme.AMBER
        self.table.fill(rows, colors)


class PortsPage(QWidget):
    close_requested = Signal(int, str, int)   # port, proto, pid

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)

        lay.addWidget(section_label("Listening ports"))
        lay.addWidget(hint_label(
            "Every port here is an open door. One bound to 0.0.0.0 is reachable "
            "from any network; one bound to 127.0.0.1 is internal and unreachable from outside."))

        self.table = DataTable(
            ["Port", "Protocol", "Bound to", "Scope", "Program",
             "PID", "Note"], stretch=6)
        self.table.itemSelectionChanged.connect(self._selected)
        lay.addWidget(self.table, 1)

        bar = QHBoxLayout()
        bar.addStretch(1)
        self.btn = QPushButton("Close selected port")
        self.btn.setObjectName("danger")
        self.btn.setEnabled(False)
        self.btn.clicked.connect(self._close)
        bar.addWidget(self.btn)
        lay.addLayout(bar)

        self._rows: list[tuple[int, str, int]] = []

    def _selected(self):
        self.btn.setEnabled(bool(self.table.selectionModel().selectedRows()))

    def _close(self):
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.close_requested.emit(*self._rows[rows[0].row()])

    def load(self, listening):
        from ..signatures import describe_port
        listening = sorted(listening, key=lambda c: c.lport)
        rows, colors, self._rows = [], {}, []
        for i, c in enumerate(listening):
            desc = describe_port(c.lport)
            note = desc[0] if desc else ""
            public = c.laddr in ("0.0.0.0", "::", "")
            rows.append([c.lport, c.family.upper(), c.laddr or "*",
                         "all networks" if public else "local only",
                         c.proc.name, c.proc.pid, note or "—"])
            self._rows.append((c.lport, c.family, c.proc.pid))
            if desc and desc[1] == "admin" and public:
                colors[i] = theme.ALARM
            elif desc:
                colors[i] = theme.AMBER
        self.table.fill(rows, colors)


class NetworkPage(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        body = QWidget()
        self.lay = QVBoxLayout(body)
        self.lay.setContentsMargins(24, 20, 24, 20)
        self.lay.setSpacing(12)
        self.setWidget(body)

        self.lay.addWidget(section_label("Devices on your local network"))
        self.lay.addWidget(hint_label(
            "This is the only place a MAC address is available — hardware "
            "addresses do not cross a router, so they cannot be obtained for anyone on the internet."))
        self.arp = DataTable(["Address", "MAC", "Vendor", "Interface"], stretch=2)
        self.arp.setMinimumHeight(180)
        self.lay.addWidget(self.arp)

        self.lay.addWidget(section_label("Network adapters"))
        self.ifaces = DataTable(["Adapter", "State", "MAC", "Addresses"], stretch=3)
        self.ifaces.setMinimumHeight(150)
        self.lay.addWidget(self.ifaces)

        self.lay.addWidget(section_label("DNS servers and hosts file"))
        self.dns = QLabel("")
        self.dns.setObjectName("evidence")
        self.dns.setWordWrap(True)
        self.dns.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lay.addWidget(self.dns)
        self.lay.addStretch(1)

    def load(self, res):
        self.arp.fill([[e["ip"], e["mac"], e.get("vendor") or "—",
                        e.get("iface") or "—"] for e in res.arp])
        self.ifaces.fill([[i["name"], "up" if i["up"] else "down",
                           i["mac"] or "—", ", ".join(i["ips"]) or "—"]
                          for i in res.interfaces])
        lines = ["DNS servers: " + (", ".join(res.dns) or "—"), ""]
        if res.hosts:
            lines.append("hosts entries:")
            lines += [f"  {h['ip']}  {h['names']}" for h in res.hosts]
        else:
            lines.append("hosts file is clean")
        self.dns.setText("\n".join(lines))


class ExtensionsPage(QWidget):
    """What the browser add-ons are permitted to do.

    Sorted by capability rather than by name: an extension that can read
    every session belongs at the top whatever it calls itself, and the
    thing worth reading is the permission, not the label the author chose.
    """

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)
        lay.addWidget(section_label("Browser extensions"))
        lay.addWidget(hint_label(
            "An extension that can read cookies on every site can sign in as "
            "you without your password and without your second factor, "
            "because the session was already authenticated. Most of these are "
            "harmless. The question for each is whether you installed it and "
            "whether it needs this much."))
        self.table = DataTable(
            ["Browser", "Extension", "It can", "From the store"], stretch=2)
        lay.addWidget(self.table, 1)

    def load(self, items):
        def weight(e):
            return (0 if (e.get("concerns") and not e.get("from_store", True))
                    else 1 if e.get("concerns") else 2)

        rows, colors = [], {}
        for i, e in enumerate(sorted(items, key=weight)):
            can = "; ".join(e.get("concerns") or []) or "nothing unusual"
            rows.append([e.get("browser", ""), e.get("name", "")[:60],
                         can[:110],
                         "yes" if e.get("from_store", True) else "NO"])
            if e.get("concerns"):
                colors[i] = (theme.ALARM if not e.get("from_store", True)
                             else theme.AMBER)
        self.table.fill(rows, colors)


class ExposurePage(QWidget):
    """What to revoke, in the order that limits the damage.

    Deliberately ordered by how quickly a loss becomes permanent rather than
    by how likely it is. Someone reading this is frightened and short of
    time, so the first line has to be the one that matters most, and the
    reason has to be on the same line as the instruction.
    """

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)
        lay.addWidget(section_label("If something ran as you"))
        self.summary = QLabel("Run a scan first.")
        self.summary.setWordWrap(True)
        self.summary.setStyleSheet(f"color:{theme.TEXT};")
        lay.addWidget(self.summary)
        lay.addWidget(hint_label(
            "Revoke sessions before changing passwords. A password change "
            "does not sign out a session that is already signed in, so an "
            "attacker holding a stolen cookie stays connected straight "
            "through the reset."))
        self.table = DataTable(["Priority", "What", "When", "What to do"],
                               stretch=3)
        lay.addWidget(self.table, 1)

    def load(self, items, summary_text=""):
        self.summary.setText(summary_text or "Nothing found to revoke.")
        rows, colors = [], {}
        for i, item in enumerate(items):
            rows.append([str(i + 1), item["name"], item["urgency"],
                         item["action"]])
            if item["category"] in ("wallet", "session"):
                colors[i] = theme.ALARM
            elif item["category"] in ("cloud", "ssh"):
                colors[i] = theme.AMBER
        self.table.fill(rows, colors)


class PersistencePage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)
        lay.addWidget(section_label("What runs automatically"))
        lay.addWidget(hint_label(
            "Cutting the connection is not enough. If the persistence point "
            "survives, the program returns after a reboot. Review this and remove what you do not recognise."))
        self.table = DataTable(["Type", "Name", "Value", "Source"], stretch=2)
        lay.addWidget(self.table, 1)

    def load(self, items):
        risk_color = {"critical": theme.ALARM, "warn": theme.AMBER}
        items = sorted(items, key=lambda i: {"critical": 0, "warn": 1}.get(
            i["risk"], 2))
        rows, colors = [], {}
        for i, it in enumerate(items):
            rows.append([it["kind"], it["name"], it["value"][:150] or "—",
                         it["source"]])
            if it["risk"] in risk_color:
                colors[i] = risk_color[it["risk"]]
        self.table.fill(rows, colors)


class HistoryPage(QWidget):
    def __init__(self, store: Store):
        super().__init__()
        self.store = store
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)

        lay.addWidget(section_label("Repeat peers over the last 24 hours"))
        lay.addWidget(hint_label(
            "Control tools often connect for seconds and drop. A point-in-time "
            "scan misses them; this table exposes the recurring pattern."))
        self.peers = DataTable(
            ["Address", "Times seen", "Last seen", "Programs"], stretch=3)
        lay.addWidget(self.peers, 1)

        lay.addWidget(section_label("Action log"))
        self.actions = DataTable(["Time", "Action", "Target", "Result"],
                                 stretch=3)
        self.actions.setMaximumHeight(220)
        lay.addWidget(self.actions)

    def refresh(self):
        self.peers.fill([
            [p["raddr"], p["n"],
             time.strftime("%H:%M:%S", time.localtime(p["last"])),
             (p["procs"] or "")[:80]]
            for p in self.store.top_peers()])
        self.actions.fill([
            [time.strftime("%m-%d %H:%M", time.localtime(a["ts"])),
             a["action"], a["target"],
             ("done" if a["ok"] else "failed") + " — " + (a["message"] or "")[:60]]
            for a in self.store.recent_actions(60)])


# ------------------------- the window -------------------------

class MainWindow(QMainWindow):
    _monitor_bridge = Signal(object)
    _mcp_bridge = Signal(object)

    NAV = [
        ("Verdict", "overview"),
        ("Connections", "connections"),
        ("Ports", "ports"),
        ("Network", "network"),
        ("Persistence", "persistence"),
        ("Extensions", "extensions"),
        ("What to revoke", "exposure"),
        ("Monitoring", "monitor"),
        ("History", "history"),
        ("Agent (MCP)", "mcp"),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MaxPort — who is controlling my machine?")
        self.resize(1180, 780)
        self.store = Store()
        self.result: engine.ScanResult | None = None
        self.worker: ScanWorker | None = None
        self.peer_worker: PeerWorker | None = None
        self._monitor_bridge.connect(self.on_monitor_event)

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.verdict = VerdictBar()
        outer.addWidget(self.verdict)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(2)
        self.progress.hide()
        outer.addWidget(self.progress)

        middle = QHBoxLayout()
        middle.setContentsMargins(0, 0, 0, 0)
        middle.setSpacing(0)

        self.stack = QStackedWidget()
        self.pages: dict[str, QWidget] = {}

        self.page_overview = OverviewPage()
        self.page_overview.action.connect(self.on_card_action)
        self.page_connections = ConnectionsPage()
        self.page_connections.profile_requested.connect(self.profile_ip)
        self.page_ports = PortsPage()
        self.page_ports.close_requested.connect(self.close_port)
        self.page_network = NetworkPage()
        self.page_persistence = PersistencePage()
        self.page_monitor = MonitorPage()
        self.page_monitor.toggle_requested.connect(self.toggle_monitor)
        self.page_monitor.approve_requested.connect(self.approve_key)
        self.page_history = HistoryPage(self.store)
        self.page_extensions = ExtensionsPage()
        self.page_exposure = ExposurePage()
        self.page_mcp = McpPage()
        self.page_mcp.start_requested.connect(self.start_mcp)
        self.page_mcp.stop_requested.connect(self.stop_mcp)
        self.page_mcp.actions_toggled.connect(self.set_mcp_actions)
        # The server runs off the interface thread, so its events arrive
        # through a queued signal rather than touching widgets directly.
        self._mcp_bridge.connect(self.page_mcp.append_event)
        self.mcp = None

        # The monitor runs on its own thread; events cross via a Qt signal
        # because touching the UI off the UI thread crashes the program.
        self.monitor = Monitor(self.store, interval=60,
                               on_event=self._monitor_bridge.emit)

        for w in (self.page_overview, self.page_connections, self.page_ports,
                  self.page_network, self.page_persistence, self.page_monitor,
                  self.page_history, self.page_extensions,
                  self.page_exposure, self.page_mcp):
            self.stack.addWidget(w)

        # Navigation rail goes on the left, so it is added first
        middle.addWidget(self._nav_rail())
        middle.addWidget(self.stack, 1)
        outer.addLayout(middle, 1)
        outer.addWidget(self._bottom_bar())

        self._check_privileges()

    def _nav_rail(self) -> QWidget:
        rail = QFrame()
        rail.setObjectName("navRail")
        rail.setFixedWidth(168)
        lay = QVBoxLayout(rail)
        lay.setContentsMargins(0, 14, 0, 14)
        lay.setSpacing(2)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for i, (label, _key) in enumerate(self.NAV):
            btn = QPushButton(label)
            btn.setObjectName("navItem")
            btn.setCheckable(True)
            btn.setChecked(i == 0)
            btn.clicked.connect(lambda _=False, idx=i: self.stack.setCurrentIndex(idx))
            self.nav_group.addButton(btn, i)
            lay.addWidget(btn)

        lay.addStretch(1)
        self.priv_label = QLabel("")
        self.priv_label.setObjectName("navCount")
        self.priv_label.setWordWrap(True)
        self.priv_label.setContentsMargins(16, 0, 16, 0)
        lay.addWidget(self.priv_label)
        return rail

    def _bottom_bar(self) -> QWidget:
        bar = QFrame()
        bar.setStyleSheet(
            f"background:{theme.PANEL};border-top:1px solid {theme.RULE};")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 12, 20, 12)
        lay.setSpacing(10)

        self.scan_btn = QPushButton("Scan now")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.start_scan)
        lay.addWidget(self.scan_btn)

        self.status = QLabel("")
        self.status.setObjectName("hint")
        lay.addWidget(self.status, 1)

        b = QPushButton("Export report")
        b.setObjectName("ghost")
        b.clicked.connect(self.export_report)
        lay.addWidget(b)

        self.isolate_btn = QPushButton("Isolate machine")
        self.isolate_btn.setObjectName("danger")
        self.isolate_btn.setToolTip(
            "Blocks all external connections at the firewall. Reversible.")
        self.isolate_btn.clicked.connect(self.toggle_isolate)
        self._isolated = False
        lay.addWidget(self.isolate_btn)
        return bar

    def _check_privileges(self):
        if respond.is_elevated():
            self.priv_label.setText("running with full privileges")
        else:
            self.priv_label.setText(
                "Limited privileges — some processes and actions will not "
                "appear. Run as administrator/root.")

    # ---------------- scanning ----------------

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        self.scan_btn.setEnabled(False)
        self.progress.setValue(0)
        self.progress.show()
        self._show_splash()
        self.worker = ScanWorker(self.store, deep=True,
                                 vt_key=self.store.get_setting("vt_key"))
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def _show_splash(self):
        """Overlay the radar animation across the whole window while scanning.

        It sits above the content as a child of the central widget and is
        resized to cover it, so no layout juggling is needed; when the sweep
        finishes it simply deletes itself and the result is already underneath.
        """
        from .splash import ScanSplash
        self._splash = ScanSplash(self.centralWidget())
        self._splash.setGeometry(self.centralWidget().rect())
        self._splash.finished.connect(self._hide_splash)
        self._splash.show()
        self._splash.raise_()

    def _hide_splash(self):
        if getattr(self, "_splash", None):
            self._splash.stop()
            self._splash.deleteLater()
            self._splash = None

    def resizeEvent(self, e):
        # keep the overlay covering the window if it is resized mid-scan
        if getattr(self, "_splash", None):
            self._splash.setGeometry(self.centralWidget().rect())
        super().resizeEvent(e)

    def on_progress(self, pct: int, text: str):
        self.progress.setValue(pct)
        self.status.setText(text)

    def on_failed(self, msg: str):
        self.progress.hide()
        self.scan_btn.setEnabled(True)
        self.status.setText("")
        QMessageBox.warning(self, "Scan could not complete", msg)

    def on_done(self, res):
        self.result = res
        self.progress.hide()
        self.scan_btn.setEnabled(True)
        # Hand the verdict to the animation so its sweep settles on the
        # result colour before revealing the page underneath.
        if getattr(self, "_splash", None):
            self._splash.resolve(res.verdict)
        self.verdict.show_result(res)
        self.page_overview.show_findings(res.findings)
        self.page_connections.load(res.connections)
        self.page_ports.load(res.listening)
        self.page_network.load(res)
        self.page_persistence.load(res.persistence + res.hardening)
        self.page_extensions.load(res.extensions)
        from ..triage import summary as exposure_summary
        self.page_exposure.load(res.exposure,
                                exposure_summary(res.exposure)
                                if res.exposure else "")
        self.page_history.refresh()

        counts = {s: len(res.by_severity(s)) for s in ("critical", "warn")}
        msg = (f"Last scan {time.strftime('%H:%M:%S')} · "
               f"{counts['critical']} critical · {counts['warn']} warnings")
        if res.warnings:
            msg += " · " + res.warnings[0]
        self.status.setText(msg)

    # ---------------- agent bridge ----------------

    def start_mcp(self):
        from ..mcpserver import McpServer
        if self.mcp is None:
            # Events arrive on the server's own threads. They are pushed
            # through a signal so the widgets are only ever touched from the
            # interface thread.
            self.mcp = McpServer(on_event=self._mcp_bridge.emit)
        ok, message = self.mcp.start()
        if ok:
            self.page_mcp.set_running(True, self.mcp.url,
                                      self.mcp.claude_code_command())
        else:
            self.page_mcp.note_error(message)
        self.status.setText(message)

    def stop_mcp(self):
        if self.mcp is None:
            return
        ok, message = self.mcp.stop()
        self.page_mcp.set_running(False)
        self.status.setText(message)

    def set_mcp_actions(self, allowed: bool):
        if self.mcp is not None:
            self.mcp.set_allow_actions(allowed)

    # ---------------- actions ----------------

    def on_card_action(self, kind: str, finding):
        if kind == "profile":
            self.profile_ip(finding.ip)
            return
        if kind == "stop":
            if not self._confirm(f"Stop process {finding.pid}?",
                                 "No file is deleted. You can start it again later."):
                return
            res = respond.stop_process(
                finding.pid, started=getattr(finding, "proc_started", 0.0),
                expect_name=getattr(finding, "proc_name", ""))
            self._after("stop process", str(finding.pid), res)
        elif kind == "suspend":
            res = respond.suspend_process(
                finding.pid, started=getattr(finding, "proc_started", 0.0),
                expect_name=getattr(finding, "proc_name", ""))
            self._after("freeze process", str(finding.pid), res)
        elif kind == "block":
            if not self._confirm(f"Block address {finding.ip}?",
                                 "A firewall block will be added, and can be lifted later."):
                return
            res = respond.block_ip(finding.ip)
            self._after("block address", finding.ip, res)
        elif kind == "close_port":
            self.close_port(finding.port, "tcp", finding.pid or 0,
                            getattr(finding, "proc_started", 0.0),
                            getattr(finding, "proc_name", ""))
        elif kind == "approve":
            self.approve_key(finding.key)

    def approve_key(self, key: str):
        if not key:
            return
        self.store.approve(key, "approved by user")
        self.status.setText(f"Will no longer alert on: {key}")
        if self.result:
            # Rebuild the view now rather than waiting for another scan
            self.result.findings = [f for f in self.result.findings
                                    if f.key != key]
            self.page_overview.show_findings(self.result.findings)

    def toggle_monitor(self):
        if self.monitor.running:
            self.monitor.stop()
            self.status.setText("Monitoring stopped")
        else:
            self.monitor.start()
            self.status.setText("Monitoring started — the first cycle builds the baseline")
        self.page_monitor.set_running(self.monitor.running,
                                      self.monitor.ticks, self.monitor.interval)

    def on_monitor_event(self, ev):
        """Arrives from the monitor thread via a signal, so it runs safely on the UI thread."""
        self.page_monitor.add_event(ev)
        self.page_monitor.set_running(self.monitor.running,
                                      self.monitor.ticks, self.monitor.interval)
        if ev.severity == "critical":
            # Critical findings do not wait for the user to open the page
            self.verdict.set_state("controlled", ev.title, ev.detail,
                                   "found by continuous monitoring")
            self.status.setText(f"⬤ {ev.title}")

    def close_port(self, port: int, proto: str, pid: int,
                   started: float = 0.0, expect_name: str = ""):
        if not self._confirm(
                f"Close port {port}/{proto}?",
                "The port will be blocked at the firewall. If it belongs to a "
                "service you use (such as RDP) you will lose remote access to this machine."):
            return
        res = respond.close_port(port, proto, pid or None,
                                 started=started, expect_name=expect_name)
        self._after("close port", f"{port}/{proto}", res)

    def toggle_isolate(self):
        target = not self._isolated
        if target and not self._confirm(
                "Isolate this machine from the network?",
                "All external connections stop immediately. This is reversible "
                "from the same button."):
            return
        res = respond.isolate(enable=target, auto_revert=600, keep_lan=True)
        if res.ok:
            self._isolated = target
            self.isolate_btn.setText("Lift isolation" if target else "Isolate machine")
            if target:
                self._offer_confirm_isolation()
        self._after("isolate" if target else "lift isolation", "machine", res)

    def _offer_confirm_isolation(self):
        """Offers to pin isolation before the timer reverts it.

        Isolation may be applied to a machine you reach remotely; if your
        connection drops and you cannot undo it, the timer reopens the
        """
        _, left = respond.isolate_status()
        keep = QMessageBox.question(
            self, "Pin isolation?",
            f"Isolation reverts automatically in {left // 60} minutes unless pinned.\n\n"
            "This is a safeguard: if you reach this machine remotely you have "
            "just cut your own access. If you are sitting at it, pin it.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if keep == QMessageBox.Yes:
            self._after("pin isolation", "machine", respond.confirm_isolation())

    def _confirm(self, title: str, body: str) -> bool:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(title)
        box.setInformativeText(body)
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        box.setDefaultButton(QMessageBox.Cancel)
        box.button(QMessageBox.Yes).setText("Proceed")
        box.button(QMessageBox.Cancel).setText("Cancel")
        return box.exec() == QMessageBox.Yes

    def _after(self, action: str, target: str, res):
        self.store.log_action(action, target, res.ok, res.message)
        self.status.setText(res.message)
        self.page_history.refresh()
        if not res.ok:
            QMessageBox.warning(self, "Action did not complete", res.message)
        else:
            self.start_scan()

    # ---------------- peer profile ----------------

    def profile_ip(self, ip: str):
        if not ip:
            return
        self.status.setText(f"Gathering what is available about {ip}…")
        self.peer_worker = PeerWorker(ip, os.environ.get("ABUSEIPDB_KEY", ""))
        self.peer_worker.done.connect(self.show_peer)
        self.peer_worker.start()

    def show_peer(self, p):
        rows = [("Address", p.ip), ("Scope", {
            "local": "your local network", "internet": "the internet",
            "loopback": "this machine itself"}.get(p.scope, "unknown"))]
        if p.scope == "local":
            rows += [("MAC", p.mac or "not in the ARP table"),
                     ("Vendor", p.vendor or "—")]
        else:
            rows += [("Reverse name", p.hostname or "—"),
                     ("Country", p.country or "—"),
                     ("City", ", ".join(x for x in (p.city, p.region) if x) or "—"),
                     ("Provider", p.isp or "—"),
                     ("Organisation", p.org or "—"),
                     ("Network number", p.asn or "—"),
                     ("VPN/proxy", "yes" if p.is_proxy else "no"),
                     ("Hosting/server", "yes" if p.is_hosting else "no"),
                     ("Abuse contact", p.abuse_email or "—")]
            if p.abuse_score >= 0:
                rows.append(("Abuse score", f"{p.abuse_score}/100 "
                                            f"({p.reports} reports)"))

        text = "\n".join(f"{k}: {v}" for k, v in rows)
        note = ("\n\nThe limits of this: it is network data, not a person's "
                "identity. A MAC address cannot be obtained for anyone outside "
                "your local network because it does not cross a router. And if "
                "they use a VPN or a compromised relay, this describes the relay.\n"
                "Correct use: attach this along with connection times to a "
                "report for the provider or the relevant authority."
                if p.scope == "internet" else "")

        box = QMessageBox(self)
        box.setWindowTitle(f"Other party — {p.ip}")
        box.setText(text + note)
        box.setStandardButtons(QMessageBox.Ok)
        box.exec()
        self.status.setText("")

    # ---------------- report ----------------

    def export_report(self):
        if not self.result:
            QMessageBox.information(self, "Nothing to export",
                                    "Run a scan first.")
            return
        res = self.result
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(os.path.expanduser("~"), f"maxport-{stamp}.html")

        cards = []
        for f in res.findings:
            color = theme.SEVERITY.get(f.severity, theme.STEEL)
            ev = "".join(f"<div><b>{k}</b>: {v}</div>"
                         for k, v in f.evidence.items() if v)
            cards.append(
                f'<div class="c" style="border-right:3px solid {color}">'
                f'<div class="t">{f.title}</div>'
                f'<div class="d">{f.detail}</div><div class="e">{ev}</div></div>')

        html = f"""<!doctype html><html dir="rtl" lang="ar"><meta charset="utf-8">
<title>MaxPort report</title><style>
body{{background:{theme.INK};color:{theme.TEXT};font-family:{theme.UI};
margin:0;padding:40px;line-height:1.7}}
h1{{color:{theme.VERDICT_COLOR.get(res.verdict, theme.STEEL)};font-size:26px;margin:0}}
.sub{{color:{theme.MUTED};font-size:14px;margin-bottom:28px}}
.c{{background:{theme.PANEL};padding:14px 18px;margin-bottom:10px;border-radius:4px}}
.t{{font-weight:600;margin-bottom:5px}}
.d{{color:{theme.MUTED};font-size:14px}}
.e{{font-family:{theme.MONO};font-size:12px;color:{theme.MUTED};margin-top:8px}}
</style>
<h1>{theme.VERDICT_HEAD.get(res.verdict, '')}</h1>
<div class="sub">{res.verdict_text}<br>
Scan time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(res.started))} ·
{len(res.connections)} connections · {len(res.listening)} listening</div>
{''.join(cards) or '<div class="c">No findings worth recording.</div>'}
</html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        self.status.setText(f"Report saved: {path}")
        webbrowser.open("file://" + path)

    def closeEvent(self, event):
        """Nothing this window started may outlive it.

        This is the single close handler. There were three, all on this
        class, so Python kept only the last and silently discarded the other
        two — which is why continuous monitoring and the startup animation
        went on running after the window was shut. Each shutdown step is
        isolated, so one failing does not strand the rest.
        """
        def attempt(what, fn):
            try:
                fn()
            except Exception:
                pass          # closing must not be blocked by a failure

        # The bridge first: a server still listening is the state the user
        # believes they just ended.
        if getattr(self, "mcp", None) is not None and self.mcp.running:
            attempt("mcp", self.mcp.stop)

        attempt("monitor", lambda: self.monitor.stop())

        if getattr(self, "_splash", None):
            attempt("splash", self._splash.stop)

        for w in (self.worker, self.peer_worker):
            if w and w.isRunning():
                attempt("worker", lambda w=w: w.wait(2000))

        attempt("store", self.store.close)
        super().closeEvent(event)


def main():
    # The GUI library is the most likely thing to fail on a machine someone
    # is trying to check right now, so text mode is a first-class path, not
    # a fallback nobody documented.
    if "--cli" in sys.argv or "--watch" in sys.argv:
        from ..cli import run
        return run(sys.argv)

    # Without privileges the scan is half-blind. Offer to relaunch elevated
    # before drawing anything, unless the user explicitly declined with
    # --no-elevate (useful when they know they cannot, and want the partial
    # scan anyway).
    from .. import elevate
    if "--no-elevate" not in sys.argv and not elevate.is_elevated():
        started, status = elevate.try_elevate()
        if started:
            # An elevated instance is taking over; this one steps aside.
            return 0

    app = QApplication([])
    app.setStyleSheet(theme.STYLESHEET)
    win = MainWindow()

    # Isolation from a previous run outlives that run's timer. If the program
    # was closed or crashed while the machine was sealed, nothing else will
    # ever lift it, so that is settled before anything else happens.
    leftover = respond.resume_or_revert()
    if leftover:
        win.status.setText(leftover.message)

    win.show()
    return app.exec()
