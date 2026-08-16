"""The page that hands this scanner to an agent, and takes it back.

A server the user starts and stops themselves, rather than one the agent
spawns on its own. That is deliberate: the moment an automated caller can
drive a root-privileged scanner, the question stops being "can it" and
becomes "does the person know". So this page is built around three things
the user must be able to see at a glance — whether it is on, what it is
allowed to do, and what it has been asked to do.

The call log is not decoration. An agent that scans is unremarkable; an
agent that scans, then blocks an address, then stops a process, is a
sequence the user should be able to watch happening rather than reconstruct
afterwards from a database.
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QApplication, QCheckBox, QFrame, QHBoxLayout,
                               QLabel, QPlainTextEdit, QPushButton,
                               QVBoxLayout, QWidget)

from .theme import AMBER, CLEAR, MUTED
from .widgets import hint_label, scroll_page, section_label


class McpPage(QWidget):
    """Start/stop the agent bridge, and watch what comes across it."""

    start_requested = Signal()
    stop_requested = Signal()
    actions_toggled = Signal(bool)

    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        page, lay = scroll_page()

        lay.addWidget(section_label("Agent access (MCP)"))
        lay.addWidget(hint_label(
            "Lets a coding agent such as Claude Code run scans and read the "
            "results. The server listens on this machine only, needs the "
            "token below, and stops when you close this program."))

        # ---- state and control ----
        row = QHBoxLayout()
        self.state = QLabel("Stopped")
        self.state.setObjectName("mcpState")
        self.state.setStyleSheet(f"color:{MUTED}; font-weight:600;")
        row.addWidget(self.state, 1)

        self.btn = QPushButton("Start server")
        self.btn.setObjectName("primary")
        self.btn.setCheckable(False)
        self.btn.clicked.connect(self._on_toggle)
        row.addWidget(self.btn)
        lay.addLayout(row)

        # ---- how to connect ----
        lay.addWidget(section_label("Connect Claude Code"))
        lay.addWidget(hint_label(
            "Run this once in your terminal while the server is on. The "
            "token changes every time the server starts, so an old command "
            "stops working."))

        self.command = QPlainTextEdit()
        self.command.setReadOnly(True)
        self.command.setFixedHeight(74)
        self.command.setPlaceholderText(
            "Start the server to generate a connection command.")
        lay.addWidget(self.command)

        copy_row = QHBoxLayout()
        self.copy_btn = QPushButton("Copy command")
        self.copy_btn.clicked.connect(self._copy)
        self.copy_btn.setEnabled(False)
        copy_row.addWidget(self.copy_btn)
        copy_row.addStretch(1)
        lay.addLayout(copy_row)

        # ---- the action gate ----
        lay.addWidget(section_label("What the agent may do"))
        lay.addWidget(hint_label(
            "Reading is always allowed: scanning, status and the capability "
            "report. Actions are separate and off by default, because an "
            "agent acting on a misread finding can stop a process this "
            "machine needs."))

        self.allow_actions = QCheckBox(
            "Allow the agent to block addresses and stop processes")
        self.allow_actions.toggled.connect(self._on_actions_toggled)
        lay.addWidget(self.allow_actions)

        note = QLabel(
            "Isolating the machine is never offered to an agent. Cutting the "
            "network removes the channel it would use to see the result, so "
            "it stays a decision you make at this window.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{MUTED}; font-size:12px;")
        lay.addWidget(note)

        # ---- live log ----
        lay.addWidget(section_label("What the agent has asked for"))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(180)
        self.log.setPlaceholderText("Nothing yet.")
        lay.addWidget(self.log, 1)

        lay.addStretch(0)
        outer.addWidget(page)
        self._running = False

    # ---------------- state ----------------

    def _on_toggle(self):
        if self._running:
            self.stop_requested.emit()
        else:
            self.start_requested.emit()

    def _on_actions_toggled(self, on: bool):
        self.actions_toggled.emit(bool(on))
        self.append_event({
            "ts": time.time(), "kind": "user",
            "name": "actions " + ("enabled" if on else "disabled"),
            "detail": "changed at this window"})

    def _copy(self):
        text = self.command.toPlainText().strip()
        if text:
            QApplication.clipboard().setText(text)
            self.copy_btn.setText("Copied")
            self.copy_btn.setEnabled(False)

    def set_running(self, running: bool, url: str = "", command: str = ""):
        self._running = running
        if running:
            self.state.setText(f"Listening on {url}")
            self.state.setStyleSheet(f"color:{CLEAR}; font-weight:600;")
            self.btn.setText("Stop server")
            self.command.setPlainText(command)
            self.copy_btn.setEnabled(True)
            self.copy_btn.setText("Copy command")
        else:
            self.state.setText("Stopped")
            self.state.setStyleSheet(f"color:{MUTED}; font-weight:600;")
            self.btn.setText("Start server")
            self.command.setPlainText("")
            self.copy_btn.setEnabled(False)
            # The token is dead once the server stops, so the checkbox must
            # not imply a permission that is still in force.
            self.allow_actions.blockSignals(True)
            self.allow_actions.setChecked(False)
            self.allow_actions.blockSignals(False)

    def append_event(self, entry: dict):
        stamp = time.strftime("%H:%M:%S", time.localtime(entry.get("ts", 0)))
        kind = entry.get("kind", "")
        name = entry.get("name", "")
        detail = (entry.get("detail") or "")[:120]
        mark = {"tool": "→", "refused": "✕", "server": "●",
                "session": "◇", "user": "☑"}.get(kind, "·")
        self.log.appendPlainText(f"{stamp}  {mark} {name}"
                                 + (f"   {detail}" if detail else ""))

    def note_error(self, message: str):
        self.state.setText(message)
        self.state.setStyleSheet(f"color:{AMBER}; font-weight:600;")
