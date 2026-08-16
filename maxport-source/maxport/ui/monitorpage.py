"""Continuous monitoring page — a live log of what has changed.

A scan answers "right now". This page answers "since when, and what moved".
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from . import theme
from .widgets import DataTable, hint_label, section_label


class MonitorPage(QWidget):
    """Shows monitoring events and lets known behaviour be silenced."""

    approve_requested = Signal(str)      # behaviour key
    toggle_requested = Signal()

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 22)
        lay.setSpacing(10)

        lay.addWidget(section_label("Continuous monitoring"))
        lay.addWidget(hint_label(
            "A manual scan sees only this moment, while remote control tools "
            "connect briefly. Monitoring learns what is normal here first."))

        head = QHBoxLayout()
        self.toggle_btn = QPushButton("Start monitoring")
        self.toggle_btn.setObjectName("primary")
        self.toggle_btn.clicked.connect(self.toggle_requested.emit)
        head.addWidget(self.toggle_btn)

        self.state = QLabel("Stopped")
        self.state.setObjectName("hint")
        head.addWidget(self.state, 1)
        lay.addLayout(head)

        self.table = DataTable(
            ["Time", "Severity", "Type", "What happened", "Details"], stretch=3)
        lay.addWidget(self.table, 1)

        self.approve_btn = QPushButton("Mark as known — stop alerting me")
        self.approve_btn.setObjectName("ghost")
        self.approve_btn.clicked.connect(self._approve)
        lay.addWidget(self.approve_btn, 0, Qt.AlignRight)

        self._keys: list[str] = []
        self._events: list = []

    # ---------------- display ----------------

    def set_running(self, running: bool, ticks: int = 0, interval: int = 60) -> None:
        self.toggle_btn.setText("Stop monitoring" if running else "Start monitoring")
        self.toggle_btn.setObjectName("danger" if running else "primary")
        self.toggle_btn.style().unpolish(self.toggle_btn)
        self.toggle_btn.style().polish(self.toggle_btn)
        if running:
            self.state.setText(
                f"Running — scanning every {interval}s · {ticks} cycles so far")
        else:
            self.state.setText("Stopped")

    def add_event(self, ev) -> None:
        self._events.insert(0, ev)
        del self._events[200:]
        self.reload()

    def load(self, events: list) -> None:
        self._events = list(events)
        self.reload()

    @staticmethod
    def _field(ev, name: str, default=""):
        """Events arrive as objects from the monitor and rows from the store."""
        if isinstance(ev, dict):
            return ev.get(name, default)
        return getattr(ev, name, default)

    def reload(self) -> None:
        rows, colors, self._keys = [], {}, []
        for i, ev in enumerate(self._events):
            ts = time.strftime("%H:%M:%S",
                               time.localtime(self._field(ev, "ts", 0) or 0))
            sev = self._field(ev, "severity", "info")
            kind = self._field(ev, "kind")
            title = self._field(ev, "title")
            detail = self._field(ev, "detail")
            key = self._field(ev, "key")
            rows.append([ts, theme.SEVERITY_LABEL.get(sev, sev), kind,
                         title, detail])
            self._keys.append(key)
            if sev in ("critical", "warn"):
                colors[i] = theme.SEVERITY[sev]
        self.table.fill(rows, colors)
        self.approve_btn.setEnabled(bool(self._keys))

    def _approve(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._keys) and self._keys[row]:
            self.approve_requested.emit(self._keys[row])
