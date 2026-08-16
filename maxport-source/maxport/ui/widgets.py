"""Shared interface components."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QHeaderView, QLabel, QPushButton, QSizePolicy,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import theme


class VerdictBar(QFrame):
    """The tool's defining element: one line answering the question it exists for.

    Everything below it is evidence supporting that line.
    """

    def __init__(self):
        super().__init__()
        self.setObjectName("verdictBar")
        self.setFixedHeight(104)

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        self.stripe = QFrame()
        self.stripe.setObjectName("verdictStripe")
        self.stripe.setFixedWidth(4)
        row.addWidget(self.stripe)

        body = QVBoxLayout()
        body.setContentsMargins(22, 18, 22, 18)
        body.setSpacing(4)

        self.head = QLabel("Ready to scan")
        self.head.setObjectName("verdictHead")

        self.detail = QLabel("Press \u201cScan now\u201d to begin")
        self.detail.setObjectName("verdictBody")

        self.meta = QLabel("")
        self.meta.setObjectName("verdictMeta")

        body.addWidget(self.head)
        body.addWidget(self.detail)
        body.addWidget(self.meta)
        row.addLayout(body, 1)

        self.set_state("clear", "Ready to scan", "Press \u201cScan now\u201d to begin", "")

    def set_state(self, verdict: str, head: str, detail: str, meta: str):
        color = theme.VERDICT_COLOR.get(verdict, theme.STEEL)
        self.stripe.setStyleSheet(f"background:{color};")
        self.head.setStyleSheet(f"color:{color};")
        self.head.setText(head)
        self.detail.setText(detail)
        self.meta.setText(meta)

    def show_result(self, res):
        head = theme.VERDICT_HEAD.get(res.verdict, "Scan result")
        meta = (f"{len(res.connections)} connections · "
                f"{len(res.listening)} listening · "
                f"{res.duration:.1f}s")
        self.set_state(res.verdict, head, res.verdict_text, meta)


class FindingCard(QFrame):
    """A single finding: what was found, why it matters, what to do."""

    action = Signal(str, object)   # (action kind, finding)

    def __init__(self, finding):
        super().__init__()
        self.setObjectName("card")
        self.finding = finding
        color = theme.SEVERITY.get(finding.severity, theme.STEEL)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(10)

        tag = QLabel(theme.SEVERITY_LABEL.get(finding.severity, ""))
        tag.setObjectName("sevTag")
        tag.setStyleSheet(f"background:{color};color:{theme.INK};")
        head.addWidget(tag)

        title = QLabel(finding.title)
        title.setObjectName("cardTitle")
        title.setWordWrap(True)
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        head.addWidget(title, 1)

        cat = QLabel(finding.category)
        cat.setObjectName("hint")
        head.addWidget(cat)
        lay.addLayout(head)

        if finding.detail:
            d = QLabel(finding.detail)
            d.setObjectName("cardDetail")
            d.setWordWrap(True)
            lay.addWidget(d)

        if finding.evidence:
            ev = QLabel("\n".join(
                f"{k}: {v}" for k, v in finding.evidence.items() if v))
            ev.setObjectName("evidence")
            ev.setWordWrap(True)
            ev.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lay.addWidget(ev)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch(1)

        # Silencing is offered on every finding: a tool that shouts about what
        # the user installed themselves gets ignored when it matters.
        if getattr(finding, "key", ""):
            b = QPushButton("Mark as known")
            b.setObjectName("ghost")
            b.setToolTip("This finding will stop appearing — reversible from the monitoring page")
            b.clicked.connect(lambda: self.action.emit("approve", finding))
            buttons.addWidget(b)

        if finding.pid and finding.pid > 0:
            b = QPushButton("Freeze process")
            b.setObjectName("ghost")
            b.setToolTip("Halts it while preserving its memory for analysis")
            b.clicked.connect(lambda: self.action.emit("suspend", finding))
            buttons.addWidget(b)

            b = QPushButton("Stop process")
            b.setObjectName("danger")
            b.clicked.connect(lambda: self.action.emit("stop", finding))
            buttons.addWidget(b)

        if finding.ip:
            b = QPushButton("Who is this?")
            b.setObjectName("ghost")
            b.clicked.connect(lambda: self.action.emit("profile", finding))
            buttons.addWidget(b)

            b = QPushButton("Block address")
            b.setObjectName("danger")
            b.clicked.connect(lambda: self.action.emit("block", finding))
            buttons.addWidget(b)

        if finding.port and not finding.ip:
            b = QPushButton("Close port")
            b.setObjectName("danger")
            b.clicked.connect(lambda: self.action.emit("close_port", finding))
            buttons.addWidget(b)

        if buttons.count() > 1:
            lay.addLayout(buttons)


class DataTable(QTableWidget):
    """Data table — monospaced columns so addresses and ports line up."""

    def __init__(self, headers: list[str], stretch: int = 0):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setShowGrid(False)
        self.setWordWrap(False)
        h = self.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeToContents)
        h.setSectionResizeMode(stretch, QHeaderView.Stretch)
        h.setHighlightSections(False)
        self.verticalHeader().setDefaultSectionSize(30)

    def fill(self, rows: list[list], colors: dict[int, str] | None = None):
        """colors: row index -> text colour, for marking rows that matter."""
        colors = colors or {}
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                if r in colors:
                    from PySide6.QtGui import QColor
                    item.setForeground(QColor(colors[r]))
                self.setItem(r, c, item)


def section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("sectionTitle")
    return lbl


def hint_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("hint")
    lbl.setWordWrap(True)
    return lbl


def scroll_page() -> tuple[QWidget, QVBoxLayout]:
    page = QWidget()
    lay = QVBoxLayout(page)
    lay.setContentsMargins(24, 20, 24, 20)
    lay.setSpacing(14)
    return page, lay
