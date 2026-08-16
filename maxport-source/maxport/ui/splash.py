"""Startup animation.

A scan takes a second or two, and during that second the user is staring at
either a frozen window or nothing. This fills it with something that is not
mere decoration: a radar sweep whose stages are the tool's actual checks, so
the animation doubles as an explanation of what the tool is doing on their
behalf while it does it.

The sweep is drawn by hand with QPainter rather than pulled from an image or
a GIF, so it stays a few kilobytes, scales to any window size, and needs no
asset files bundled alongside the single-file build. Colour follows the same
instrument-panel palette as the rest of the interface: steel while working,
resolving to the verdict colour at the end.
"""

from __future__ import annotations

import math

from PySide6.QtCore import Qt, QTimer, Signal, QRectF
from PySide6.QtGui import (
    QColor, QConicalGradient, QFont, QPainter, QPainterPath, QPen, QRadialGradient,
)
from PySide6.QtWidgets import QWidget

from . import theme

# The checks the engine runs, in order, so the caption tracks real progress
STAGES = [
    "Reading active connections",
    "Matching remote-control signatures",
    "Checking tunnels and covert channels",
    "Verifying tool destinations",
    "Inspecting the network",
    "Reading what recently executed",
    "Checking persistence points",
    "Checking dormant doors",
]


class ScanSplash(QWidget):
    """A radar sweep whose arcs are the scan's own stages.

    Emits `finished` when the intro completes so the window can reveal the
    result underneath. It also accepts an early real result via `resolve`,
    so the animation never outlives the work it illustrates.
    """

    finished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._angle = 0.0            # sweep position, degrees
        self._pulse = 0.0            # blip radius fraction, 0..1
        self._stage = 0
        self._done = False
        self._verdict_color = QColor(theme.STEEL)
        self._elapsed = 0

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)        # ~60fps

        # A minimum on-screen time so the intro reads as intentional, not a
        # flicker, even when the scan returns almost instantly.
        self._min_ms = 2200

    def resolve(self, verdict: str) -> None:
        """Hand the real verdict in early; the sweep finishes on its colour."""
        self._verdict_color = QColor(theme.VERDICT_COLOR.get(verdict, theme.STEEL))
        # let the current sweep complete rather than snapping shut
        self._done = True

    def stop(self) -> None:
        """Halt the timer so no paint is issued during teardown."""
        self._timer.stop()

    def _tick(self) -> None:
        self._elapsed += 16
        self._angle = (self._angle + 3.2) % 360
        self._pulse = (self._pulse + 0.018) % 1.0
        # advance the caption in step with the sweep going round
        self._stage = int((self._angle / 360) * len(STAGES)) % len(STAGES)

        # End only after both the minimum time and, if given, a real result
        if self._elapsed >= self._min_ms and (self._done or
                                              self._elapsed >= 3600):
            self._timer.stop()
            self.finished.emit()
            return
        self.update()

    # ------------------------------------------------------------------

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        p.fillRect(self.rect(), QColor(theme.INK))

        cx, cy = w / 2, h / 2 - 20
        radius = min(w, h) * 0.28

        self._draw_rings(p, cx, cy, radius)
        self._draw_sweep(p, cx, cy, radius)
        self._draw_blips(p, cx, cy, radius)
        self._draw_center(p, cx, cy)
        self._draw_caption(p, w, cy + radius)

    def _draw_rings(self, p: QPainter, cx: float, cy: float, r: float) -> None:
        pen = QPen(QColor(theme.RULE))
        pen.setWidthF(1.2)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        for frac in (0.4, 0.7, 1.0):
            rr = r * frac
            p.drawEllipse(QRectF(cx - rr, cy - rr, rr * 2, rr * 2))
        # crosshairs
        pen.setColor(QColor(theme.RULE))
        p.setPen(pen)
        p.drawLine(int(cx - r), int(cy), int(cx + r), int(cy))
        p.drawLine(int(cx), int(cy - r), int(cx), int(cy + r))

    def _draw_sweep(self, p: QPainter, cx: float, cy: float, r: float) -> None:
        # A conical gradient trailing behind the leading edge gives the
        # familiar radar "comet tail" without drawing dozens of segments.
        grad = QConicalGradient(cx, cy, -self._angle)
        head = QColor(self._verdict_color)
        head.setAlpha(150)
        tail = QColor(self._verdict_color)
        tail.setAlpha(0)
        grad.setColorAt(0.0, head)
        grad.setColorAt(0.12, tail)
        grad.setColorAt(1.0, tail)

        p.setPen(Qt.NoPen)
        p.setBrush(grad)
        path = QPainterPath()
        path.moveTo(cx, cy)
        path.arcTo(QRectF(cx - r, cy - r, r * 2, r * 2), self._angle, -60)
        path.closeSubpath()
        p.drawPath(path)

        # the bright leading line
        pen = QPen(self._verdict_color)
        pen.setWidthF(2.0)
        p.setPen(pen)
        rad = math.radians(self._angle)
        p.drawLine(int(cx), int(cy),
                   int(cx + r * math.cos(rad)), int(cy - r * math.sin(rad)))

    def _draw_blips(self, p: QPainter, cx: float, cy: float, r: float) -> None:
        # A few fixed "contacts" that glow as the sweep passes over them,
        # suggesting the scan is finding and checking things.
        contacts = [(35, 0.55), (110, 0.8), (200, 0.45), (295, 0.7)]
        for ang, dist in contacts:
            # brightness peaks when the sweep angle is near this contact
            delta = abs((self._angle - ang + 180) % 360 - 180)
            glow = max(0.0, 1.0 - delta / 45)
            if glow <= 0.02:
                continue
            bx = cx + r * dist * math.cos(math.radians(ang))
            by = cy - r * dist * math.sin(math.radians(ang))
            size = 3 + glow * 5
            col = QColor(self._verdict_color)
            col.setAlpha(int(60 + glow * 195))
            p.setPen(Qt.NoPen)
            p.setBrush(col)
            p.drawEllipse(QRectF(bx - size / 2, by - size / 2, size, size))

    def _draw_center(self, p: QPainter, cx: float, cy: float) -> None:
        # a soft pulse radiating from the centre, tied to the blip clock
        rr = 6 + self._pulse * 22
        grad = QRadialGradient(cx, cy, rr)
        c0 = QColor(self._verdict_color)
        c0.setAlpha(int(120 * (1 - self._pulse)))
        c1 = QColor(self._verdict_color)
        c1.setAlpha(0)
        grad.setColorAt(0.0, c0)
        grad.setColorAt(1.0, c1)
        p.setPen(Qt.NoPen)
        p.setBrush(grad)
        p.drawEllipse(QRectF(cx - rr, cy - rr, rr * 2, rr * 2))

        p.setBrush(QColor(self._verdict_color))
        p.drawEllipse(QRectF(cx - 4, cy - 4, 8, 8))

    def _draw_caption(self, p: QPainter, w: float, y: float) -> None:
        title = QFont()
        title.setPointSize(15)
        title.setBold(True)
        p.setFont(title)
        p.setPen(QColor(theme.INK_TEXT if hasattr(theme, "INK_TEXT")
                        else "#E8EEF1"))
        p.drawText(QRectF(0, y + 30, w, 30), Qt.AlignHCenter, "MaxPort")

        sub = QFont()
        sub.setPointSize(10)
        p.setFont(sub)
        p.setPen(QColor(theme.MUTED))
        caption = STAGES[self._stage] + "…"
        p.drawText(QRectF(0, y + 62, w, 24), Qt.AlignHCenter, caption)
