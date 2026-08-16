"""Continuous monitoring.

A button-press scan answers a weak question: "is someone controlling this
machine at this exact instant?" Remote-control tools connect for a few
seconds every several minutes, so the odds your click coincides with a
session are low. Monitoring reframes it usefully: "has anything new
appeared since yesterday?"

The principle is learn-then-alert. The first cycle records a baseline and
stays silent, because otherwise every single thing on the machine would be
reported as "new" at once and the user would learn to ignore the tool.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from . import collectors, signatures
from .store import Store

CRITICAL, WARN, INFO = "critical", "warn", "info"


@dataclass
class Event:
    ts: float = 0.0
    severity: str = INFO
    kind: str = ""
    title: str = ""
    detail: str = ""
    key: str = ""
    ip: str = ""
    port: int = 0
    pid: int = 0
    evidence: dict = field(default_factory=dict)


def conn_key(c) -> str:
    """A stable key identifying "this behaviour" across time.

    Keyed on program name plus peer rather than PID, because the PID changes
    on every launch and the same program would look new each time.
    """
    if c.raddr:
        return f"{c.proc.name}|{c.raddr}:{c.rport}"
    return f"{c.proc.name}|LISTEN:{c.lport}"


class Monitor:
    """Background thread that scans periodically, reporting only what is new."""

    def __init__(self, store: Store, interval: int = 60, on_event=None,
                 learn_first: bool = True):
        self.store = store
        self.interval = max(15, interval)
        self.on_event = on_event
        self.learn_first = learn_first
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.ticks = 0
        self.last_run = 0.0
        self.events: list[Event] = []

    # ---------------- lifecycle ----------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="maxport-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive()
                    and not self._stop.is_set())

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:  # monitoring must never die silently
                self._emit(Event(ts=time.time(), severity=INFO,
                                 kind="Monitoring",
                                 title="Scan cycle failed",
                                 detail=str(e)[:200]))
            # interruptible wait so stop() takes effect immediately
            self._stop.wait(self.interval)

    # ---------------- scanning ----------------

    def tick(self) -> list[Event]:
        """One cycle: collect, compare against baseline, report what is new."""
        # deep=False because signature verification is slow and unsuitable for
        # a once-a-minute loop; we go deep only on connections found to be new.
        conns, _ = collectors.collect_connections(deep=False)
        first_run = self.ticks == 0 and self.learn_first
        new: list[Event] = []

        for c in conns:
            key = conn_key(c)
            if self.store.is_approved(key):
                continue
            if not self.store.is_new(key, min_age_hours=0):
                continue          # seen before, not new
            ev = self._classify(c, key)
            if ev:
                new.append(ev)

        # Record after comparing. Recording first would mark everything
        # "known" before we ever had the chance to examine it.
        self.store.record(conns)
        self.ticks += 1
        self.last_run = time.time()

        if first_run:
            self._emit(Event(ts=time.time(), severity=INFO,
                             kind="Monitoring", title="Monitoring started",
                             detail=f"Baseline saved: {len(conns)} connections. "
                                    "Only deviations will be reported."))
            return []

        for ev in new:
            self.store.log_event(ev)
            self._emit(ev)
        return new

    def _classify(self, c, key: str) -> Event | None:
        """Decide whether a new connection deserves an alert, and how loud."""
        now = time.time()
        proc = c.proc

        if c.tunnel:
            return Event(
                ts=now, severity=CRITICAL, kind="Tunnel", key=key,
                pid=proc.pid, ip=c.raddr, port=c.rport,
                title=f"{c.tunnel} started running",
                detail=("A tunnel makes the machine dial outward, passing "
                        "through the firewall and router without opening any "
                        "port. The visible address belongs to the tunnel "
                        "provider, not to whoever is in control."),
                evidence={"Path": proc.exe, "Command": proc.cmdline[:200],
                          "Launched by": proc.ancestry or "—"})

        if c.tool:
            live = c.status == "ESTABLISHED" and c.raddr
            return Event(
                ts=now, severity=CRITICAL if live else WARN,
                kind="Remote control", key=key, pid=proc.pid,
                ip=c.raddr, port=c.rport,
                title=(f"{c.tool} opened a session just now" if live
                       else f"{c.tool} started running"),
                detail=(f"Live session with {c.raddr}:{c.rport}" if live
                        else "Running and waiting for a session"),
                evidence={"Path": proc.exe,
                          "Launched by": proc.ancestry or "—"})

        if c.status == "LISTEN":
            desc = signatures.describe_port(c.lport)
            exposed = c.laddr in ("0.0.0.0", "::", "")
            if desc:
                note, conf = desc
                return Event(
                    ts=now,
                    severity=CRITICAL if (conf == "admin" and exposed) else WARN,
                    kind="New port", key=key, pid=proc.pid, port=c.lport,
                    title=f"Port {c.lport} opened — {note}",
                    detail=("Reachable from any network" if exposed
                            else "Bound to localhost only"),
                    evidence={"Program": proc.name, "Path": proc.exe,
                              "Launched by": proc.ancestry or "—"})
            if exposed:
                return Event(
                    ts=now, severity=WARN, kind="New port", key=key,
                    pid=proc.pid, port=c.lport,
                    title=f"{proc.name} opened port {c.lport} to the network",
                    detail="A listening port that was not in the baseline.",
                    evidence={"Path": proc.exe,
                              "Launched by": proc.ancestry or "—"})
            return None

        if c.status == "ESTABLISHED" and c.raddr:
            hint = collectors.path_looks_suspicious(proc.exe)
            parent = collectors.parent_is_suspicious(proc)
            if hint or parent:
                return Event(
                    ts=now, severity=WARN, kind="New connection", key=key,
                    pid=proc.pid, ip=c.raddr, port=c.rport,
                    title=f"{proc.name} opened an outbound connection",
                    detail=(f"Launched by {parent}, which is not what you would "
                            "expect to start a network program."
                            if parent else
                            f"Running from a temporary path ({hint})."),
                    evidence={"Destination": f"{c.raddr}:{c.rport}",
                              "Path": proc.exe,
                              "Launched by": proc.ancestry or "—"})
        return None

    def _emit(self, ev: Event) -> None:
        self.events.append(ev)
        del self.events[:-500]
        if self.on_event:
            try:
                self.on_event(ev)
            except Exception:
                pass
