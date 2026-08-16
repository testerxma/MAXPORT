"""Text mode — because the answer matters more than the interface.

The GUI library is large and its install can fail, and someone running this
usually wants an answer now. This mode needs only psutil and reports the same.
"""

from __future__ import annotations

import sys
import time

from . import engine, respond, triage
from .store import Store

BOLD, DIM, OFF = "\033[1m", "\033[2m", "\033[0m"
RED, YEL, GRN, CYN = "\033[31m", "\033[33m", "\033[32m", "\033[36m"

SEV_COLOR = {"critical": RED, "warn": YEL, "info": CYN}
SEV_TEXT = {"critical": "CRITICAL", "warn": "WARNING", "info": "NOTE"}


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{OFF}" if _supports_color() else text


def _rule(char: str = "─", width: int = 72) -> str:
    return char * width


def report(res, show_all: bool = False) -> str:
    """Builds the complete text report."""
    lines = []
    add = lines.append

    verdict_color = {"controlled": RED, "exposed": YEL}.get(res.verdict, GRN)
    add("")
    add(_rule("━"))
    add(_c(f"  {res.verdict_text}", verdict_color + BOLD))
    add(_c(f"  {len(res.connections)} connections · {len(res.listening)} listening"
           f" · {round(res.duration, 1)}s", DIM))
    add(_rule("━"))

    for w in res.warnings:
        add(_c(f"  ! {w}", YEL))
    if res.suppressed:
        add(_c(f"  ({res.suppressed} findings hidden by the known-good list)", DIM))
    if res.warnings or res.suppressed:
        add("")

    if not res.findings:
        add(_c("  Nothing found that warrants an alert.", GRN))
        add("")
        add(_c("  But a single scan sees only this moment. Control tools connect", DIM))
        add(_c("  for seconds every few minutes, so run continuous monitoring:", DIM))
        add(_c("      python maxport.py --watch", CYN))
        return "\n".join(lines)

    for i, f in enumerate(res.findings, 1):
        if f.severity == "info" and not show_all:
            continue
        color = SEV_COLOR.get(f.severity, "")
        add(_c(f"[{SEV_TEXT.get(f.severity, f.severity)}] {f.title}",
               color + BOLD))
        if f.detail:
            add(f"    {f.detail}")
        for k, v in f.evidence.items():
            if v and str(v) != "—":
                add(_c(f"    {k}: {v}", DIM))
        add("")

    hidden = sum(1 for f in res.findings if f.severity == "info")
    if hidden and not show_all:
        add(_c(f"  ({hidden} informational items hidden — add --all to show)", DIM))

    # The timeline is where a list of findings becomes a sequence of events.
    # Someone who cannot interpret "AnyDesk established" often recognises
    # "this all happened within four minutes, last Tuesday afternoon".
    episode = [e for e in (res.timeline or []) if e.get("same_episode")]
    if episode:
        add("")
        add(_rule("─"))
        add(_c("  What happened, in order", BOLD))
        add(_c("  Events close together are usually one action, not several.",
               DIM))
        add("")
        for e in res.timeline:
            when = time.strftime("%d %b %H:%M", time.localtime(e["when"]))
            gap = e.get("seconds_after_previous", 0)
            marker = "  └─" if e.get("same_episode") else "  ●"
            note = f"  (+{int(gap)}s)" if e.get("same_episode") else ""
            colour = SEV_COLOR.get(e.get("severity", ""), "")
            add(_c(f"{marker} {when}  {e['what']}{note}", colour))
            if e.get("detail"):
                add(_c(f"       {e['detail'][:100]}", DIM))

    if res.exposure:
        add("")
        add(_rule("─"))
        add(_c("  If something did run as you, revoke these", BOLD))
        add(_c("  " + triage.summary(res.exposure), DIM))
        add("")
        for item in res.exposure:
            add(_c(f"  [{item['category']}] {item['name']}", BOLD))
            add(_c(f"      when: {item['urgency']}", YEL))
            add(f"      {item['action']}")
        add("")
        add(_c("  Revoking sessions before changing passwords is the order "
               "that matters:", DIM))
        add(_c("  a password change does not sign out a session already "
               "signed in.", DIM))

    return "\n".join(lines)


def run(argv: list[str]) -> int:
    show_all = "--all" in argv
    watch = "--watch" in argv
    store = Store()

    # Isolation outlives the run that applied it; deal with any left behind
    # before doing anything else.
    leftover = respond.resume_or_revert()
    if leftover:
        print(_c("  " + leftover.message, YEL))

    if not respond.is_elevated():
        from . import elevate
        # In a terminal we can hand off to sudo in place, which is the clean
        # path. try_elevate execs sudo directly when stdin is a tty, so if it
        # returns at all here, elevation did not happen and we explain why.
        if "--no-elevate" not in argv:
            started, status = elevate.try_elevate()
            if started:
                return 0
        print(_c("\n  ! Running without full privileges — most connections "
                 "will show no program name.", YEL))
        print(_c("    " + elevate.instruction() + "\n", DIM))

    def progress(pct, text):
        if _supports_color():
            print(f"\r  {pct:3}%  {text}          ", end="", flush=True)

    res = engine.run_scan(deep=True, store=store, progress=progress,
                          vt_key=store.get_setting("vt_key"))
    if _supports_color():
        print("\r" + " " * 60 + "\r", end="")
    print(report(res, show_all=show_all))

    if not watch:
        return 0

    # A single scan is weak; the real value is in noticing what appears later
    from .monitor import Monitor
    print(_rule())
    print(_c("  Continuous monitoring — the first cycle builds the baseline.", BOLD))
    print(_c("  Leave it running. Ctrl+C to stop.", DIM))
    print(_rule())

    def on_event(ev):
        stamp = time.strftime("%H:%M:%S", time.localtime(ev.ts))
        color = SEV_COLOR.get(ev.severity, "")
        print(_c(f"  {stamp}  [{SEV_TEXT.get(ev.severity, '')}] {ev.title}",
                 color))
        if ev.detail:
            print(_c(f"            {ev.detail}", DIM))

    mon = Monitor(store, interval=60, on_event=on_event)
    mon.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mon.stop()
        print(_c("\n  Monitoring stopped.", DIM))
    return 0
