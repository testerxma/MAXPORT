#!/usr/bin/env python3
"""Merges the maxport package into one portable file.

The split source stays the source of truth; this script generates the
single-file version from it, so two copies are never maintained by hand.
"""
import ast
import re
import pathlib

ORDER = [
    ("maxport/elevate.py", "Privilege elevation"),
    ("maxport/rmm_catalogue.py", "Generated RMM catalogue"),
    ("maxport/signatures.py", "Remote-control tool and port signatures"),
    ("maxport/netcheck.py", "Network inspection: ARP, DNS, hosts"),
    ("maxport/collectors.py", "Connection collection tied to processes"),
    ("maxport/intel.py", "Profiling the other party"),
    ("maxport/extensions.py", "Browser extensions"),
    ("maxport/rmmconfig.py", "Remote-access configuration"),
    ("maxport/triage.py", "Post-compromise revocation list"),
    ("maxport/persistence.py", "Persistence points"),
    ("maxport/exectrace.py", "Execution-trace forensics"),
    ("maxport/hardening.py", "Dormant doors and protection settings"),
    ("maxport/vulncheck.py", "Known-vulnerable remote-access versions"),
    ("maxport/lolbins.py", "Abused signed system binaries"),
    ("maxport/profiles.py", "Machine profiles"),
    ("maxport/store.py", "Historical record"),
    ("maxport/monitor.py", "Continuous monitoring"),
    ("maxport/respond.py", "Response actions"),
    ("maxport/engine.py", "Scan engine and verdict"),
    ("maxport/cli.py", "Text mode"),
    ("maxport/cmdline.py", "Terminal and agent interface"),
    ("maxport/mcpserver.py", "MCP server for agent access"),
    ("maxport/ui/theme.py", "Design system"),
    ("maxport/ui/widgets.py", "Interface components"),
    ("maxport/ui/monitorpage.py", "Monitoring page"),
    ("maxport/ui/mcppage.py", "Agent access page"),
    ("maxport/ui/splash.py", "Startup animation"),
    ("maxport/ui/app.py", "Main window"),
]

# Modules whose shell helper returns text, against respond which returns (code, text)
RC_MODULES = {"maxport/respond.py"}

HEADER = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MaxPort — remote-control detector for your own machine.

It answers one question: is anyone controlling this computer right now?
Then it gives you the evidence and the ability to cut the connection.

Running it (full privileges are needed to see every connection):
    Windows : open PowerShell as Administrator, then  python maxport.py
    Linux   : sudo -E python3 maxport.py

    --cli    text report only, needs just psutil
    --watch  keep monitoring after the scan
    --all    include informational findings

Requirements:
    pip install psutil PySide6-Essentials

An important technical limit: a MAC address does not cross a router. It can
only be obtained for a device inside your own network. For an address on the
internet you can learn the provider, approximate location and reputation
only, which is enough for a formal report and does not identify a person.

Generated from the split package by build_single.py — do not edit directly.
"""
from __future__ import annotations

import ctypes
import glob
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import secrets
import socket
import sqlite3
import argparse
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass, field, asdict

import psutil

# Text mode must not need a GUI toolkit. The interface classes below are
# defined at import time, so Qt has to be importable for the file to load at
# all — but a machine someone is checking right now is exactly where PySide6
# is most likely to be missing, and --cli was documented as needing only
# psutil. Text mode is therefore dispatched before any of this is touched,
# and a missing toolkit degrades to a clear instruction instead of a
# traceback.
if any(a in sys.argv for a in ("--cli", "--watch")):
    _QT_MISSING = "text mode requested"
else:
    _QT_MISSING = ""

try:
    from PySide6.QtCore import Qt, QThread, QTimer, Signal, QRectF
    from PySide6.QtGui import (
        QColor, QConicalGradient, QFont, QPainter, QPainterPath, QPen,
        QRadialGradient,
    )
    from PySide6.QtWidgets import (
        QApplication, QButtonGroup, QCheckBox, QFrame, QHBoxLayout,
        QHeaderView, QLabel, QMainWindow, QMessageBox, QPlainTextEdit,
        QProgressBar, QPushButton, QScrollArea, QSizePolicy, QStackedWidget,
        QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    )
except ImportError as _qt_err:                       # pragma: no cover
    _QT_MISSING = _QT_MISSING or str(_qt_err)

if _QT_MISSING:
    # Stand-ins so the module-level class definitions still parse. Nothing
    # instantiates them in text mode; anything that tries says why.
    class _NoQt:
        def __init__(self, *a, **k):
            raise SystemExit(
                "The graphical interface needs PySide6:\\n"
                "    pip install PySide6-Essentials\\n"
                "Text mode works without it:  python maxport.py --cli")

        def __getattr__(self, name):
            raise AttributeError(name)

    class _NoQtMeta(type):
        def __getattr__(cls, name):
            return 0

    class _Stub(_NoQt, metaclass=_NoQtMeta):
        pass

    def Signal(*a, **k):        # noqa: N802 — mirrors the Qt name
        return None

    Qt = _NoQtMeta("Qt", (), {})
    QThread = QTimer = QRectF = _Stub
    QColor = QConicalGradient = QFont = QPainter = QPainterPath = _Stub
    QPen = QRadialGradient = _Stub
    QApplication = QButtonGroup = QCheckBox = QFrame = QHBoxLayout = _Stub
    QHeaderView = QLabel = QMainWindow = QMessageBox = QPlainTextEdit = _Stub
    QProgressBar = QPushButton = QScrollArea = QSizePolicy = _Stub
    QStackedWidget = QTableWidget = QTableWidgetItem = QVBoxLayout = _Stub
    QWidget = _Stub

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# Every qualified reference (theme.ALARM, collectors.uptime_of) points at this
# same file, so the moved code runs without rewriting its names.
#
# This resolves against globals() rather than sys.modules[__name__]. The
# module is only in sys.modules if whoever loaded it put it there, which
# import does but a manual importlib.util.spec_from_file_location does not —
# so the previous version raised KeyError the moment anyone tried to use the
# merged file as a library instead of running it.
class _SelfRef:
    __slots__ = ()

    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name) from None


_M = _SelfRef()
signatures = netcheck = collectors = intel = persistence = respond = _M
engine = theme = widgets = monitor = store = hardening = vulncheck = lolbins = profiles = elevate = cli = _M
exectrace = cmdline = mcpserver = _M
extensions = rmmconfig = triage = rmm_catalogue = _M


def _sh(cmd: list[str], timeout: int = 20) -> str:
    """Runs a command and returns its output as text. Never raises."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return r.stdout or ""
    except Exception:
        return ""


def _sh_rc(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    """Runs a command, returning (exit code, output) — for actions whose success matters."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return 127, "command not present on this system"
    except Exception as e:
        return 1, str(e)

'''

FOOTER = '''

if __name__ == "__main__":
    sys.exit(main())
'''

DROP_PREFIXES = (
    "from __future__", "import ", "from dataclasses", "from collections",
    "from PySide6", "from . ", "from .. ", "from .", "from ..",
)


def stdlib_imports_used() -> set[str]:
    """Every top-level stdlib module imported anywhere in the package.

    A new module can pull in a stdlib name the merged header does not list,
    which then vanishes at merge time and crashes only at runtime — exactly
    the kind of failure that is invisible until someone runs the feature. So
    we gather them all and check the header covers them before writing.
    """
    third_party = {"psutil", "PySide6"}
    used = set()
    for path, _ in ORDER:
        tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
        # only module-level imports matter: an import nested inside a function
        # is left untouched by the merge and runs normally, and is often
        # deliberately local (e.g. platform-specific modules like pwd)
        for node in tree.body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    root = a.name.split(".")[0]
                    if root not in third_party:
                        used.add(root)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    root = node.module.split(".")[0]
                    if root not in third_party:
                        used.add(root)
    return used


def verify_header_imports() -> list[str]:
    """Returns stdlib modules used by the package but missing from the header."""
    have = set(re.findall(r"^import (\w+)", HEADER, re.MULTILINE))
    have |= set(re.findall(r"^from (\w+)", HEADER, re.MULTILINE))
    return sorted(stdlib_imports_used() - have)


def strip_module(path: str) -> str:
    src = pathlib.Path(path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    lines = src.splitlines()
    drop = set()

    # Drop the module docstring (a section heading replaces it)
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)):
        for i in range(tree.body[0].lineno - 1, tree.body[0].end_lineno):
            drop.add(i)

    for node in tree.body:
        # Imports are hoisted or dropped (relative ones are meaningless once merged)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for i in range(node.lineno - 1, node.end_lineno):
                drop.add(i)        # platform constants are defined once in the header
        if isinstance(node, ast.Assign):
            tgt = node.targets[0]
            if isinstance(tgt, ast.Name) and tgt.id in ("IS_WINDOWS", "IS_LINUX"):
                for i in range(node.lineno - 1, node.end_lineno):
                    drop.add(i)
        # is_elevated lives in elevate.py; respond's copy is a shim, so it goes
        if (isinstance(node, ast.FunctionDef) and node.name == "is_elevated"
                and path == "maxport/respond.py"):
            start = min([d.lineno for d in node.decorator_list] or [node.lineno])
            for i in range(start - 1, node.end_lineno):
                drop.add(i)
                # duplicated shell helpers were replaced by _sh / _sh_rc
        if isinstance(node, ast.FunctionDef) and node.name == "_run":
            start = min([d.lineno for d in node.decorator_list] or [node.lineno])
            for i in range(start - 1, node.end_lineno):
                drop.add(i)

    kept = [l for i, l in enumerate(lines) if i not in drop]
    body = "\n".join(kept).strip("\n")

    # A relative import inside a function: after merging the name is global,
    # so we keep the indentation valid with a no-op instead of deleting the line.
    body = re.sub(
        r"^(\s*)from\s+\.+[\w.]*\s+import\s+.*$",
        lambda m: f"{m.group(1)}pass  # (relative import removed when merging)",
        body, flags=re.MULTILINE)

    repl = "_sh_rc" if path in RC_MODULES else "_sh"
    body = re.sub(r"\b_run\b", repl, body)
    return body


def top_level_names(src: str) -> set[str]:
    names = set()
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names


def main() -> int:
    parts, seen, clashes = [HEADER], {}, []
    for path, title in ORDER:
        body = strip_module(path)
        for n in top_level_names(body):
            if n in seen:
                clashes.append(f"{n}: {seen[n]} ↔ {path}")
            seen[n] = path
        bar = "─" * 62
        parts.append(f"\n# {bar}\n# {title}\n# {bar}\n\n{body}\n")
    parts.append(FOOTER)

    out = pathlib.Path("dist/maxport.py")
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(parts), encoding="utf-8")

    missing = verify_header_imports()
    if missing:
        print("!! header is missing stdlib imports these modules use:")
        for m in missing:
            print(f"    import {m}")
        return 1

    if clashes:
        print("!! name collision — must be resolved:")
        for c in clashes:
            print("   ", c)
        return 1

    ast.parse(out.read_text(encoding="utf-8"))
    n = len(out.read_text(encoding="utf-8").splitlines())
    print(f"Generated: {out} ({n} lines) — no name collisions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
