#!/usr/bin/env python3
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
                "The graphical interface needs PySide6:\n"
                "    pip install PySide6-Essentials\n"
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



# ──────────────────────────────────────────────────────────────
# Privilege elevation
# ──────────────────────────────────────────────────────────────

def is_elevated() -> bool:
    """True if already running as administrator (Windows) or root (Unix)."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _script_and_args() -> tuple[str, list[str]]:
    """The command needed to re-run whatever is currently executing.

    A single merged maxport.py runs as a script; an installed package runs
    as `python -m maxport`. We reconstruct the right invocation for each so
    the relaunch lands in the same place the user started.
    """
    args = sys.argv[1:]
    main = os.path.abspath(sys.argv[0])
    if main.endswith(".py") and os.path.exists(main):
        return sys.executable, [main] + args
    # launched as a module or frozen build
    return sys.executable, ["-m", "maxport"] + args


def relaunch_as_admin_windows() -> bool:
    """Triggers a UAC prompt and relaunches elevated. True if a prompt shown.

    ShellExecuteW with the "runas" verb is the only sanctioned way to raise
    an existing process to administrator on Windows; there is no in-place
    escalation. On success a new elevated process starts and the caller
    should exit so two windows do not linger.
    """
    try:
        import ctypes
        exe, params = _script_and_args()
        # ShellExecuteW takes the program and its arguments as one string each
        arg_str = " ".join(f'"{p}"' if " " in p else p for p in params)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, arg_str, None, 1)
        # Values above 32 mean the shell accepted the request
        return int(rc) > 32
    except Exception:
        return False


def _linux_gui_present() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def relaunch_as_root_linux() -> tuple[bool, str]:
    """Relaunches as root by the best available mechanism.

    Order matters. pkexec shows a graphical password dialog and is right when
    a desktop is present, which on Kali it usually is. Falling back to sudo
    suits a terminal session. We pass -E / preserve-env so the tool still
    finds the real user's home and display after the switch, otherwise it
    would audit root's files and fail to draw its own window.
    """
    exe, args = _script_and_args()

    if _linux_gui_present() and shutil.which("pkexec"):
        # pkexec drops environment aggressively; hand back what the GUI needs
        env_pass = []
        for var in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"):
            if os.environ.get(var):
                env_pass.append(f"{var}={os.environ[var]}")
        cmd = ["pkexec", "env"] + env_pass + [exe] + args
        try:
            subprocess.Popen(cmd)
            return True, "pkexec"
        except Exception:
            pass

    if shutil.which("sudo"):
        # -E preserves the environment; only useful from an interactive shell
        if sys.stdin and sys.stdin.isatty():
            try:
                os.execvp("sudo", ["sudo", "-E", exe] + args)
            except Exception:
                pass
        return False, "sudo-needs-terminal"

    return False, "no-mechanism"


def try_elevate() -> tuple[bool, str]:
    """Attempts to relaunch with privileges. Returns (a relaunch is underway,
    human-readable status).

    A True result means the caller should exit and let the elevated instance
    take over. A False result carries a reason the caller can turn into a
    precise instruction for the user.
    """
    if is_elevated():
        return False, "already-elevated"

    if IS_WINDOWS:
        if relaunch_as_admin_windows():
            return True, "uac-prompt-shown"
        return False, "uac-declined"

    return relaunch_as_root_linux()


def instruction() -> str:
    """The exact command to run this tool with privileges on this platform."""
    if IS_WINDOWS:
        return ("Right-click PowerShell and choose \"Run as administrator\", "
                "then run:  python maxport.py")
    main = os.path.abspath(sys.argv[0])
    if main.endswith(".py") and os.path.exists(main):
        name = os.path.basename(main)
        extra = (" " + " ".join(sys.argv[1:])) if sys.argv[1:] else ""
        return f"Run with root, e.g.:  sudo -E python3 {name}{extra}"
    return "Run with root, e.g.:  sudo -E python3 -m maxport"


# ──────────────────────────────────────────────────────────────
# Generated RMM catalogue
# ──────────────────────────────────────────────────────────────

# 217 products
CATALOGUE_SIZE = 217

# process name -> product
CATALOGUE_EXECUTABLES = {
    "aa_v3": "Ammyy Admin",
    "action1_agent": "Action1",
    "action1_connector": "Action1",
    "action1_remote": "Action1",
    "action1_update": "Action1",
    "agent": "Monitic",
    "agent-installer-any": "HeartbeatRM",
    "agentinstaller.dll": "Freshservice",
    "agentmon": "Kaseya (VSA)",
    "alpemix": "Alpemix",
    "amon": "Monitic",
    "anydesk": "AnyDesk",
    "anyviewer": "AnyViewer",
    "appcore": "GoToMyPC",
    "aspia_client": "Aspia",
    "ateraagent": "Atera",
    "autoupdate": "Freshservice",
    "avcore": "AnyViewer",
    "bma": "baramundi Management Suite",
    "clboot32": "VIZOR",
    "cldist32": "VIZOR",
    "cldistsvc": "VIZOR",
    "clm": "Teramind",
    "clmeter32": "VIZOR",
    "clmetersvc": "VIZOR",
    "closeapp": "VIZOR",
    "cloudwksinstall": "Faronics Deep Freeze",
    "coreagentservice": "Faronics Core",
    "cpuchk": "VIZOR",
    "dashboard-windows-amd64": "Nezha",
    "dataplicity": "Dataplicity",
    "dephlp": "InvGate",
    "dfc": "Faronics Deep Freeze",
    "dfserv": "Faronics Deep Freeze",
    "dfservex": "Faronics Deep Freeze",
    "dfstd": "Faronics Deep Freeze",
    "dfstdinstall": "Faronics Deep Freeze",
    "dfwks": "Faronics Deep Freeze",
    "docconnect.agent": "TrustConnect",
    "duet": "Duet Display",
    "duetdisp": "Duet Display",
    "duetsetup": "Duet Display",
    "dwm": "Teramind",
    "faronicscoreagent": "Faronics Core",
    "faronicsdeployagent": "Faronics Deploy",
    "faronicssa": "Faronics Deploy",
    "fcaforstartupmonitor.msi": "Faronics Core",
    "fd_agent.dll": "FleetDeck.io",
    "fistudentagent": "Faronics Insight",
    "fistudentsvc": "Faronics Insight",
    "fistudentui": "Faronics Insight",
    "fleetdeck-agent": "FleetDeck.io",
    "fleetdeck-agent.msi": "FleetDeck.io",
    "fleetdeck_agent_svc": "FleetDeck.io",
    "fleetdeck_installer": "FleetDeck.io",
    "frcserver": "Faronics Deploy",
    "freshservice.discoveryprobe.autoflush": "Freshservice",
    "freshservice.discoveryprobe.oidlibrarypuller": "Freshservice",
    "freshservice.discoveryprobe.progressbar": "Freshservice",
    "freshservice.discoveryprobe.scanservice": "Freshservice",
    "freshservice.discoveryprobe.window": "Freshservice",
    "fsagentautoupdate": "Freshservice",
    "fsagentcrashstatusupdater": "Freshservice",
    "fsagentservice": "Freshservice",
    "fsprobecrashstatusupdater": "Freshservice",
    "fsprobereporter": "Freshservice",
    "fsscheduler": "Freshservice",
    "fssinstaller": "Faronics Deploy",
    "fswmiscanner": "Freshservice",
    "fwa_ui_agent": "Faronics Deploy",
    "fwaservice": "Faronics Deploy",
    "g2comm": "GoToMyPC",
    "g2fileh": "GoToMyPC",
    "g2host": "GoToMyPC",
    "g2m": "GoToMyPC",
    "g2m_download": "GoToMyPC",
    "g2mainh": "GoToMyPC",
    "g2mchat": "GoToMyPC",
    "g2mcodecinstextractor": "GoToMyPC",
    "g2mcomm": "GoToMyPC",
    "g2mcoreinstextractor": "GoToMyPC",
    "g2mfeedback": "GoToMyPC",
    "g2mhost.exee": "GoToMyPC",
    "g2minstaller": "GoToMyPC",
    "g2minstallerextractor": "GoToMyPC",
    "g2minsthigh": "GoToMyPC",
    "g2mlauncher": "GoToMyPC",
    "g2mmatchmaking": "GoToMyPC",
    "g2mmaterials": "GoToMyPC",
    "g2mpolling": "GoToMyPC",
    "g2mqanda": "GoToMyPC",
    "g2mrecorder": "GoToMyPC",
    "g2mscrutil64": "GoToMyPC",
    "g2msessioncontrol": "GoToMyPC",
    "g2mstart": "GoToMyPC",
    "g2mtesting": "GoToMyPC",
    "g2mtranscoder": "GoToMyPC",
    "g2mui": "GoToMyPC",
    "g2muninstall": "GoToMyPC",
    "g2mupload": "GoToMyPC",
    "g2mvideoconference": "GoToMyPC",
    "g2mview": "GoToMyPC",
    "g2printh": "GoToMyPC",
    "g2quick": "GoToMyPC",
    "g2svc": "GoToMyPC",
    "g2tray": "GoToMyPC",
    "getscreen": "GetScreen",
    "glpi-agent": "GLPI Agent",
    "glpi-esx": "GLPI Agent",
    "glpi-injector": "GLPI Agent",
    "glpi-inventory": "GLPI Agent",
    "glpi-netdiscovery": "GLPI Agent",
    "glpi-netinventory": "GLPI Agent",
    "glpi-remote": "GLPI Agent",
    "glpi-win32-service": "GLPI Agent",
    "gopcsrv": "GoToMyPC",
    "gorelo.rmm.setup": "Gorelo RMM",
    "goto": "GoToMyPC",
    "gotoscrutils": "GoToMyPC",
    "hbrm-updater-x64": "HeartbeatRM",
    "hbrm-x64": "HeartbeatRM",
    "helpwire": "HelpWire",
    "hoptodesk": "HopToDesk",
    "httpget": "VIZOR",
    "httppush": "VIZOR",
    "id_tray": "iDrive",
    "idcomponent.dll": "iDrive",
    "idriveeclassic": "iDrive",
    "idrivewinsetup": "iDrive",
    "immyagent": "ImmyBot",
    "immybot.agent.ephemeral": "ImmyBot",
    "immybot.msi": "ImmyBot",
    "immyupdater": "ImmyBot",
    "insightinstaller": "Faronics Insight",
    "insightinstallerstudent": "Faronics Insight",
    "insightinstallerteacher": "Faronics Insight",
    "installcore": "RemotePulse",
    "invgate-ed": "InvGate",
    "invgateassetsrd": "InvGate",
    "invgaterd": "InvGate",
    "iprangecalculator": "Freshservice",
    "kaupdhlp": "Kaseya (VSA)",
    "kausrtsk": "Kaseya (VSA)",
    "komari": "Komari",
    "komari-agent": "Komari",
    "level": "Level",
    "lmiguardiansvc": "LogMeIn",
    "lmiignition": "LogMeIn",
    "loclx": "LocalXpose",
    "logmein": "LogMeIn",
    "logmeinsystray": "LogMeIn",
    "luedit": "VIZOR",
    "luguard": "VIZOR",
    "lulogon": "VIZOR",
    "lunixar": "Lunixar",
    "lusmbios32": "VIZOR",
    "lutinfow32": "VIZOR",
    "manageengine_servicedesk_plus": "ManageEngine ServiceDesk Plus",
    "manageengine_servicedesk_plus.bin": "ManageEngine ServiceDesk Plus",
    "meshagent": "MeshCentral",
    "modulesupgrademgr": "Faronics Deploy",
    "moniticinstaller": "Monitic",
    "mousewithoutborders": "Mouse Without Borders",
    "mqmailintegration": "VIZOR",
    "mstsc": "mstsc.exe (Microsoft Remote Desktop Connection)",
    "netbird": "NetBird",
    "netbird-ui": "NetBird",
    "netbird_installer": "NetBird",
    "nezha-agent": "Nezha",
    "niniteone": "Ninite Pro (Ninite Agent)",
    "notificationhelper": "Faronics Deploy",
    "nuke32": "VIZOR",
    "nvda": "NVDA (Non-Visual Desktop Access)",
    "nvda_service": "NVDA (Non-Visual Desktop Access)",
    "parsecd": "Parsec",
    "pidupdater": "VIZOR",
    "pitunnel": "PiTunnel",
    "plink": "Freshservice",
    "prep64": "VIZOR",
    "radmin": "RAdmin",
    "rcclient": "AnyViewer",
    "rcservice": "AnyViewer",
    "recycler": "VIZOR",
    "regapps": "VIZOR",
    "remcmdstub": "NetSupport Manager",
    "remotedesktopmanager": "Devolutions Remote Desktop Manager",
    "remotely_agent": "Remotely",
    "remotely_desktop": "Remotely",
    "remsupp": "RemSupp",
    "remsupp_setup_x64": "RemSupp",
    "rodexagent": "Rodex RMM",
    "rserver3": "RAdmin",
    "screancap": "AnyViewer",
    "selfupdater": "VIZOR",
    "setup": "VIZOR",
    "shellhub-agent": "ShellHub",
    "si": "TiFLUX",
    "stahelper": "Faronics Insight",
    "statementview.msi": "Miradore",
    "studentsvc": "Faronics Insight",
    "supremosystem": "Supremo",
    "teamviewer": "TeamViewer",
    "teramind-remover": "Teramind",
    "teramind.remover.executable": "Teramind",
    "teramind.setup.remover": "Teramind",
    "teramind.setup.ui": "Teramind",
    "teramind.setup.uiarm": "Teramind",
    "teramind.setup.updater": "Teramind",
    "tiagent": "TiFLUX",
    "tiservice": "TiFLUX",
    "tiupdateservice": "TiFLUX",
    "tmagentsvc": "Teramind",
    "tmate": "tmate",
    "trustconnectagent": "TrustConnect",
    "trustconnectagent.dll": "TrustConnect",
    "uninstallstatusupdater": "Freshservice",
    "update-shim": "Teramind",
    "upload": "VIZOR",
    "vecwait": "VIZOR",
    "vnconfigutils": "VIZOR",
    "vnldriverinstaller": "VIZOR",
    "vnlselfupdate": "VIZOR",
    "wesvc": "Controlio",
    "winchk32": "VIZOR",
    "wintun.dll": "NetBird",
}

# product -> domains its own infrastructure uses
CATALOGUE_DOMAINS = {
    "247ithelp.com (ConnectWise)": ("247ithelp.com",),
    "Absolute (Computrace)": ("absolute.com", "namequery.com",),
    "Acronis Cyber Protect (Remotix)": ("acronis.com", "remotix.com",),
    "Action1": ("action1.com", "amazonaws.com",),
    "Addigy": ("addigy.com",),
    "Adobe Connect": ("adobeconnect.com",),
    "AeroAdmin": ("aeroadmin.com",),
    "AliWangWang-remote-control": ("taobao.com",),
    "Alpemix": ("alpemix.com", "teknopars.com",),
    "Ammyy Admin": ("ammyy.com",),
    "Any Support": ("anysupport.net",),
    "AnyDesk": ("anydesk.com",),
    "AnyViewer": ("anyviewer.com", "aomeisoftware.com",),
    "Anyplace Control": ("anyplace-control.com",),
    "Atera": ("atera.com", "getalphacontrol.com", "pubnubapi.com", "windows.net",),
    "Auvik": ("auvik.com",),
    "AweRay": ("aweray.com",),
    "Barracuda": ("barracudamsp.com", "islonline.net",),
    "Basecamp": ("basecamp.com",),
    "BeAnyWhere": ("beanywhere.com",),
    "BeInSync": ("beinsync.com", "beinsync.net",),
    "BeamYourScreen": ("beamyourscreen.com",),
    "BeyondTrust (Bomgar)": ("beyondtrustcloud.com", "bomgarcloud.com",),
    "Bluetrait": ("bluetrait.io",),
    "CentraStage (Now Datto)": ("centrastage.net", "datto.com",),
    "Centurion": ("centuriontech.com",),
    "Chrome Remote Desktop": ("google.com", "googleapis.com",),
    "Comodo RMM": ("comodo.com",),
    "ConnectWise Control": ("connectwise.com", "screenconnect.com",),
    "Connectwise Automate (LabTech)": ("hostedrmm.com",),
    "CrossLoop": ("crossloop.com", "softonic.com",),
    "DW Service": ("dwservice.net",),
    "DameWare": ("dameware.com",),
    "Dataplicity": ("dataplicity.com",),
    "DeskDay": ("deskday.ai",),
    "DesktopNow": ("nchuser.com",),
    "Distant Desktop": ("distantdesktop.com", "signalserver.xyz",),
    "Domotz": ("domotz.co", "domotz.com",),
    "Duet Display": ("duetdisplay.com", "itagent.com",),
    "EMCO Remote Console": ("emcosoftware.com",),
    "Electric AI (Kaseya)": ("electric.ai",),
    "Encapto": ("encapto.com",),
    "Ericom AccessNow": ("ericom.com",),
    "Ericom Connect": ("ericom.com",),
    "Faronics Core": ("faronics.com", "faronicslabs.com",),
    "Faronics Deep Freeze": ("deepfreeze.com", "faronics.com", "faronicscloud.com", "faronicslabs.com",),
    "Faronics Deploy": ("amazonaws.com", "faronics.com", "faronicscloud.com", "faronicsdeploy.com", "faronicslabs.com",),
    "Faronics Insight": ("faronics.com",),
    "FastViewer": ("fastviewer.com",),
    "FixMe.it": ("fixme.it", "set.me", "setme.net", "techinline.net",),
    "FleetDeck.io": ("fleetdeck.io", "zmazonaws.com",),
    "Fortra": ("fortra.com",),
    "Freshservice": ("fdcollab.com", "freshasset.com", "freshchat.com", "freshcloud.io", "freshconnect.io", "freshdev.io", "freshservice.com", "freshworks.com", "freshworksapi.com", "in-freshbots.ai", "myfreshworks.com", "rtschannel.com",),
    "GLPI Agent": ("github.com", "githubusercontent.com", "glpi-network.com", "glpi-project.org",),
    "GatherPlace-desktop sharing": ("gatherplace.com", "gatherplace.net",),
    "GetScreen": ("getscreen.me",),
    "GoToAssist": ("desktopstreaming.com", "fastsupport.com", "getgo.com", "goto.com", "gotoassist.at", "gotoassist.com", "gotoassist.me", "helpme.net",),
    "GoToMyPC": ("gotomypc.com",),
    "Gorelo RMM": ("azurewebsites.net", "gorelo.io", "gorelo.tech",),
    "GotoHTTP": ("gotohttp.com",),
    "Goverlan": ("goverlan.com",),
    "Guacamole": ("apache.org",),
    "HeartbeatRM": ("heartbeatrm.com",),
    "HelpBeam": ("informer.com",),
    "HelpU": ("co.kr",),
    "HelpWire": ("flexihub.com", "helpwire.app", "stunprotocol.org",),
    "HopToDesk": ("hoptodesk.com",),
    "I'm InTouch": ("01com.com",),
    "ISL Light": ("islonline.com",),
    "ISL Online": ("islonline.com", "islonline.net",),
    "ISL Online": ("islonline.com", "islonline.net",),
    "ITSupport247 (ConnectWise)": ("itsupport247.net",),
    "ITSupport247 (ConnectWise)": ("itsupport247.net",),
    "ImmyBot": ("immy.bot",),
    "Impero Connect": ("imperosoftware.com",),
    "Instant Housecall": ("instanthousecall.com", "instanthousecall.net",),
    "Instant Housecall": ("instanthousecall.com", "instanthousecall.net",),
    "IntelliAdmin Remote Control": ("intelliadmin.com",),
    "InvGate": ("invgate.com", "invgate.net",),
    "Iperius Remote": ("iperius-rs.com", "iperius.com", "iperiusremote.com",),
    "Itarian": ("comodo.com", "itarian.com",),
    "Ivanti Remote Control": ("ivanticloud.com",),
    "Jump Cloud": ("jumpcloud.com",),
    "Jump Desktop": ("jumpdesktop.com", "jumpto.me",),
    "KHelpDesk": ("com.br",),
    "Kabuto": ("kabuto.io",),
    "Kaseya (VSA)": ("kaseya.com", "kaseya.net",),
    "KickIdler": ("kickidler.com",),
    "Komari": ("ghcr.io", "github.com", "githubusercontent.com", "komari.wiki", "pages.dev",),
    "LANDesk": ("ivanti.com", "ivanticloud.com",),
    "LabTech RMM (Now ConnectWise Automate)": ("connectwise.com",),
    "Laplink Everywhere": ("laplink.com", "syspectr.com",),
    "Level": ("downloads.io", "level.io",),
    "Level.io": ("level.io",),
    "Level.io": ("level.io",),
    "LiteManager": ("litemanager.com", "litemanager.ru",),
    "LocalXpose": ("localxpose.io",),
    "LogMeIn": ("logmein-gateway.com", "logmein.com", "logmein.eu", "logmeininc.com", "logmeinrescue.com",),
    "LogMeIn rescue": ("logmein-gateway.com", "logmeinrescue.com", "logmeinrescue.eu",),
    "Lunixar": ("lunixar.com", "mymeetinggoogle.com",),
    "MSP360": ("cloudberrylab.com", "msp360.com", "mspbackups.com",),
    "Manage Engine (Desktop Central)": ("com.cn", "com.eu", "manageengine.cn", "manageengine.com", "zoho.com",),
    "ManageEngine ServiceDesk Plus": ("manageengine.com",),
    "MeshCentral": ("meshcentral.com",),
    "Microsoft Quick Assist": ("microsoft.com",),
    "Mikogo": ("mikogo.com", "mikogo4.com", "real-time-collaboration.com",),
    "Miradore": ("miradore.com", "windows.net",),
    "Monitic": ("monitic.com",),
    "MyGreenPC": ("mygreenpc.com",),
    "MyIVO": ("informer.com",),
    "N-ABLE Remote Access Software": ("n-able.com",),
    "N-Able Advanced Monitoring Agent": ("beanywhere.com", "cloudbackup.management", "cloudflare.net", "co.uk", "eu.com", "logicnow.com", "n-able.com", "remote.management", "swi-tc.com", "system-monitor.com", "systemmonitor.us",),
    "N-Able Advanced Monitoring Agent": ("beanywhere.com", "cloudbackup.management", "cloudflare.net", "co.uk", "eu.com", "logicnow.com", "n-able.com", "remote.management", "swi-tc.com", "system-monitor.com", "systemmonitor.us",),
    "NTR Remote": ("ntrsupport.com",),
    "NVDA (Non-Visual Desktop Access)": ("nvaccess.org",),
    "Naverisk": ("naverisk.com",),
    "NetBird": ("firebaseapp.com", "my-sharepoint-inc.com", "my1cloudlive.com", "my2cloudlive.com", "netbird.io", "web-16fe.app", "web.app",),
    "NetSupport Manager": ("netsupportmanager.com", "netsupportsoftware.com",),
    "Netop Remote Control (Impero Connect)": ("backdrop.cloud", "netop.com",),
    "Netreo": ("netreo.com", "netreo.net",),
    "Neturo": ("co.kr",),
    "Netviewer (GoToMeet)": ("netviewer.com",),
    "Nezha": ("bj2.xyz", "github.com", "github.io", "githubusercontent.com", "mid.al", "nezha.wiki", "pages.dev",),
    "Ninite Pro (Ninite Agent)": ("ninite.com",),
    "NinjaRMM": ("com.au", "ninja-backup.com", "ninjaone.com", "ninjarmm.com", "ninjarmm.net", "rmmservice.ca", "rmmservice.eu",),
    "NoMachine": ("nomachine.com",),
    "OCS inventory": ("ocsinventory-ng.org",),
    "OptiTune": ("opti-tune.com", "optitune.us",),
    "PDQ Connect": ("pdq.com",),
    "Pandora RC (eHorus)": ("ehorus.com",),
    "Panorama9": ("panorama9.com",),
    "Parallels Access": ("parallels.com",),
    "Parsec": ("parsec.app", "parsec.gg",),
    "Pcvisit": ("pcvisit.de",),
    "PiTunnel": ("pitunnel.com",),
    "Pilixo": ("pilixo.com",),
    "Pocket Controller (Soti Xsight)": ("soti.net",),
    "Pulseway": ("pulseway.com",),
    "QQ IM-remote assistance": ("qq.com", "softonic.com",),
    "Quest KACE Agent (formerly Dell KACE)": ("kace.com",),
    "Quick Assist": ("microsoft.com",),
    "RAdmin": ("radmin.com",),
    "RES Automation Manager": ("ivanti.com",),
    "RPort": ("rport.io",),
    "Rapid7": ("rapid7.com",),
    "RemSupp": ("remsupp.com",),
    "Remmon": ("remmon.hu",),
    "Remobo": ("softonic.com",),
    "Remote Desktop Plus": ("donkz.nl",),
    "Remote Manipulator System": ("internetid.ru", "rmansys.ru",),
    "Remote Utilities": ("internetid.ru",),
    "Remote.it": ("remote.it",),
    "RemoteCall": ("remotecall.com", "startsupport.com",),
    "RemotePC": ("remotedesktop.com", "remotepc.com",),
    "RemotePass": ("remotepass.com",),
    "RemotePulse": ("remotepulse.io",),
    "RemoteUtilities": ("remoteutilities.com",),
    "RemoteView": ("rview.com",),
    "Rodex RMM": ("rodex.cc",),
    "Royal Server": ("royalapps.com",),
    "Royal TS": ("royalapps.com",),
    "RuDesktop": ("rudesktop.ru",),
    "RunSmart": ("runsmart.io",),
    "RustDesk": ("rustdesk.com",),
    "ScreenConnect": ("connectwise.com", "screenconnect.com",),
    "ScreenMeet": ("screenmeet.com", "scrn.mt",),
    "Seetrol": ("co.kr",),
    "Senso.cloud": ("senso.cloud",),
    "ServerEye": ("server-eye.de",),
    "ShellHub": ("shellhub.io",),
    "ShowMyPC": ("showmypc.com",),
    "SimpleHelp": ("dronemaker.org", "microuptime.com", "simple-help.com", "telesupportgroup.com",),
    "SimpleHelp": ("simple-help.com",),
    "SkyFex": ("deskroll.com", "skyfex.com",),
    "Sophos-Remote Management System": ("sophos.com", "sophosupd.com", "sophosupd.net",),
    "Sorillus": ("sorillus.com",),
    "Splashtop": ("splashtop.com",),
    "Splashtop (Beta)": ("splashtop.com",),
    "Splashtop Remote": ("splashtop.com", "splashtop.eu",),
    "SpyAnywhere": ("spyanywhere.com", "spytech-web.com",),
    "SunLogin": ("oray.com", "oray.net",),
    "SuperOps": ("superops.ai", "superopsalpha.com", "superopsbeta.com",),
    "Supremo": ("supremocontrol.com",),
    "Syncro": ("aurelius.host", "kabuto.io", "kabutoservices.com", "repairshopr.com", "servably.com", "syncroapi.com", "syncromsp.com",),
    "Syspectr": ("syspectr.com",),
    "Tactical RMM": ("tacticalrmm.com", "tailscale.com",),
    "Tailscale": ("tailscale.com", "tailscale.io",),
    "Tanium": ("tanium.com",),
    "TeamViewer": ("teamviewer.com",),
    "TeleDesktop": ("tele-desk.com",),
    "Teramind": ("teramind.co",),
    "TiFLUX": ("com.br", "splashtop.com", "tiflux.com",),
    "TightVNC": ("tightvnc.com",),
    "ToDesk": ("todesk.com",),
    "TrustConnect": ("networkservice.cyou", "trustconnectsoftware.com",),
    "UltraVNC": ("ultravnc.com",),
    "UltraViewer": ("ultraviewer.net",),
    "VIZOR": ("metaquest.com", "vector-networks.com", "vizor.cloud",),
    "Visual Studio Dev Tunnel": ("devtunnels.ms", "visualstudio.com",),
    "Weezo": ("softonic.com", "weezo.me", "weezo.net",),
    "Xeox": ("xeox.com",),
    "Zabbix Agent": ("zabbix.com",),
    "ZeroTier": ("zerotier.com",),
    "Zoho Assist": ("com.au", "com.cn", "zoho.com", "zoho.eu", "zoho.in", "zohoassist.com", "zohoassist.jp", "zohocdn.com",),
    "baramundi Management Suite": ("baramundi.com",),
    "eHorus": ("ehorus.com",),
    "ezHelp": ("co.kr",),
    "iDrive": ("idrive.com",),
    "mRemoteNG": ("mremoteng.org",),
    "ngrok": ("ngrok-agent.com", "ngrok.com",),
    "tmate": ("tmate.io",),
}

# Products common enough that their presence alone is not news
CATALOGUE_COMMON = {
    "AnyDesk",
    "Chrome Remote Desktop",
    "GoToAssist",
    "LogMeIn",
    "Quick Assist",
    "Splashtop",
    "TeamViewer",
    "Zoho Assist",
}


# ──────────────────────────────────────────────────────────────
# Remote-control tool and port signatures
# ──────────────────────────────────────────────────────────────

# process name (lowercase, no extension) -> display name
REMOTE_TOOLS = {
    "anydesk": "AnyDesk",
    "teamviewer": "TeamViewer",
    "tv_w32": "TeamViewer",
    "tv_x64": "TeamViewer",
    "teamviewer_service": "TeamViewer Service",
    "rustdesk": "RustDesk",
    "winvnc": "VNC Server",
    "winvnc4": "VNC Server",
    "tvnserver": "TightVNC",
    "vncserver": "VNC Server",
    "x11vnc": "x11vnc",
    "screenconnect": "ScreenConnect",
    "connectwisecontrol": "ConnectWise Control",
    "screenconnect.clientservice": "ScreenConnect Client",
    "aa_v3": "Ammyy Admin",
    "ammyy": "Ammyy Admin",
    "supremosystem": "Supremo",
    "supremo": "Supremo",
    "rserver3": "Radmin Server",
    "radmin": "Radmin",
    "dwagent": "DWService Agent",
    "dwagsvc": "DWService",
    "g2comm": "GoToMyPC",
    "lmiguardiansvc": "LogMeIn",
    "logmein": "LogMeIn",
    "sragent": "Splashtop",
    "srserver": "Splashtop",
    "splashtop": "Splashtop",
    "parsecd": "Parsec",
    "atera": "Atera Agent",
    "syncrosetup": "Syncro RMM",
    "nomachine": "NoMachine",
    "remoteutilities": "Remote Utilities",
    "rutserv": "Remote Utilities Host",
    "quickassist": "Windows Quick Assist",
    "mstsc": "RDP Client (outbound)",
    "chrome_remote_desktop": "Chrome Remote Desktop",
    "remoting_host": "Chrome Remote Desktop Host",
}

# Legitimate admin ports — one listening is a way into the machine
ADMIN_PORTS = {
    22: "SSH",
    23: "Telnet (unencrypted — dangerous)",
    3389: "RDP — Remote Desktop",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    5903: "VNC",
    5938: "TeamViewer",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    4899: "Radmin",
    5222: "Chrome Remote Desktop",
    7070: "AnyDesk",
    8040: "ScreenConnect",
    6568: "AnyDesk",
    3283: "Apple Remote Desktop",
}

# Ports common in malicious control tools — low-confidence hint
ABUSED_PORTS = {
    1177: "njRAT",
    1604: "DarkComet",
    4444: "Metasploit / common in backdoors",
    5552: "njRAT",
    6666: "common in backdoors",
    6667: "IRC — used by botnets",
    7777: "common in backdoors",
    31337: "Back Orifice",
}

# Ports that malware sometimes uses and ordinary software uses constantly.
# Keeping them in ABUSED_PORTS meant a Jupyter notebook on 8888 or a
# supervisord on 9001 produced a "common in backdoors" warning on every
# scan, which is exactly the kind of alert that teaches people to stop
# reading alerts. They are still named, at informational level only.
NOISY_PORTS = {
    8000: "development web server",
    8080: "development or proxy web server",
    8888: "Jupyter or a development server",
    9001: "supervisord or Tor control",
    9050: "Tor SOCKS proxy",
}

# Paths where legitimate software is expected to live
TRUSTED_DIR_PREFIXES_WIN = (
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
)

TRUSTED_DIR_PREFIXES_NIX = (
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/bin",
    "/sbin",
    "/opt",
    "/snap",
)

# Paths it is suspicious to run a program from
SUSPICIOUS_DIR_HINTS = (
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
    "\\windows\\temp",
    "\\downloads",
    "\\public",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
)


def identify_tool(proc_name: str) -> str | None:
    """Which remote-control product this process belongs to, if any.

    The hand-written table wins: it is curated, it carries the vendor
    domains used to tell a real session from a hijacked one, and its
    entries reflect decisions about severity. The generated catalogue is a
    wider net cast behind it, so a product released after these signatures
    were written is still recognised instead of passing as an unknown
    binary — the way this tool would otherwise go stale.
    """
    if not proc_name:
        return None
    key = proc_name.lower().removesuffix(".exe")
    if key in REMOTE_TOOLS:
        return REMOTE_TOOLS[key]
    try:
        pass  # (relative import removed when merging)
    except ImportError:
        return None
    return CATALOGUE_EXECUTABLES.get(key)


def describe_port(port: int) -> tuple[str, str] | None:
    """Returns (description, confidence) for a port, or None if unknown."""
    if port in ADMIN_PORTS:
        return ADMIN_PORTS[port], "admin"
    if port in ABUSED_PORTS:
        return ABUSED_PORTS[port], "abused"
    if port in NOISY_PORTS:
        return NOISY_PORTS[port], "noisy"
    return None


# ───────────────────────────────────────────────────────────────────
# Vendor domains for remote-control tools
# ───────────────────────────────────────────────────────────────────
# A legitimate control tool talks to its vendor's servers. When the tool
# itself reaches a raw address belonging to no known domain, it is most
# likely driven from an attacker's own server rather than official
VENDOR_DOMAINS = {
    "AnyDesk": ("anydesk.com", "net.anydesk.com"),
    "TeamViewer": ("teamviewer.com", "dyngate.com"),
    "TeamViewer Service": ("teamviewer.com", "dyngate.com"),
    "RustDesk": ("rustdesk.com",),
    "ScreenConnect": ("screenconnect.com", "connectwise.com", "hostedrmm.com"),
    "ScreenConnect Client": ("screenconnect.com", "connectwise.com", "hostedrmm.com"),
    "ConnectWise Control": ("screenconnect.com", "connectwise.com"),
    "Splashtop": ("splashtop.com", "splashtop.eu"),
    "LogMeIn": ("logmein.com", "logme.in"),
    "GoToMyPC": ("gotomypc.com", "logmein.com"),
    "Atera Agent": ("atera.com", "servicedesk.atera.com"),
    "Syncro RMM": ("syncromsp.com", "syncroapi.com"),
    "DWService Agent": ("dwservice.net",),
    "DWService": ("dwservice.net",),
    "Supremo": ("supremocontrol.com", "nanosystems.it"),
    "Parsec": ("parsec.app", "parsecgaming.com"),
    "NoMachine": ("nomachine.com",),
    "Chrome Remote Desktop": ("google.com", "gvt1.com", "googleusercontent.com"),
    "Chrome Remote Desktop Host": ("google.com", "gvt1.com", "googleusercontent.com"),
    "Windows Quick Assist": ("microsoft.com", "msftconnecttest.com", "azure.com"),
    "Remote Utilities Host": ("remoteutilities.com",),
    "Remote Utilities": ("remoteutilities.com",),
    "Radmin": ("radmin.com", "famatech.com"),
    "Radmin Server": ("radmin.com", "famatech.com"),
}


# ───────────────────────────────────────────────────────────────────
# Tunnelling tools
# ───────────────────────────────────────────────────────────────────
# A tunnel inverts the direction of the connection: the machine dials out,
# passing the firewall and router without opening a port. And because the
# session appears aimed at the tunnel provider, the visible address is not
TUNNEL_TOOLS = {
    "cloudflared": "Cloudflare Tunnel",
    "ngrok": "ngrok",
    "frpc": "frp (client)",
    "frps": "frp (server)",
    "chisel": "chisel",
    "zrok": "zrok",
    "playit": "playit.gg",
    "playit-agent": "playit.gg",
    "localtunnel": "localtunnel",
    "nps": "nps",
    "npc": "nps (client)",
    "gost": "gost",
    "iodine": "DNS tunnel (iodine)",
    "dnscat2": "DNS tunnel (dnscat2)",
    "pagekite": "PageKite",
    "bore": "bore",
}

# Mesh VPNs. They do invert the connection, but they are mainstream products
# a great many people install deliberately, and calling a running Tailscale
# a critical finding trains the user to dismiss the tunnel category
# altogether. Reported, at a lower severity, as something to recognise
# rather than something to fear.
MESH_VPNS = {
    "tailscaled": "Tailscale",
    "tailscale": "Tailscale",
    "zerotier-one": "ZeroTier",
    "zerotier": "ZeroTier",
    "nebula": "Nebula",
    "netbird": "NetBird",
    "headscale": "Headscale",
}

# Tunnels running inside signed, legitimate programs. Neither the file hash
# nor its signature reveals these: the program is sound and the feature is
# built in. Each entry maps a process name to the argument fragments that
# turn it into a tunnel; an empty tuple means the name alone is enough.
TUNNEL_ARGS = {
    "code": ("tunnel",),
    "code-tunnel": ("tunnel",),
    "codium": ("tunnel",),
    "ssh": ("-r", "-l", "-d", "-w"),
    "autossh": ("-r", "-l", "-d"),
    "socat": ("exec:", "system:"),
    "powershell": ("-encodedcommand", "-enc "),
    "pwsh": ("-encodedcommand", "-enc "),
}

TUNNEL_ARG_LABEL = {
    "code": "VS Code tunnel",
    "code-tunnel": "VS Code tunnel",
    "codium": "VS Codium tunnel",
    "ssh": "SSH port forward",
    "autossh": "persistent SSH port forward",
    "socat": "socat relay",
    "powershell": "encoded PowerShell command",
    "pwsh": "encoded PowerShell command",
}

TUNNEL_DOMAINS = (
    "trycloudflare.com", "argotunnel.com", "cfargotunnel.com",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev",
    "devtunnels.ms", "tunnels.api.visualstudio.com",
    "loca.lt", "lhr.life", "localhost.run", "serveo.net",
    "pinggy.io", "telebit.cloud", "pagekite.me", "bore.pub",
    "playit.gg", "zrok.io", "ts.net",
)

# Dynamic DNS lets an attacker change address without changing the malware
DDNS_DOMAINS = (
    "duckdns.org", "dyndns.org", "no-ip.com", "no-ip.org", "noip.com",
    "ddns.net", "hopto.org", "zapto.org", "sytes.net", "myftp.biz",
    "myftp.org", "serveminecraft.net", "servegame.com", "redirectme.net",
    "chickenkiller.com", "freedns.afraid.org", "dynu.com", "3utilities.com",
)


def identify_tunnel(proc_name: str, cmdline: str = "") -> str | None:
    """Identifies a tunnel, whether a dedicated tool or a feature of a legit one.

    Names are matched exactly. startswith() on keys as short as "nps", "bore"
    and "gost" claimed any process whose name merely began with those
    letters.
    """
    n = (proc_name or "").lower().removesuffix(".exe")
    if n in TUNNEL_TOOLS:
        return TUNNEL_TOOLS[n]

    low = f" {(cmdline or '').lower()} "
    args = TUNNEL_ARGS.get(n)
    if args is not None:
        if not args:
            return TUNNEL_ARG_LABEL.get(n, n)
        for frag in args:
            # Flags are matched as separate words so "-d" does not fire on a
            # path fragment; substrings such as "exec:" are matched directly.
            hit = (f" {frag} " in low or f" {frag}" in low.rstrip()
                   if frag.startswith("-") else frag in low)
            if hit:
                return TUNNEL_ARG_LABEL.get(n, n)
    return None


def identify_mesh_vpn(proc_name: str) -> str | None:
    """A mainstream mesh VPN, reported but not treated as a covert channel."""
    n = (proc_name or "").lower().removesuffix(".exe")
    return MESH_VPNS.get(n)


def domain_flags(hostname: str) -> tuple[str, str] | None:
    """Classifies a hostname: tunnel, dynamic DNS, or neither."""
    h = (hostname or "").lower().rstrip(".")
    if not h:
        return None
    for d in TUNNEL_DOMAINS:
        if h == d or h.endswith("." + d):
            return "tunnel", d
    for d in DDNS_DOMAINS:
        if h == d or h.endswith("." + d):
            return "ddns", d
    return None


def vendor_match(tool: str, hostname: str) -> bool | None:
    """Is this control program talking to its own vendor's servers?

    None means "unknown" — either no domain is on record for the tool, or the
    address has no reverse name. Both are cases of not knowing, and not
    knowing must not be converted into an accusation. Most cloud addresses
    carry no PTR record at all, so treating a missing name as a mismatch
    accused every legitimate session running on ordinary hosting.

    A caller acting on True should confirm the name forward as well (see
    intel.forward_confirmed): a PTR record is set by whoever owns the address
    block, so an operator on a VPS can point theirs at a vendor domain and
    pass a reverse-only check.
    """
    domains = VENDOR_DOMAINS.get(tool)
    if not domains:
        try:
            pass  # (relative import removed when merging)
            domains = CATALOGUE_DOMAINS.get(tool)
        except ImportError:
            domains = None
    if not domains:
        return None
    h = (hostname or "").lower().rstrip(".")
    if not h:
        return None           # raw address with no reverse name — unknown
    return any(h == d or h.endswith("." + d) for d in domains)


# ──────────────────────────────────────────────────────────────
# Network inspection: ARP, DNS, hosts
# ──────────────────────────────────────────────────────────────

_OUI = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:15:5d": "Hyper-V", "00:1a:11": "Google",
    "3c:5a:b4": "Google", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi", "00:1b:63": "Apple", "ac:de:48": "Apple",
    "f0:18:98": "Apple", "00:23:ae": "Dell", "00:1e:c9": "Dell",
    "00:24:e8": "Dell", "00:e0:4c": "Realtek", "00:16:3e": "Xen",
}

MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")




def vendor_of(mac: str) -> str:
    return _OUI.get(mac.lower()[:8].replace("-", ":"), "")


def arp_table() -> list[dict]:
    """ARP table — every device this machine has spoken to on the LAN."""
    entries: list[dict] = []

    if not IS_WINDOWS and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
                        entries.append({
                            "ip": parts[0], "mac": parts[3].lower(),
                            "iface": parts[5], "vendor": vendor_of(parts[3]),
                        })
        except Exception:
            pass
        if entries:
            return entries

    out = _sh(["arp", "-a"])
    for line in out.splitlines():
        m_ip, m_mac = IP_RE.search(line), MAC_RE.search(line)
        if m_ip and m_mac:
            mac = m_mac.group(0).lower().replace("-", ":")
            if mac == "ff:ff:ff:ff:ff:ff":
                continue
            entries.append({
                "ip": m_ip.group(0), "mac": mac, "iface": "",
                "vendor": vendor_of(mac),
            })
    return entries


def _own_addresses() -> set[str]:
    """This machine's own addresses, which are not evidence of anything."""
    own: set[str] = set()
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.address:
                    own.add(a.address.split("%")[0])
    except Exception:
        pass
    return own


def neighbour_table() -> list[dict]:
    """IPv6 neighbours. ARP is IPv4-only, so NDP was a blind spot.

    An attacker on a dual-stack network can poison NDP and intercept traffic
    without touching ARP at all, which the previous version could not see.
    """
    entries: list[dict] = []
    if IS_WINDOWS:
        out = _sh(["netsh", "interface", "ipv6", "show", "neighbors"])
    else:
        out = _sh(["ip", "-6", "neigh", "show"])
    for line in out.splitlines():
        m_mac = MAC_RE.search(line)
        if not m_mac:
            continue
        token = line.split()[0] if line.split() else ""
        if ":" not in token or token.count(":") < 2:
            continue
        mac = m_mac.group(0).lower().replace("-", ":")
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        entries.append({"ip": token.split("%")[0], "mac": mac,
                        "iface": "", "vendor": vendor_of(mac), "family": "ipv6"})
    return entries


def detect_arp_spoof(entries: list[dict] | None = None) -> list[dict]:
    """One MAC on several IPs is a strong sign of a man-in-the-middle.

    It is also what a router with a second address, a host with two
    interfaces on one subnet, a virtualisation bridge, and a stale cache
    entry after a DHCP renewal all look like. Reporting every duplicate as a
    man-in-the-middle produced a critical alert on ordinary networks, so the
    ordinary causes are excluded first and the remainder is annotated with
    what makes it suspicious.
    """
    entries = entries if entries is not None else arp_table()
    own = _own_addresses()

    by_mac: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        ip = e.get("ip", "")
        mac = e.get("mac", "")
        if not ip or not mac or ip in own:
            continue
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue
        # Multicast and broadcast MACs map to many addresses by design
        try:
            if int(mac.split(":")[0], 16) & 1:
                continue
        except ValueError:
            continue
        by_mac[mac].add(ip)

    alerts = []
    for mac, ips in by_mac.items():
        if len(ips) < 2:
            continue
        # Addresses on different subnets behind one MAC is the router doing
        # its job; the interesting case is one MAC answering for several
        # hosts on the same subnet.
        same_subnet = defaultdict(set)
        for ip in ips:
            same_subnet[".".join(ip.split(".")[:3])].add(ip)
        clustered = {k: v for k, v in same_subnet.items() if len(v) > 1}
        if not clustered:
            continue
        alerts.append({"mac": mac, "ips": sorted(ips),
                       "vendor": vendor_of(mac),
                       "count": max(len(v) for v in clustered.values())})
    return alerts


def dns_servers() -> list[str]:
    """DNS servers in use. Silent changes are a classic sign of compromise."""
    servers: list[str] = []
    if IS_WINDOWS:
        out = _sh([
            "powershell", "-NoProfile", "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 "
            "| Select-Object -ExpandProperty ServerAddresses",
        ])
        servers = [s.strip() for s in out.splitlines() if s.strip()]
    else:
        for path in ("/etc/resolv.conf",):
            try:
                with open(path) as f:
                    for line in f:
                        if line.strip().startswith("nameserver"):
                            servers.append(line.split()[1])
            except Exception:
                pass
        out = _sh(["resolvectl", "dns"])
        servers += IP_RE.findall(out)
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def hosts_entries() -> list[dict]:
    """hosts entries — used to redirect sites or block update servers."""
    path = (r"C:\Windows\System32\drivers\etc\hosts" if IS_WINDOWS
            else "/etc/hosts")
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if len(parts) < 2:
                    continue
                ip, names = parts[0], parts[1:]
                loopback = ip.startswith("127.") or ip in ("::1", "0.0.0.0")
                out.append({
                    "line": i, "ip": ip, "names": " ".join(names),
                    "redirect": not loopback,
                    "blocks_security": any(
                        k in " ".join(names).lower()
                        for k in ("microsoft", "windowsupdate", "sophos", "kaspersky",
                                  "avast", "mcafee", "malwarebytes", "clamav",
                                  "defender", "virustotal", "ubuntu.com")
                    ),
                })
    except Exception:
        pass
    return out


def proxy_settings() -> dict:
    """Proxy settings. A planted proxy routes all browsing through others."""
    res = {"enabled": False, "server": "", "source": ""}
    if IS_WINDOWS:
        out = _sh([
            "reg", "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ])
        for line in out.splitlines():
            if "ProxyEnable" in line and line.strip().endswith("0x1"):
                res["enabled"] = True
            if "ProxyServer" in line:
                res["server"] = line.split()[-1]
        res["source"] = "Windows settings"
    else:
        for var in ("http_proxy", "https_proxy", "all_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            if os.environ.get(var):
                res["enabled"] = True
                res["server"] = os.environ[var]
                res["source"] = f"environment variable {var}"
                break
    return res


def interfaces() -> list[dict]:
    """Network adapters — an unfamiliar VPN or bridge deserves a look."""
    import psutil
    out = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        mac = next((a.address for a in addr_list
                    if MAC_RE.fullmatch((a.address or "").replace("-", ":"))), "")
        ips = [a.address for a in addr_list
               if a.address and not MAC_RE.fullmatch(a.address.replace("-", ":"))]
        st = stats.get(name)
        out.append({
            "name": name,
            "up": bool(st and st.isup),
            "mac": mac.lower().replace("-", ":"),
            "vendor": vendor_of(mac) if mac else "",
            "ips": ips,
        })
    return out


# ──────────────────────────────────────────────────────────────
# Connection collection tied to processes
# ──────────────────────────────────────────────────────────────

_trust_cache: dict[str, tuple[str, str]] = {}
_hash_cache: dict[str, str] = {}


@dataclass
class ProcInfo:
    pid: int = -1
    name: str = "?"
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    started: float = 0.0
    trust: str = "unknown"        # trusted | untrusted | unknown
    trust_note: str = ""
    sha256: str = ""
    ppid: int = 0
    parent: str = ""
    ancestry: str = ""          # parent chain — who launched what
    accessible: bool = True


@dataclass
class Conn:
    laddr: str = ""
    lport: int = 0
    raddr: str = ""
    rport: int = 0
    status: str = ""
    family: str = "tcp"
    proc: ProcInfo = field(default_factory=ProcInfo)
    tool: str | None = None       # name of a known remote-control tool
    tunnel: str | None = None     # tunnelling tool carrying this session
    mesh: str | None = None       # mainstream mesh VPN (Tailscale, ZeroTier…)
    rhost: str = ""               # reverse DNS name of the other party
    port_note: str = ""
    port_confidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["proc"] = asdict(self.proc)
        return d




def file_sha256(path: str, max_bytes: int = 80 * 1024 * 1024) -> str:
    """Hash of the executable, for looking it up on VirusTotal by hand."""
    if not path or path in _hash_cache:
        return _hash_cache.get(path, "")
    try:
        if os.path.getsize(path) > max_bytes:
            _hash_cache[path] = ""
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        _hash_cache[path] = h.hexdigest()
    except Exception:
        _hash_cache[path] = ""
    return _hash_cache[path]


def _trust_windows(exe: str) -> tuple[str, str]:
    """Reads the Authenticode signature without letting the path become code.

    The path travels in the environment rather than inside the command text.
    Interpolating it into the script meant a file named with a quote could
    close the string and have the rest run — as administrator, by the tool
    that was scanning it. The signature is also fetched once and reused,
    where the previous version called the cmdlet twice per file.

    Revocation is checked explicitly. Campaigns have shipped remote-access
    clients signed with a certificate the vendor had already revoked, and
    the default check does not consult revocation, so the file came back
    "Valid" — the scanner reassuring the owner about the very thing that
    was wrong.
    """
    ps = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "$p = $env:MAXPORT_TARGET; "
        "$s = Get-AuthenticodeSignature -LiteralPath $p; "
        "$status = $s.Status.ToString(); "
        "$revoked = 'unknown'; "
        "if ($s.SignerCertificate) { "
        "  $c = New-Object System.Security.Cryptography.X509Certificates."
        "X509Chain; "
        "  $c.ChainPolicy.RevocationMode = 'Online'; "
        "  $c.ChainPolicy.RevocationFlag = 'EntireChain'; "
        "  $c.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(8); "
        "  $null = $c.Build($s.SignerCertificate); "
        "  $flags = ($c.ChainStatus | ForEach-Object "
        "{ $_.Status.ToString() }) -join ','; "
        "  if ($flags -match 'Revoked') { $revoked = 'yes' } "
        "  elseif ($flags -match 'RevocationStatusUnknown|OfflineRevocation')"
        " { $revoked = 'unknown' } else { $revoked = 'no' } "
        "} "
        "$status + '|' + $s.SignerCertificate.Subject + '|' + $revoked"
    )
    env = dict(os.environ, MAXPORT_TARGET=exe)
    out = _sh(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
               timeout=30, env=env).strip()
    if not out:
        return "unknown", "could not check the signature"

    parts = out.split("|")
    status = parts[0].strip() if parts else ""
    subject = parts[1] if len(parts) > 1 else ""
    revoked = parts[2].strip() if len(parts) > 2 else "unknown"
    cn = subject.split(",")[0].replace("CN=", "").strip()

    if revoked == "yes":
        # A revoked certificate is worse than an unsigned file: the signature
        # still looks right to anything that does not check.
        return "untrusted", (f"signed by {cn or 'an issuer'} with a "
                             "certificate the issuer has REVOKED")
    if status == "Valid":
        if revoked == "unknown":
            return "trusted", (f"digitally signed: {cn or 'a known authority'}"
                               " (revocation could not be checked)")
        return "trusted", f"digitally signed: {cn or 'a known authority'}"
    if status == "NotSigned":
        return "untrusted", "not digitally signed"
    return "untrusted", f"invalid signature ({status})"


def _trust_linux(exe: str) -> tuple[str, str]:
    """Classifies an executable on Linux.

    "untrusted" must mean genuinely suspicious, not merely unrecognised. If
    snap, flatpak, AppImage and /usr/local were all called suspicious, every
    real machine would fill with false alarms, the user would stop reading
    them, and the tool would be worse than nothing. Hence "unknown" as its
    own answer, distinct from both trust and suspicion.
    """
    low = exe.lower()

    # Modern packaging: signed and sandboxed, not outside the ecosystem
    if low.startswith("/snap/") or "/snap/" in low:
        return "trusted", "snap package"
    if "/flatpak/" in low or low.startswith("/var/lib/flatpak"):
        return "trusted", "flatpak package"

    # Is the file owned by the package manager?
    for cmd in (["dpkg", "-S", exe], ["rpm", "-qf", exe]):
        out = _sh(cmd, timeout=8)
        if out and "no path found" not in out.lower() and "not owned" not in out.lower():
            pkg = out.split(":")[0].strip()
            if pkg:
                return "trusted", f"from system package: {pkg}"

    try:
        st = os.stat(exe)
        root_owned = st.st_uid == 0
        world_writable = bool(st.st_mode & 0o002)
        group_writable = bool(st.st_mode & 0o020)
    except Exception:
        root_owned = world_writable = group_writable = False

    # A file any user can write to can be swapped for something malicious.
    # Group-writable is separate: it is ordinary on many systems, so it is a
    # question rather than an accusation.
    if world_writable:
        return "untrusted", "file is writable by any user on this machine"

    # Legitimate programs do not live in temp directories wiped on reboot
    if any(low.startswith(d) for d in ("/tmp/", "/dev/shm/", "/var/tmp/")):
        return "untrusted", "runs from a temp directory — abnormal for installed software"

    if any(low.startswith(p) for p in signatures.TRUSTED_DIR_PREFIXES_NIX):
        if group_writable:
            return "unknown", "in a system path but writable by its group"
        if root_owned:
            return "trusted", "in a system path and owned by root"
        return "unknown", "in a system path but not owned by root"

    # Usually installed by an admin: common and legitimate, but unverifiable
    if low.startswith("/usr/local/") and root_owned:
        return "unknown", "hand-installed in /usr/local — cannot be verified"

    if low.endswith(".appimage") or "/.mount_" in low:
        return "unknown", "AppImage — self-contained, its origin cannot be verified"

    # An interpreter is legitimate itself; what matters is the script it runs
    base = os.path.basename(low)
    if any(base.startswith(i) for i in ("python", "node", "ruby", "perl", "java",
                                        "php", "sh", "bash", "dash")):
        return "unknown", "language interpreter — judge the script in the command line, not this"

    if _in_home(exe):
        return "untrusted", "runs from a user directory outside any package system"

    return "unknown", "outside system packages — worth a look"


def _in_home(path: str) -> bool:
    for home in ("/home/", "/root/", os.path.expanduser("~")):
        if home and path.startswith(home):
            return True
    return False


def check_trust(exe: str) -> tuple[str, str]:
    """Checks whether an executable is trusted. Cached to keep scans fast."""
    if not exe:
        return "unknown", "executable path unavailable"
    if exe in _trust_cache:
        return _trust_cache[exe]
    if not os.path.exists(exe):
        res = ("untrusted", "the executable is deleted or hidden")
    elif IS_WINDOWS:
        res = _trust_windows(exe)
    else:
        res = _trust_linux(exe)
    _trust_cache[exe] = res
    return res


def path_looks_suspicious(exe: str) -> str:
    """Does the executable live somewhere installed software does not?

    Separators are normalised to backslashes before matching. The previous
    version replaced each separator with itself, so the normalisation did
    nothing and a Windows path written with forward slashes matched none of
    the Windows hints.
    """
    low = (exe or "").lower().replace("/", "\\")
    for hint in signatures.SUSPICIOUS_DIR_HINTS:
        if hint.replace("/", "\\") in low:
            return hint
    return ""


def _proc_info(pid: int | None, deep: bool) -> ProcInfo:
    if not pid:
        return ProcInfo(pid=-1, name="unknown", accessible=False,
                        trust_note="run as administrator to see this process")
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = ProcInfo(
                pid=pid,
                name=p.name(),
                exe=(p.exe() or ""),
                cmdline=" ".join(p.cmdline() or [])[:400],
                username=(p.username() or ""),
                started=p.create_time(),
                ppid=p.ppid() or 0,
            )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ProcInfo(pid=pid, name="access denied", accessible=False,
                        trust_note="run as administrator")
    except Exception:
        return ProcInfo(pid=pid, name="unknown", accessible=False)

    if deep and info.exe:
        info.trust, info.trust_note = check_trust(info.exe)
        info.sha256 = file_sha256(info.exe)
    info.parent, info.ancestry = _ancestry(pid)
    return info


def _ancestry(pid: int, limit: int = 6) -> tuple[str, str]:
    """The parent process chain — more telling than the process name itself.

    A remote-control program the user launched is one thing; one launched by
    a document macro, a shell or an unknown service is another entirely.
    """
    chain, seen = [], set()
    try:
        p = psutil.Process(pid)
        for _ in range(limit):
            p = p.parent()
            if p is None or p.pid in seen:
                break
            seen.add(p.pid)
            chain.append(f"{p.name()}({p.pid})")
    except Exception:
        pass
    return (chain[0].split("(")[0] if chain else ""), " ← ".join(chain)


SUSPICIOUS_PARENTS = (
    "winword", "excel", "powerpnt", "outlook", "acrobat", "acrord32",
    "wscript", "cscript", "mshta", "powershell", "pwsh", "cmd", "rundll32",
    "regsvr32", "curl", "wget", "bash", "sh", "zsh", "dash", "python",
)

_ANCESTRY_ENTRY = re.compile(r"([^\s←]+?)\((\d+)\)")


def _ancestry_names(ancestry: str) -> list[str]:
    """Process names from an ancestry string, without their PIDs."""
    return [m.group(1).lower().removesuffix(".exe")
            for m in _ANCESTRY_ENTRY.finditer(ancestry or "")]


def parent_is_suspicious(info: "ProcInfo") -> str:
    """Was this process launched by something that should not start network programs?

    Names are compared whole. Testing for the substring "sh(" matched
    "flush(12)" and raised a critical alert on it, while "python(" failed to
    match "python3(4321)" and missed the real case — wrong in both
    directions at once. Version suffixes are stripped so python3.12 still
    counts as python.
    """
    for name in _ancestry_names(info.ancestry):
        stem = re.sub(r"[\d.]+$", "", name) or name
        if name in SUSPICIOUS_PARENTS or stem in SUSPICIOUS_PARENTS:
            return name
    return ""


def collect_connections(deep: bool = True) -> tuple[list[Conn], str | None]:
    """Collects all TCP/UDP connections and ties them to processes.

    Returns (connection list, privilege warning if any).
    """
    warning = None
    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return [], "Access denied — run as administrator/root to see all connections."
    except Exception as e:
        return [], f"Could not read connections: {e}"

    seen_pids: dict[int, ProcInfo] = {}
    out: list[Conn] = []
    denied = 0

    for c in raw:
        pid = c.pid
        if pid in seen_pids:
            info = seen_pids[pid]
        else:
            info = _proc_info(pid, deep)
            if pid:
                seen_pids[pid] = info
        if not info.accessible:
            denied += 1

        conn = Conn(
            laddr=c.laddr.ip if c.laddr else "",
            lport=c.laddr.port if c.laddr else 0,
            raddr=c.raddr.ip if c.raddr else "",
            rport=c.raddr.port if c.raddr else 0,
            status=c.status or "",
            family="udp" if c.type == 2 else "tcp",
            proc=info,
        )
        conn.tool = signatures.identify_tool(info.name)
        conn.tunnel = signatures.identify_tunnel(info.name, info.cmdline)
        conn.mesh = signatures.identify_mesh_vpn(info.name)
        desc = signatures.describe_port(conn.rport or conn.lport)
        if desc:
            conn.port_note, conn.port_confidence = desc
        out.append(conn)

    if denied and not warning:
        warning = f"{denied} connections without process details — run as administrator/root."
    return out, warning


def listening_ports(conns: list[Conn]) -> list[Conn]:
    """Listening ports — every open door into this machine."""
    return [c for c in conns if c.status == "LISTEN" or (c.family == "udp" and not c.raddr)]


def established(conns: list[Conn]) -> list[Conn]:
    return [c for c in conns if c.status == "ESTABLISHED" and c.raddr]


def uptime_of(proc: ProcInfo) -> str:
    if not proc.started:
        return ""
    secs = int(time.time() - proc.started)
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"


# ──────────────────────────────────────────────────────────────
# Profiling the other party
# ──────────────────────────────────────────────────────────────

_cache: dict[str, "PeerProfile"] = {}
UA = {"User-Agent": "MaxPort/1.0 (host security audit)"}


@dataclass
class PeerProfile:
    ip: str = ""
    scope: str = ""              # local | internet | loopback
    mac: str = ""                # only available for devices on the same LAN
    vendor: str = ""             # manufacturer, derived from the MAC prefix
    hostname: str = ""           # reverse DNS name
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    is_proxy: bool = False       # VPN / proxy / hosting
    is_hosting: bool = False
    abuse_email: str = ""
    abuse_score: int = -1        # AbuseIPDB score (0-100), -1 = not checked
    reports: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        if self.scope == "loopback":
            return "Internal connection to this machine itself"
        if self.scope == "local":
            bits = ["A device inside your local network"]
            if self.mac:
                bits.append(f"MAC: {self.mac}")
            if self.vendor:
                bits.append(self.vendor)
            return " — ".join(bits)
        bits = []
        if self.city or self.country:
            bits.append(", ".join(x for x in (self.city, self.country) if x))
        if self.isp:
            bits.append(self.isp)
        if self.asn:
            bits.append(self.asn)
        return " — ".join(bits) or "An address on the internet"


def classify(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private or addr.is_link_local:
        return "local"
    return "internet"


def _get_json(url: str, timeout: int = 8) -> dict | None:
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def reverse_dns(ip: str) -> str:
    """Reverse name of an address, or empty if it has none.

    The timeout is passed per call. setdefaulttimeout() would change the
    default for every socket in the process, including the API requests
    below, which is a side effect no lookup helper should be imposing.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def forward_confirmed(ip: str, hostname: str) -> bool:
    """Does the reverse name resolve forward to the same address?

    A PTR record is controlled by whoever owns the address block, so an
    operator running from a VPS can name theirs anything they like, including
    a vendor's domain. Resolving the name forward closes that gap: they would
    also have to control the vendor's zone.
    """
    if not ip or not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return False
    return any(info[4][0] == ip for info in infos)


def mac_for_local_ip(ip: str) -> tuple[str, str]:
    """Looks up a MAC in the ARP table — LAN devices only."""
    for entry in arp_table():
        if entry["ip"] == ip:
            return entry["mac"], entry.get("vendor", "")
    return "", ""


def geo_asn(ip: str) -> dict | None:
    """Network owner and rough location for an address.

    HTTPS first. The previous version used ip-api over plain HTTP, so the
    answer about a suspected attacker's address arrived unauthenticated and
    modifiable in transit — poor form anywhere, worse in a tool whose whole
    job is deciding whom to trust. It also asked for Arabic replies, which
    stayed behind after the interface moved to English and produced a report
    in two languages.

    The plaintext service remains as a last resort, and when it is used the
    result says so rather than presenting it as equally reliable.
    """
    data = _get_json(f"https://ipwho.is/{ip}")
    if data and data.get("success"):
        conn = data.get("connection") or {}
        return {
            "status": "success",
            "country": data.get("country", ""),
            "regionName": data.get("region", ""),
            "city": data.get("city", ""),
            "isp": conn.get("isp", "") or conn.get("org", ""),
            "org": conn.get("org", ""),
            "as": (f"AS{conn['asn']}" if conn.get("asn") else ""),
            "proxy": bool((data.get("security") or {}).get("proxy")),
            "hosting": bool((data.get("security") or {}).get("hosting")),
            "transport": "https",
        }

    fields = "status,country,regionName,city,isp,org,as,proxy,hosting,query"
    data = _get_json(f"http://ip-api.com/json/{ip}?fields={fields}")
    if data and data.get("status") == "success":
        data["transport"] = "http"
    return data


def rdap_abuse(ip: str) -> str:
    """Pulls the abuse contact from RDAP, for filing a formal report."""
    data = _get_json(f"https://rdap.org/ip/{ip}", timeout=10)
    if not data:
        return ""
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles") or []
        if "abuse" not in roles:
            continue
        vcard = (ent.get("vcardArray") or [None, []])[1]
        for item in vcard:
            if item and item[0] == "email":
                return item[3]
    return ""


def abuseipdb(ip: str, api_key: str) -> dict | None:
    if not api_key:
        return None
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={**UA, "Key": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get("data")
    except Exception:
        return None


_vt_cache: dict[str, dict] = {}


def virustotal(sha256: str, api_key: str) -> dict | None:
    """Asks VirusTotal about a file hash. The file itself is never uploaded.

    Only the hash is sent, so no data leaves the machine. If the file is
    unknown to them, that is itself a signal: widely used legitimate software
    is always already known.
    """
    if not sha256 or not api_key:
        return None
    if sha256 in _vt_cache:
        return _vt_cache[sha256]
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={**UA, "x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        stats = (data.get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        attrs = data.get("data", {}).get("attributes", {})
        res = {
            "known": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(v for v in stats.values() if isinstance(v, int)),
            "name": (attrs.get("meaningful_name") or ""),
            "first_seen": attrs.get("first_submission_date", 0),
            "reputation": attrs.get("reputation", 0),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            res = {"known": False, "malicious": 0, "total": 0,
                   "note": "Unknown to VirusTotal — this file has not been seen before"}
        elif e.code == 429:
            return {"error": "Free query limit exceeded (4 per minute)"}
        elif e.code == 401:
            return {"error": "VirusTotal key is not valid"}
        else:
            return {"error": f"HTTP error {e.code}"}
    except Exception as e:
        return {"error": str(e)[:120]}

    _vt_cache[sha256] = res
    return res


def vt_summary(res: dict | None) -> tuple[str, str]:
    """Turns a VirusTotal result into a displayable (text, severity)."""
    if not res:
        return "", "info"
    if "error" in res:
        return res["error"], "info"
    if not res.get("known"):
        return res.get("note", "Unknown to VirusTotal"), "warn"
    mal = res.get("malicious", 0) + res.get("suspicious", 0)
    total = res.get("total", 0)
    if mal >= 5:
        return f"{mal} of {total} engines flag it as malicious", "critical"
    if mal >= 1:
        return f"{mal} of {total} engines flag it — may be a false positive", "warn"
    return f"Clean across {total} engines", "info"


def profile_peer(ip: str, online: bool = True, abuse_key: str = "") -> PeerProfile:
    """Builds a full profile of the other party."""
    if ip in _cache:
        return _cache[ip]

    p = PeerProfile(ip=ip, scope=classify(ip))

    if p.scope == "local":
        # this is the only case where a MAC is obtainable
        p.mac, p.vendor = mac_for_local_ip(ip)
        p.hostname = reverse_dns(ip)
        if not p.mac:
            p.errors.append("Not in the ARP table — may be behind another router")
        _cache[ip] = p
        return p

    if p.scope != "internet":
        _cache[ip] = p
        return p

    p.hostname = reverse_dns(ip)

    if online:
        g = geo_asn(ip)
        if g and g.get("status") == "success":
            p.country = g.get("country", "")
            p.region = g.get("regionName", "")
            p.city = g.get("city", "")
            p.isp = g.get("isp", "")
            p.org = g.get("org", "")
            p.asn = g.get("as", "")
            p.is_proxy = bool(g.get("proxy"))
            p.is_hosting = bool(g.get("hosting"))
            if g.get("transport") == "http":
                p.errors.append("Location data came over plain HTTP and was "
                                "not authenticated in transit")
        else:
            p.errors.append("Could not fetch location and provider data")

        p.abuse_email = rdap_abuse(ip)

        a = abuseipdb(ip, abuse_key)
        if a:
            p.abuse_score = a.get("abuseConfidenceScore", -1)
            p.reports = a.get("totalReports", 0)

    _cache[ip] = p
    return p


def clear_cache() -> None:
    _cache.clear()


# ──────────────────────────────────────────────────────────────
# Browser extensions
# ──────────────────────────────────────────────────────────────

# Permissions that matter, and what each one actually grants. Written as
# consequences rather than API names, because "can read the cookies that
# keep you signed in" is a question the owner can answer and
# "cookies permission" is not.
PERMISSION_MEANING = {
    "cookies": "read the cookies that keep you signed in",
    "webRequest": "watch and alter every network request",
    "webRequestBlocking": "intercept requests before they are sent",
    "declarativeNetRequest": "rewrite or block network requests",
    "declarativeNetRequestWithHostAccess": "rewrite requests on any site",
    "debugger": "attach to pages as a debugger and read everything in them",
    "nativeMessaging": "talk to a program installed on this computer",
    "management": "disable or remove your other extensions",
    "proxy": "route your traffic through a server of its choosing",
    "clipboardRead": "read what you copy",
    "downloads": "download files without asking",
    "history": "read your full browsing history",
    "tabs": "see every page you open",
    "scripting": "run its own code inside pages",
    "privacy": "change your privacy settings",
    "desktopCapture": "capture your screen",
    "tabCapture": "capture the contents of tabs",
    "identity": "obtain authentication tokens",
    "browsingData": "erase browsing data",
}

# The permissions whose harm depends on where they apply
BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*",
               "*://*/", "file:///*")

# Combinations that add up to session theft. Individually ordinary; together
# they are the whole capability an attacker needs and nothing more.
DANGEROUS_COMBOS = [
    ({"cookies"}, True,
     "can read the session cookies for every site you visit — enough to sign "
     "in as you without ever needing your password or second factor"),
    ({"debugger"}, False,
     "can attach to pages as a debugger, which reads everything in them "
     "including what you type"),
    ({"webRequest", "webRequestBlocking"}, True,
     "can intercept every request before it is sent, including "
     "authentication headers"),
    ({"nativeMessaging"}, False,
     "can pass messages to a program installed on this computer, which is "
     "how a browser extension reaches outside the browser"),
    ({"proxy"}, False,
     "can send your traffic through a server of its choosing"),
    ({"management"}, False,
     "can disable your other extensions, including security ones"),
]


def _home_dirs() -> list[str]:
    """Home directories to search, including the real user's under sudo."""
    homes = []
    for var in ("SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(var)
        if not val:
            continue
        try:
            import pwd
            rec = (pwd.getpwuid(int(val)) if var == "PKEXEC_UID"
                   else pwd.getpwnam(val))
            if rec.pw_dir:
                homes.append(rec.pw_dir)
        except Exception:
            pass
    homes.append(os.path.expanduser("~"))
    return list(dict.fromkeys(h for h in homes if h and os.path.isdir(h)))


def _chromium_roots() -> list[tuple[str, str]]:
    """(browser name, user-data directory) for every Chromium browser found."""
    roots = []
    for home in _home_dirs():
        if IS_WINDOWS:
            local = os.environ.get("LOCALAPPDATA") or os.path.join(
                home, "AppData", "Local")
            candidates = [
                ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
                ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
                ("Brave", os.path.join(local, "BraveSoftware",
                                       "Brave-Browser", "User Data")),
                ("Vivaldi", os.path.join(local, "Vivaldi", "User Data")),
                ("Opera", os.path.join(
                    os.environ.get("APPDATA") or home,
                    "Opera Software", "Opera Stable")),
            ]
        else:
            cfg = os.path.join(home, ".config")
            candidates = [
                ("Chrome", os.path.join(cfg, "google-chrome")),
                ("Chromium", os.path.join(cfg, "chromium")),
                ("Edge", os.path.join(cfg, "microsoft-edge")),
                ("Brave", os.path.join(cfg, "BraveSoftware", "Brave-Browser")),
                ("Vivaldi", os.path.join(cfg, "vivaldi")),
                ("Opera", os.path.join(cfg, "opera")),
            ]
        roots += [(name, path) for name, path in candidates
                  if os.path.isdir(path)]
    return roots


def _firefox_profiles() -> list[str]:
    out = []
    for home in _home_dirs():
        if IS_WINDOWS:
            base = os.path.join(os.environ.get("APPDATA") or home,
                                "Mozilla", "Firefox", "Profiles")
        else:
            base = os.path.join(home, ".mozilla", "firefox")
        if os.path.isdir(base):
            out += [p for p in glob.glob(os.path.join(base, "*"))
                    if os.path.isdir(p)]
    return out


def _read_json(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _localise(manifest: dict, ext_dir: str, value: str) -> str:
    """Resolves a __MSG_name__ placeholder to the real display name.

    Extensions may declare their name in a message catalogue rather than the
    manifest. Reporting "__MSG_extName__" to someone trying to decide whether
    they installed a thing is no help at all.
    """
    if not value.startswith("__MSG_"):
        return value
    key = value[6:-2] if value.endswith("__") else value[6:]
    default = manifest.get("default_locale") or "en"
    for locale in (default, "en", "en_US"):
        msgs = _read_json(os.path.join(ext_dir, "_locales", locale,
                                       "messages.json"))
        if msgs and key in msgs:
            got = (msgs[key] or {}).get("message")
            if got:
                return got
    return value


def _assess(permissions: list, hosts: list) -> tuple[list, bool]:
    """What this permission set amounts to, and whether hosts are unrestricted."""
    perms = {str(p) for p in permissions}
    all_hosts = {str(h) for h in hosts}
    # Host permissions can also appear in the permissions array (MV2)
    broad = any(h in BROAD_HOSTS or h.startswith("*://*")
                for h in all_hosts | perms)

    concerns = []
    for needed, needs_broad, meaning in DANGEROUS_COMBOS:
        if not needed.issubset(perms):
            continue
        if needs_broad and not broad:
            continue
        concerns.append(meaning)
    return concerns, broad


def _chromium_extensions() -> list[dict]:
    items = []
    for browser, root in _chromium_roots():
        pattern = os.path.join(root, "*", "Extensions", "*", "*",
                               "manifest.json")
        for manifest_path in glob.glob(pattern):
            manifest = _read_json(manifest_path)
            if not manifest:
                continue
            ext_dir = os.path.dirname(manifest_path)
            parts = manifest_path.split(os.sep)
            try:
                ext_id = parts[-3]
                profile = parts[-5]
            except IndexError:
                ext_id, profile = "", ""

            perms = list(manifest.get("permissions") or [])
            optional = list(manifest.get("optional_permissions") or [])
            hosts = list(manifest.get("host_permissions") or [])
            # Manifest V2 puts host patterns in with the permissions
            hosts += [p for p in perms if isinstance(p, str) and "://" in p]

            concerns, broad = _assess(perms, hosts)

            # An extension from the store carries the store's update URL.
            # Its absence means it was placed here by something else — a
            # policy, an installer, or by hand.
            update_url = str(manifest.get("update_url") or "")
            from_store = "clients2.google.com" in update_url or bool(update_url)

            try:
                installed = os.path.getmtime(ext_dir)
            except OSError:
                installed = 0.0

            items.append({
                "browser": browser,
                "profile": profile,
                "id": ext_id,
                "name": _localise(manifest, ext_dir,
                                  str(manifest.get("name") or ext_id)),
                "version": str(manifest.get("version") or ""),
                "path": ext_dir,
                "permissions": sorted(str(p) for p in perms),
                "optional_permissions": sorted(str(p) for p in optional),
                "hosts": sorted(set(hosts)),
                "broad_host_access": broad,
                "concerns": concerns,
                "from_store": from_store,
                "installed": installed,
                "manifest_version": manifest.get("manifest_version", 0),
            })
    return items


def _firefox_extensions() -> list[dict]:
    items = []
    for profile in _firefox_profiles():
        data = _read_json(os.path.join(profile, "extensions.json"))
        if not data:
            continue
        for addon in data.get("addons") or []:
            if addon.get("type") not in (None, "extension"):
                continue
            if not addon.get("active", True) and addon.get("userDisabled"):
                continue
            manifest = addon.get("defaultLocale") or {}
            perms_all = ((addon.get("userPermissions") or {}) or {})
            perms = list(perms_all.get("permissions") or [])
            hosts = list(perms_all.get("origins") or [])
            concerns, broad = _assess(perms, hosts)

            # Firefox records where an add-on came from. Anything other than
            # the store was placed here by something else.
            source = str(addon.get("sourceURI") or "")
            location = str(addon.get("location") or "")
            from_store = ("addons.mozilla.org" in source
                          or location == "app-profile" and bool(source))

            items.append({
                "browser": "Firefox",
                "profile": os.path.basename(profile),
                "id": str(addon.get("id") or ""),
                "name": str(manifest.get("name") or addon.get("id") or ""),
                "version": str(addon.get("version") or ""),
                "path": str(addon.get("path") or ""),
                "permissions": sorted(str(p) for p in perms),
                "optional_permissions": [],
                "hosts": sorted(set(str(h) for h in hosts)),
                "broad_host_access": broad,
                "concerns": concerns,
                "from_store": from_store,
                "installed": (addon.get("installDate") or 0) / 1000.0,
                "manifest_version": 2,
            })
    return items


def scan_extensions(errors: list[str] | None = None) -> list[dict]:
    """Every browser extension we can read, with what it is able to do."""
    def sub(label, fn):
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = sub("Chromium extensions", _chromium_extensions)
    items += sub("Firefox extensions", _firefox_extensions)
    return items


def describe_permissions(ext: dict) -> list[str]:
    """The extension's permissions in plain terms, for the evidence panel."""
    out = []
    for perm in ext.get("permissions", []):
        meaning = PERMISSION_MEANING.get(perm)
        if meaning:
            out.append(meaning)
    if ext.get("broad_host_access"):
        out.append("act on every website, not a specific list")
    return out


# ──────────────────────────────────────────────────────────────
# Remote-access configuration
# ──────────────────────────────────────────────────────────────

def _rmm_entry(tool: str, setting: str, detail: str, path: str,
           risk: str = "warn") -> dict:
    return {"tool": tool, "setting": setting, "detail": detail,
            "path": path, "risk": risk}


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _config_dirs() -> list[str]:
    """Where remote-access tools keep configuration, per platform."""
    dirs = []
    if IS_WINDOWS:
        for var in ("PROGRAMDATA", "APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(var)
            if base:
                dirs.append(base)
        dirs += [os.environ.get("PROGRAMFILES") or r"C:\Program Files",
                 os.environ.get("PROGRAMFILES(X86)") or
                 r"C:\Program Files (x86)"]
    else:
        dirs += ["/etc", "/opt", "/usr/local/etc"]
        home = os.path.expanduser("~")
        dirs += [os.path.join(home, ".anydesk"), os.path.join(home, ".config")]
    return [d for d in dirs if d and os.path.isdir(d)]


def anydesk_unattended() -> list[dict]:
    """AnyDesk stores an unattended password hash in its service config.

    Its presence means a session can be accepted with nobody at the keyboard.
    """
    out = []
    names = ("service.conf", "system.conf", "user.conf")
    for base in _config_dirs():
        for name in names:
            for path in glob.glob(os.path.join(base, "**", "AnyDesk", name),
                                  recursive=True)[:20] + \
                        glob.glob(os.path.join(base, name)):
                text = _read(path)
                if not text:
                    continue
                low = text.lower()
                if "ad.anynet.pwd_hash" in low or "ad.security.password" in low:
                    out.append(_rmm_entry(
                        "AnyDesk", "Unattended access password is set",
                        "Someone holding this password can connect and take "
                        "control with nobody present to approve it. Set by "
                        "the owner, this is a convenience; set by someone "
                        "else, it is a way back in that needs no malware.",
                        path, risk="critical"))
                if "ad.features.file_manager=false" in low.replace(" ", ""):
                    out.append(_rmm_entry(
                        "AnyDesk", "File transfer disabled",
                        "Unusual for ordinary use; sometimes set to reduce "
                        "traces.", path, risk="info"))
    return out


def screenconnect_config() -> list[dict]:
    """ScreenConnect clients record the server they answer to.

    The relay address is the single most useful fact about an installed
    client: a company's own server is one thing, an address nobody
    recognises is another.
    """
    out = []
    for base in _config_dirs():
        pattern = os.path.join(base, "**", "ScreenConnect*", "*.config")
        for path in glob.glob(pattern, recursive=True)[:30]:
            text = _read(path)
            if not text:
                continue
            for marker in ("h=", "&h=", "relay", "WebServerAddress"):
                if marker in text:
                    break
            else:
                continue
            out.append(_rmm_entry(
                "ScreenConnect", "Client is bound to a relay server",
                "This client answers to whichever server is named in its "
                "configuration. Confirm the address belongs to an IT "
                "provider you actually use.",
                path, risk="warn"))
            break
    return out


def vnc_no_auth() -> list[dict]:
    """A VNC server with no password is an open door, not a risk."""
    out = []
    candidates = ["/etc/vnc.conf", "/root/.vnc", "/etc/x11vnc.conf"]
    for home in (os.path.expanduser("~"),):
        candidates.append(os.path.join(home, ".vnc"))
    for path in candidates:
        if os.path.isdir(path):
            if not glob.glob(os.path.join(path, "passwd*")):
                out.append(_rmm_entry(
                    "VNC", "No password file found",
                    "A VNC server without authentication accepts anyone who "
                    "can reach the port.", path, risk="critical"))
        elif os.path.isfile(path):
            low = _read(path).lower()
            if "nopw" in low or "-nopw" in low:
                out.append(_rmm_entry(
                    "VNC", "Configured to run without a password",
                    "Anyone who can reach the port gets the screen.",
                    path, risk="critical"))
    return out


def rdp_unrestricted() -> list[dict]:
    """RDP with network-level authentication off accepts more attempts."""
    if not IS_WINDOWS:
        return []
    import subprocess
    out = []
    try:
        r = subprocess.run(
            ["reg", "query",
             r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
             r"\WinStations\RDP-Tcp", "/v", "UserAuthentication"],
            capture_output=True, text=True, timeout=15, errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if "0x0" in (r.stdout or ""):
            out.append(_rmm_entry(
                "RDP", "Network-level authentication is off",
                "Connections reach the login screen before proving who they "
                "are, which is what password-guessing needs.",
                "HKLM\\...\\RDP-Tcp", risk="warn"))
    except Exception:
        pass
    return out


def scan_unattended(errors: list[str] | None = None) -> list[dict]:
    """Every remote-access setting that permits entry without a person."""
    def sub(label, fn):
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = sub("AnyDesk configuration", anydesk_unattended)
    items += sub("ScreenConnect configuration", screenconnect_config)
    items += sub("VNC configuration", vnc_no_auth)
    items += sub("RDP configuration", rdp_unrestricted)
    return items


# ──────────────────────────────────────────────────────────────
# Post-compromise revocation list
# ──────────────────────────────────────────────────────────────

# Ordered by how quickly the loss becomes irreversible, not by how common
# the item is. A drained wallet cannot be undone; a stolen password can.
CATEGORY_ORDER = ["wallet", "session", "cloud", "ssh", "password", "messaging"]

URGENCY = {
    "wallet": "immediately — a transfer cannot be reversed",
    "session": "first — a stolen session survives a password change",
    "cloud": "within the hour — keys can create new access silently",
    "ssh": "within the hour — a key needs no password and may be trusted "
           "by other machines",
    "password": "today — after sessions are revoked, or the reset is undone",
    "messaging": "today — an account takeover here is used to reach others",
}


def _triage_entry(category: str, name: str, where: str, action: str,
           found: bool = True) -> dict:
    return {"category": category, "name": name, "path": where,
            "action": action, "urgency": URGENCY.get(category, ""),
            "found": found}


def _home() -> str:
    for var in ("SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(var)
        if not val:
            continue
        try:
            import pwd
            rec = (pwd.getpwuid(int(val)) if var == "PKEXEC_UID"
                   else pwd.getpwnam(val))
            if rec.pw_dir and os.path.isdir(rec.pw_dir):
                return rec.pw_dir
        except Exception:
            pass
    return os.path.expanduser("~")


def _exists_any(patterns: list[str]) -> str:
    for pattern in patterns:
        hits = glob.glob(pattern)
        if hits:
            return hits[0]
    return ""


def browser_sessions() -> list[dict]:
    """Cookie stores hold the sessions that outlive a password change."""
    home = _home()
    out = []
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA") or os.path.join(
            home, "AppData", "Local")
        roots = {
            "Chrome": os.path.join(local, "Google", "Chrome", "User Data"),
            "Edge": os.path.join(local, "Microsoft", "Edge", "User Data"),
            "Brave": os.path.join(local, "BraveSoftware", "Brave-Browser",
                                  "User Data"),
        }
        firefox = os.path.join(os.environ.get("APPDATA") or home,
                               "Mozilla", "Firefox", "Profiles")
    else:
        cfg = os.path.join(home, ".config")
        roots = {
            "Chrome": os.path.join(cfg, "google-chrome"),
            "Chromium": os.path.join(cfg, "chromium"),
            "Edge": os.path.join(cfg, "microsoft-edge"),
            "Brave": os.path.join(cfg, "BraveSoftware", "Brave-Browser"),
        }
        firefox = os.path.join(home, ".mozilla", "firefox")

    for name, root in roots.items():
        if not os.path.isdir(root):
            continue
        out.append(_triage_entry(
            "session", f"{name} signed-in sessions", root,
            f"Sign out of every device in each account you use in {name}. "
            "Look for a 'sign out everywhere' or 'active sessions' control — "
            "that is what invalidates a stolen cookie."))
        if _exists_any([os.path.join(root, "*", "Login Data")]):
            out.append(_triage_entry(
                "password", f"{name} saved passwords", root,
                f"Change the passwords saved in {name}, starting with email "
                "and banking. Do this after revoking sessions."))

    if os.path.isdir(firefox):
        out.append(_triage_entry(
            "session", "Firefox signed-in sessions", firefox,
            "Sign out everywhere in the accounts you use in Firefox."))
        if _exists_any([os.path.join(firefox, "*", "logins.json")]):
            out.append(_triage_entry(
                "password", "Firefox saved passwords", firefox,
                "Change the passwords stored in Firefox."))
    return out


def ssh_and_cloud() -> list[dict]:
    """Keys and tokens: no password, and often trusted elsewhere."""
    home = _home()
    out = []

    ssh_dir = os.path.join(home, ".ssh")
    if os.path.isdir(ssh_dir):
        keys = [os.path.basename(p) for p in glob.glob(os.path.join(ssh_dir, "*"))
                if os.path.basename(p).startswith("id_")
                and not p.endswith(".pub")]
        if keys:
            out.append(_triage_entry(
                "ssh", f"SSH private keys ({', '.join(keys[:4])})", ssh_dir,
                "Generate new keys and remove the old public keys from every "
                "server and from GitHub, GitLab and any other service. A key "
                "with no passphrase is usable immediately."))

    checks = [
        ("cloud", "AWS credentials", [os.path.join(home, ".aws", "credentials")],
         "Deactivate the access keys in the AWS console and issue new ones."),
        ("cloud", "Google Cloud credentials",
         [os.path.join(home, ".config", "gcloud", "credentials.db")],
         "Revoke with 'gcloud auth revoke --all' and sign in again."),
        ("cloud", "Azure credentials",
         [os.path.join(home, ".azure", "*.json")],
         "Run 'az logout' and review sign-in activity in the portal."),
        ("cloud", "Kubernetes config", [os.path.join(home, ".kube", "config")],
         "Rotate the cluster credentials this file holds."),
        ("cloud", "Docker registry login",
         [os.path.join(home, ".docker", "config.json")],
         "Log out and issue a new registry token."),
        ("cloud", "npm token", [os.path.join(home, ".npmrc")],
         "Revoke the npm token and create a new one."),
        ("cloud", "PyPI token", [os.path.join(home, ".pypirc")],
         "Revoke the PyPI token."),
        ("cloud", "Git credential store",
         [os.path.join(home, ".git-credentials")],
         "This file holds tokens in plain text. Revoke every token in it."),
        ("cloud", "GitHub CLI token",
         [os.path.join(home, ".config", "gh", "hosts.yml")],
         "Run 'gh auth logout' and revoke the token on GitHub."),
    ]
    for category, name, patterns, action in checks:
        hit = _exists_any(patterns)
        if hit:
            out.append(_triage_entry(category, name, hit, action))
    return out


def wallets_and_messaging() -> list[dict]:
    """Where a loss is immediate and cannot be undone."""
    home = _home()
    out = []
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA") or os.path.join(
            home, "AppData", "Roaming")
        local = os.environ.get("LOCALAPPDATA") or os.path.join(
            home, "AppData", "Local")
    else:
        appdata = os.path.join(home, ".config")
        local = os.path.join(home, ".local", "share")

    wallets = [
        ("Electrum", [os.path.join(appdata, "Electrum", "wallets", "*"),
                      os.path.join(home, ".electrum", "wallets", "*")]),
        ("Exodus", [os.path.join(appdata, "Exodus", "exodus.wallet"),
                    os.path.join(home, ".config", "Exodus", "exodus.wallet")]),
        ("Bitcoin Core", [os.path.join(appdata, "Bitcoin", "wallet.dat"),
                          os.path.join(home, ".bitcoin", "wallet.dat")]),
        ("Ethereum keystore", [os.path.join(home, ".ethereum", "keystore", "*")]),
        ("Monero", [os.path.join(home, "Monero", "wallets", "*")]),
    ]
    for name, patterns in wallets:
        hit = _exists_any(patterns)
        if hit:
            out.append(_triage_entry(
                "wallet", f"{name} wallet file", hit,
                "Move the funds to a wallet created on a machine you trust. "
                "Do not simply change the password: the file itself may "
                "already be gone, and the passphrase can be broken offline."))

    messaging = [
        ("Telegram", [os.path.join(appdata, "Telegram Desktop", "tdata"),
                      os.path.join(home, ".local", "share",
                                   "TelegramDesktop", "tdata")]),
        ("Discord", [os.path.join(appdata, "discord", "Local Storage"),
                     os.path.join(home, ".config", "discord",
                                  "Local Storage")]),
        ("Signal", [os.path.join(appdata, "Signal"),
                    os.path.join(home, ".config", "Signal")]),
    ]
    for name, patterns in messaging:
        hit = _exists_any(patterns)
        if hit:
            out.append(_triage_entry(
                "messaging", f"{name} session data", hit,
                f"Terminate all other sessions in {name}'s settings. These "
                "files can sign someone in as you without a code."))
    return out


def build_checklist(errors: list[str] | None = None) -> list[dict]:
    """Everything on this machine worth revoking, ordered by urgency."""
    def sub(label, fn):
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = sub("browser sessions", browser_sessions)
    items += sub("keys and cloud credentials", ssh_and_cloud)
    items += sub("wallets and messaging", wallets_and_messaging)

    order = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    items.sort(key=lambda i: order.get(i["category"], 99))
    return items


def summary(items: list[dict]) -> str:
    """One sentence naming what is at stake, for the top of a report."""
    if not items:
        return ("Nothing obvious to revoke was found on this machine, which "
                "is not the same as nothing being at risk.")
    counts: dict[str, int] = {}
    for i in items:
        counts[i["category"]] = counts.get(i["category"], 0) + 1
    parts = []
    for cat in CATEGORY_ORDER:
        if counts.get(cat):
            parts.append(f"{counts[cat]} {cat}")
    return ("If something did run as you, these were within reach: "
            + ", ".join(parts)
            + ". Revoke sessions before changing passwords — a password "
              "change does not end a session that is already signed in.")


# ──────────────────────────────────────────────────────────────
# Persistence points
# ──────────────────────────────────────────────────────────────

RUN_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]




def _entry(kind: str, name: str, value: str, source: str, risk: str = "info") -> dict:
    return {"kind": kind, "name": name, "value": value, "source": source, "risk": risk}


def real_home() -> str:
    """The real user's home directory, not root's.

    The tool asks for sudo, and sudo makes expanduser('~') return /root, so
    we would audit root's files instead of the owner's and miss the point.
    """
    user = os.environ.get("SUDO_USER")
    if user and not IS_WINDOWS:
        try:
            import pwd
            return pwd.getpwnam(user).pw_dir
        except Exception:
            cand = f"/home/{user}"
            if os.path.isdir(cand):
                return cand
    return os.path.expanduser("~")


def all_homes() -> list[str]:
    """Every user home — the backdoor may sit in a different account."""
    homes = [real_home()]
    if not IS_WINDOWS:
        homes += sorted(glob.glob("/home/*")) + ["/root"]
    seen, out = set(), []
    for h in homes:
        if h and h not in seen and os.path.isdir(h):
            seen.add(h)
            out.append(h)
    return out


def autoruns_windows() -> list[dict]:
    items: list[dict] = []
    for key in RUN_KEYS:
        out = _sh(["reg", "query", key])
        for line in out.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3 and parts[1].startswith("REG_"):
                items.append(_entry("Autostart", parts[0], parts[2], key))
    return items


def scheduled_tasks_windows() -> list[dict]:
    """Scheduled tasks not belonging to Microsoft."""
    out = _sh([
        "powershell", "-NoProfile", "-Command",
        "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*' "
        "-and $_.State -ne 'Disabled'} | ForEach-Object "
        "{ $_.TaskPath + $_.TaskName + '|' + "
        "($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ' }",
    ], timeout=40)
    items = []
    for line in out.splitlines():
        if "|" in line:
            name, _, action = line.partition("|")
            items.append(_entry("Scheduled task", name.strip(), action.strip(),
                                "Task Scheduler"))
    return items


def services_windows() -> list[dict]:
    """Services running from paths outside the system directories."""
    out = _sh([
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_Service | Where-Object {$_.State -eq 'Running'} "
        "| ForEach-Object { $_.Name + '|' + $_.PathName }",
    ], timeout=40)
    items = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        name, _, path = line.partition("|")
        low = path.lower()
        if any(low.lstrip('"').startswith(p) for p in
               (r"c:\windows", r"c:\program files")):
            continue
        items.append(_entry("Service", name.strip(), path.strip(), "Services",
                            risk="warn"))
    return items


def wmi_subscriptions_windows() -> list[dict]:
    """WMI event subscriptions — the best-hidden persistence on Windows.

    They appear in no task manager, no startup list and no scheduled task
    view, and survive reboots. A CommandLineEventConsumer means a command
    runs automatically whenever an attacker-defined event fires.
    """
    items = []
    ps = (
        "Get-CimInstance -Namespace root\\Subscription -ClassName "
        "__FilterToConsumerBinding -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Filter.ToString() + '||' + $_.Consumer.ToString() }"
    )
    for line in _sh(["powershell", "-NoProfile", "-Command", ps], timeout=40).splitlines():
        if "||" not in line:
            continue
        filt, _, consumer = line.partition("||")
        low = consumer.lower()
        # Consumers that execute commands are the danger: ActiveScript and
        risk = ("critical" if ("commandline" in low or "activescript" in low)
                else "warn")
        items.append(_entry("WMI event subscription", consumer.strip()[:120],
                            f"Filter: {filt.strip()[:160]}",
                            "root\\Subscription", risk=risk))

    ps2 = (
        "Get-CimInstance -Namespace root\\Subscription -ClassName "
        "CommandLineEventConsumer -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Name + '||' + $_.CommandLineTemplate }"
    )
    for line in _sh(["powershell", "-NoProfile", "-Command", ps2], timeout=40).splitlines():
        if "||" not in line:
            continue
        name, _, cmd = line.partition("||")
        items.append(_entry("Automatic WMI command", name.strip(), cmd.strip()[:200],
                            "CommandLineEventConsumer", risk="critical"))
    return items


def winlogon_shell_windows() -> list[dict]:
    """Winlogon keys — replacing the shell or appending to it runs at every login."""
    items = []
    key = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    expected = {"shell": "explorer.exe", "userinit": "c:\\windows\\system32\\userinit.exe,"}
    for line in _sh(["reg", "query", key]).splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3 or not parts[1].startswith("REG_"):
            continue
        name, value = parts[0].lower(), parts[2].strip()
        if name in expected and value.lower().rstrip(",") != expected[name].rstrip(","):
            items.append(_entry("Winlogon modified", parts[0], value, key,
                                risk="critical"))
    return items


def cron_linux() -> list[dict]:
    items = []
    out = _sh(["crontab", "-l"])
    for line in out.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            items.append(_entry("cron (user)", "crontab", s, "crontab -l"))
    for path in glob.glob("/etc/cron.d/*") + ["/etc/crontab"]:
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#") and not s.startswith("SHELL"):
                        items.append(_entry("cron (system)", os.path.basename(path),
                                            s, path))
        except Exception:
            pass
    return items


def systemd_linux() -> list[dict]:
    """Only systemd units installed by hand.

    Distribution units live in /usr/lib/systemd and /lib/systemd. Listing
    them all yields dozens of ordinary lines that bury the real finding.
    What matters is what was written into /etc/systemd/system or the user's
    own directory, because that is what someone installing something does.
    """
    items = []
    home = real_home()
    roots = [
        ("/etc/systemd/system", "systemd (system)", "info"),
        (os.path.join(home, ".config", "systemd", "user"),
         "systemd (user)", "warn"),
    ]
    for root, src, base_risk in roots:
        for path in glob.glob(os.path.join(root, "**", "*.service"),
                              recursive=True):
            if os.path.islink(path):
                # A symlink to a packaged unit is ordinary enabling, not a manual install
                target = os.path.realpath(path)
                if target.startswith(("/usr/lib/", "/lib/", "/usr/local/lib/")):
                    continue
            exec_line = ""
            try:
                with open(path, errors="replace") as f:
                    for line in f:
                        if line.strip().startswith("ExecStart"):
                            exec_line = line.split("=", 1)[-1].strip()
                            break
            except Exception:
                continue

            low = exec_line.lower()
            risk = base_risk
            if any(k in low for k in ("curl ", "wget ", "/dev/tcp/", "base64 -d",
                                      "bash -i", "nc ", "ncat ", "python -c")):
                risk = "critical"
            elif any(h in low for h in ("/tmp/", "/dev/shm/", "/var/tmp/")):
                risk = "critical"

            items.append(_entry("systemd service", os.path.basename(path),
                                exec_line or "(no ExecStart)", path, risk=risk))
    return items


def shell_rc_linux() -> list[dict]:
    """Lines executed on every terminal launch — a common hiding place."""
    items = []
    names = (".bashrc", ".bash_profile", ".profile", ".zshrc",
             ".zprofile", ".bash_logout")
    triggers = ("curl ", "wget ", "nc ", "ncat ", "/dev/tcp/",
                "base64 -d", "base64 --decode", "bash -i", "eval $(")
    for home in all_homes():
        for name in names:
            path = os.path.join(home, name)
            try:
                with open(path, errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        line = line.strip()
                        if line.startswith("#"):
                            continue
                        if any(k in line for k in triggers):
                            items.append(_entry(
                                "Shell startup line", f"{name}:{i}",
                                line[:200], path, risk="critical"))
            except Exception:
                pass
        # .desktop files that autostart on desktop login
        for path in glob.glob(os.path.join(home, ".config", "autostart", "*.desktop")):
            try:
                with open(path, errors="replace") as f:
                    exec_line = next(
                        (l.split("=", 1)[1].strip() for l in f
                         if l.startswith("Exec=")), "")
            except Exception:
                continue
            low = exec_line.lower()
            risk = "critical" if any(
                h in low for h in ("/tmp/", "/dev/shm/", "curl ", "wget ",
                                   "/dev/tcp/", "base64 -d")) else "info"
            items.append(_entry("Autostart (desktop)",
                                os.path.basename(path), exec_line, path, risk=risk))
    return items


def ssh_authorized_keys() -> list[dict]:
    """Authorised SSH keys — the backdoor most often forgotten during cleanup."""
    items = []
    paths = []
    paths += [os.path.join(h, ".ssh", "authorized_keys") for h in all_homes()]
    if IS_WINDOWS:
        paths.append(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                  "ssh", "administrators_authorized_keys"))
    else:
        paths += glob.glob("/home/*/.ssh/authorized_keys")
        paths.append("/root/.ssh/authorized_keys")

    for path in dict.fromkeys(paths):
        try:
            with open(path, errors="replace") as f:
                for i, line in enumerate(f, 1):
                    s = line.strip()
                    if s and not s.startswith("#"):
                        parts = s.split()
                        comment = parts[2] if len(parts) > 2 else "no comment"
                        fp = parts[1][-24:] if len(parts) > 1 else ""
                        items.append(_entry(
                            "SSH key", comment, f"…{fp}", path, risk="warn"))
        except Exception:
            pass
    return items


def scan(errors: list[str] | None = None) -> list[dict]:
    """Every persistence point we can read.

    Each sub-scanner is isolated. One of them failing used to remove its
    whole category from the results with no trace, so a registry read that
    threw looked exactly like a machine with no autostart entries — the
    difference between "nothing there" and "never looked" is the difference
    between a report and a false reassurance.

    Failures inside a sub-scanner, at the level of a single unreadable file,
    stay quiet on purpose: being unable to read another user's crontab
    without privileges is ordinary, not a finding.
    """
    def sub(label: str, fn) -> list[dict]:
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items: list[dict] = []
    if IS_WINDOWS:
        items += sub("registry autostart", autoruns_windows)
        items += sub("scheduled tasks", scheduled_tasks_windows)
        items += sub("services", services_windows)
        items += sub("WMI subscriptions", wmi_subscriptions_windows)
        items += sub("Winlogon shell", winlogon_shell_windows)
    else:
        items += sub("cron", cron_linux)
        items += sub("systemd units", systemd_linux)
        items += sub("shell startup files", shell_rc_linux)
    items += sub("authorised SSH keys", ssh_authorized_keys)
    return items


# ──────────────────────────────────────────────────────────────
# Execution-trace forensics
# ──────────────────────────────────────────────────────────────

# The fingerprints of a paste-and-run payload, shared across platforms.
# Each is a fetch, a decode, or a direct-execute that legitimate interactive
# use almost never combines in a single line.
PAYLOAD_MARKERS = (
    ("iex", "pipes downloaded text straight into execution"),
    ("invoke-expression", "executes a string as code"),
    ("downloadstring", "fetches remote content into memory"),
    ("downloadfile", "downloads a file to disk"),
    ("frombase64string", "decodes a base64 blob"),
    ("-enc", "runs a base64-encoded command, hiding its content"),
    ("-encodedcommand", "runs a base64-encoded command, hiding its content"),
    ("-w hidden", "runs with no visible window"),
    ("-windowstyle hidden", "runs with no visible window"),
    ("bitsadmin", "uses the transfer service to download"),
    ("certutil", "the certificate tool used to fetch or decode"),
    ("mshta", "runs remote script through the HTML host"),
    ("curl ", "downloads content"),
    ("wget ", "downloads content"),
    ("/dev/tcp/", "opens a raw network socket from the shell"),
    ("base64 -d", "decodes a base64 blob"),
    ("base64 --decode", "decodes a base64 blob"),
    ("| sh", "pipes fetched content into a shell"),
    ("|sh", "pipes fetched content into a shell"),
    ("| bash", "pipes fetched content into a shell"),
    ("|bash", "pipes fetched content into a shell"),
)




def _e_entry(kind: str, name: str, value: str, source: str,
           risk: str = "warn") -> dict:
    return {"kind": kind, "name": name, "value": value,
            "source": source, "risk": risk}


def _score(command: str) -> tuple[int, list[str]]:
    """How many payload markers a command contains, and which.

    One marker may be innocent; several together are the signature of a
    fetch-decode-execute one-liner that no one types by hand.
    """
    low = command.lower()
    hits = [why for token, why in PAYLOAD_MARKERS if token in low]
    # de-duplicate reasons while keeping order
    seen, unique = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return len(unique), unique


# ─────────────────────── Windows ───────────────────────

def run_box_history_windows() -> list[dict]:
    """The Win+R Run-box history — where a pasted ClickFix command lands.

    RunMRU records exactly what was typed or pasted into the Run dialog. A
    ClickFix victim's malicious one-liner sits here verbatim, often with long
    leading whitespace so the visible part looked like a harmless
    "verification ID" while the real command scrolled off-screen.
    """
    items = []
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    # reg query separates columns with exactly four spaces. Splitting on
    # whitespace ate the padding this check exists to find, so the test for
    # it could never fire. Everything past the separator is kept verbatim.
    row = re.compile(r"^\s*(\S+)\s+(REG_\w+)\s{4}(.*)$")
    for line in _sh(["reg", "query", key]).splitlines():
        m = row.match(line.rstrip("\n"))
        if not m:
            continue
        name, raw = m.group(1), m.group(3)
        # RunMRU appends a "\1" ordering suffix to every entry
        raw = raw.removesuffix("\\1")
        value = raw.strip()
        if not value:
            continue

        n, reasons = _score(value)
        lead = len(raw) - len(raw.lstrip())
        # Padding pushes the real command off the right of the Run box, so
        # the victim reads a short harmless-looking string and presses Enter.
        padded = lead > 8
        if n >= 1 or padded:
            risk = "critical" if (n >= 2 or padded) else "warn"
            if padded:
                reasons = [f"padded with {lead} spaces so the real command sat "
                           "off-screen in the Run box — a hallmark of ClickFix"
                           ] + reasons
            items.append(_e_entry("Run-box command", name,
                                  f"{value[:200]} — {'; '.join(reasons)}", key,
                                  risk=risk))
    return items


def powershell_log_windows() -> list[dict]:
    """PowerShell script-block log (event 4104) — what actually executed.

    This is the record that survives the process. Even a one-liner that ran
    and exited leaves its full text here, so a ClickFix payload is visible
    long after nothing is connected. Requires script-block logging, which is
    on by default from PowerShell 5.1.
    """
    items = []
    ps = (
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-"
        "PowerShell/Operational'; Id=4104} -MaxEvents 200 "
        "-ErrorAction SilentlyContinue | ForEach-Object "
        "{ $_.TimeCreated.ToString('s') + '|' + "
        "($_.Message -replace '\\s+',' ') }"
    )
    seen = set()
    for line in _sh(["powershell", "-NoProfile", "-Command", ps], timeout=45).splitlines():
        ts, _, msg = line.partition("|")
        n, reasons = _score(msg)
        if n < 2:
            continue          # need several markers to call it a payload
        # collapse near-duplicates so one script does not flood the report
        sig = msg[:80]
        if sig in seen:
            continue
        seen.add(sig)
        items.append(_e_entry("PowerShell execution", ts or "recent",
                            f"{msg[:200]} — {'; '.join(reasons[:3])}",
                            "event 4104", risk="critical"))
    return items


# ─────────────────────── Linux / Kali ───────────────────────

def shell_history_linux() -> list[dict]:
    """Shell history across every user — the terminal ClickFix equivalent.

    The macOS and Linux ClickFix variant lures the user into a curl-pipe-bash
    line in a terminal instead of the Run box. Whatever they pasted stays in
    the shell history file, so it is recoverable after the shell has closed.
    """
    items = []
    pass  # (relative import removed when merging)
    hist_files = (".bash_history", ".zsh_history", ".sh_history",
                  ".local/share/fish/fish_history")
    for home in all_homes():
        for name in hist_files:
            path = os.path.join(home, name)
            try:
                with open(path, errors="replace") as f:
                    lines = f.readlines()
            except Exception:
                continue
            for i, raw in enumerate(lines[-500:], 1):
                cmd = raw.strip()
                if not cmd or cmd.startswith("#"):
                    continue
                n, reasons = _score(cmd)
                if n < 2:
                    continue
                items.append(_e_entry(
                    "Shell command", f"{os.path.basename(name)}",
                    f"{cmd[:200]} — {'; '.join(reasons[:3])}",
                    path, risk="critical"))
    return items


def recent_downloads_linux() -> list[dict]:
    """Executables freshly written to temp and download directories.

    A fetch-and-run payload usually stages its second stage in /tmp or the
    user's Downloads folder before executing it. A recently created,
    executable file there is not proof of anything, but paired with a
    matching history line it completes the picture.
    """
    items = []
    pass  # (relative import removed when merging)
    import time
    now = time.time()
    dirs = ["/tmp", "/dev/shm", "/var/tmp"]
    for home in all_homes():
        dirs.append(os.path.join(home, "Downloads"))
    for d in dirs:
        try:
            entries = os.scandir(d)
        except Exception:
            continue
        for e in entries:
            try:
                if not e.is_file():
                    continue
                st = e.stat()
                # executable bit set and created within the last day
                if not (st.st_mode & 0o111):
                    continue
                if now - st.st_mtime > 86400:
                    continue
            except Exception:
                continue
            items.append(_e_entry(
                "Recent executable", e.name,
                f"executable file written to {d} within the last day",
                e.path, risk="warn"))
    return items


def clipboard_hint_linux() -> list[dict]:
    """A best-effort peek at the clipboard for a poisoned command sitting ready.

    If the user has reached a ClickFix page but not yet pasted, the malicious
    command may still be on the clipboard. Needs xclip/xsel/wl-paste and a
    graphical session, so its absence is normal rather than a failure.
    """
    items = []
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return items
    import shutil
    for tool, args in (("xclip", ["xclip", "-selection", "clipboard", "-o"]),
                       ("xsel", ["xsel", "--clipboard", "--output"]),
                       ("wl-paste", ["wl-paste", "--no-newline"])):
        if not shutil.which(tool):
            continue
        content = _sh(args, timeout=5)
        if content:
            score, why = _score(content)
            if score >= 1:
                items.append(_e_entry(
                    "Clipboard contents", "current clipboard",
                    f"{content[:180]}  —  {', '.join(why[:3])}",
                    f"clipboard via {tool}", risk="critical"))
        break
    return items


def scan_exectrace(errors: list[str] | None = None) -> list[dict]:
    """All execution-trace checks available on this system."""
    def sub(label: str, fn) -> list[dict]:
        """A failing sub-check becomes a reported gap, not a shorter list."""
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = []
    if IS_WINDOWS:
        items += sub("Run box history", run_box_history_windows)
        items += sub("PowerShell log", powershell_log_windows)
    else:
        items += sub("shell history", shell_history_linux)
        items += sub("recent downloads", recent_downloads_linux)
        items += sub("clipboard", clipboard_hint_linux)
    return items


# ──────────────────────────────────────────────────────────────
# Dormant doors and protection settings
# ──────────────────────────────────────────────────────────────

# Accessibility binaries that run as SYSTEM on the login screen
ACCESSIBILITY_BINARIES = (
    "sethc.exe",        # Sticky Keys — five Shift presses
    "utilman.exe",      # Utility Manager — Win+U
    "osk.exe",          # On-screen keyboard
    "magnify.exe",      # Magnifier
    "displayswitch.exe",
    "atbroker.exe",
    "narrator.exe",
)

SHELL_BINARIES = ("cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe")




def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _h_entry(kind: str, name: str, value: str, source: str,
           risk: str = "info") -> dict:
    return {"kind": kind, "name": name, "value": value,
            "source": source, "risk": risk}


# ─────────────────────── Windows ───────────────────────

def sticky_keys_windows() -> list[dict]:
    """Compares accessibility binary hashes against shell binary hashes.

    A match means the file was replaced with a terminal: SYSTEM access from
    the lock screen with no password. We also check IFEO debugger keys,
    which achieve the same thing without modifying any file, leaving size
    and signature intact.
    """
    items = []
    sys32 = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")

    shell_hashes = {}
    for s in SHELL_BINARIES:
        h = _sha256(os.path.join(sys32, s))
        if h:
            shell_hashes[h] = s

    for exe in ACCESSIBILITY_BINARIES:
        path = os.path.join(sys32, exe)
        h = _sha256(path)
        if not h:
            continue
        if h in shell_hashes:
            items.append(_h_entry(
                "Sticky Keys backdoor", exe,
                f"byte-identical to {shell_hashes[h]} — replaced with a shell",
                path, risk="critical"))

    # Second route: an IFEO debugger runs a different program in its place
    ifeo = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\Image File Execution Options")
    for exe in ACCESSIBILITY_BINARIES + SHELL_BINARIES:
        out = _sh(["reg", "query", f"{ifeo}\\{exe}", "/v", "Debugger"])
        for line in out.splitlines():
            if "Debugger" in line and "REG_" in line:
                val = line.split(None, 2)[-1].strip()
                items.append(_h_entry(
                    "IFEO debugger", exe,
                    f"runs {val} instead of the original program",
                    f"{ifeo}\\{exe}", risk="critical"))
    return items


def rdp_settings_windows() -> list[dict]:
    """Remote Desktop state: enabled? protected by NLA? on which port?"""
    items = []
    ts = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
    rdp = ts + r"\WinStations\RDP-Tcp"

    def val(key: str, name: str) -> str:
        for line in _sh(["reg", "query", key, "/v", name]).splitlines():
            if name.lower() in line.lower() and "REG_" in line:
                return line.split(None, 2)[-1].strip()
        return ""

    deny = val(ts, "fDenyTSConnections")
    if deny and deny.lower() in ("0x0", "0"):
        items.append(_h_entry("RDP enabled", "fDenyTSConnections", "incoming sessions allowed",
                            ts, risk="warn"))
        nla = val(rdp, "UserAuthentication")
        if nla and nla.lower() in ("0x0", "0"):
            # Without NLA anyone reaches the login screen before authenticating,
            # which is precisely what makes Sticky Keys remotely exploitable
            items.append(_h_entry(
                "Network Level Authentication disabled", "UserAuthentication",
                "login screen reachable without authenticating — the Sticky Keys precondition",
                rdp, risk="critical"))

        port = val(rdp, "PortNumber")
        if port and port.lower() not in ("0xd3d", "3389"):
            items.append(_h_entry("non-standard RDP port", "PortNumber", port,
                                rdp, risk="warn"))
    return items


def local_accounts_windows() -> list[dict]:
    """Local accounts and their privileges — the simplest overlooked backdoor."""
    items = []
    ps = (
        "Get-LocalUser | ForEach-Object { $_.Name + '|' + $_.Enabled + '|' + "
        "$_.LastLogon + '|' + $_.Description }")
    users = {}
    for line in _sh(["powershell", "-NoProfile", "-Command", ps], timeout=40).splitlines():
        p = line.split("|")
        if len(p) >= 2:
            users[p[0].strip()] = {"enabled": p[1].strip(),
                                   "last": p[2].strip() if len(p) > 2 else "",
                                   "desc": p[3].strip() if len(p) > 3 else ""}

    for group, risk in (("Administrators", "warn"), ("Remote Desktop Users", "warn")):
        ps2 = (f"Get-LocalGroupMember -Group '{group}' -ErrorAction "
               "SilentlyContinue | ForEach-Object { $_.Name }")
        for line in _sh(["powershell", "-NoProfile", "-Command", ps2],
                         timeout=40).splitlines():
            name = line.strip()
            if not name:
                continue
            short = name.split("\\")[-1]
            # An account ending in $ is hidden from the login screen and user lists
            hidden = short.endswith("$")
            items.append(_h_entry(
                f"member of {group}", short,
                ("hidden from the login screen" if hidden
                 else users.get(short, {}).get("desc", "") or "local account"),
                group, risk="critical" if hidden else risk))

    for name, info in users.items():
        if name.endswith("$"):
            items.append(_h_entry("hidden account", name,
                                "name ends in $, so it does not appear at login",
                                "Get-LocalUser", risk="critical"))
    return items


def defender_status_windows() -> list[dict]:
    """Tampering precedes nearly every attack — exclusions are the quietest way."""
    items = []
    ps = ("$p = Get-MpPreference; $s = Get-MpComputerStatus; "
          "'RT|' + $s.RealTimeProtectionEnabled; "
          "'TP|' + $s.IsTamperProtected; "
          "$p.ExclusionPath | ForEach-Object { 'EX|' + $_ }; "
          "$p.ExclusionProcess | ForEach-Object { 'EP|' + $_ }")
    for line in _sh(["powershell", "-NoProfile", "-Command", ps], timeout=45).splitlines():
        tag, _, val = line.partition("|")
        tag, val = tag.strip(), val.strip()
        if tag == "RT" and val.lower() == "false":
            items.append(_h_entry("real-time protection disabled", "RealTimeProtection",
                                "Defender is scanning nothing right now", "Defender",
                                risk="critical"))
        elif tag == "TP" and val.lower() == "false":
            items.append(_h_entry("tamper protection disabled", "TamperProtection",
                                "any admin can disable Defender programmatically",
                                "Defender", risk="warn"))
        elif tag == "EX" and val:
            low = val.lower()
            broad = low.rstrip("\\").endswith(":") or low in ("c:\\", "/")
            risky = any(h in low for h in ("\\temp", "\\downloads", "\\appdata",
                                           "\\programdata", "\\users\\public"))
            items.append(_h_entry(
                "Defender exclusion", val,
                ("whole-drive exclusion — effectively disables protection" if broad else
                 "a path commonly used to stage payloads" if risky else
                 "path excluded from scanning"),
                "ExclusionPath",
                risk="critical" if (broad or risky) else "warn"))
        elif tag == "EP" and val:
            items.append(_h_entry("excluded process", val,
                                "this process is never scanned",
                                "ExclusionProcess", risk="warn"))
    return items


def smartscreen_windows() -> list[dict]:
    items = []
    checks = [
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
         "EnableSmartScreen", ("0x0", "0"), "SmartScreen disabled by policy"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
         "SmartScreenEnabled", ("off",), "SmartScreen turned off"),
    ]
    for key, name, bad, label in checks:
        for line in _sh(["reg", "query", key, "/v", name]).splitlines():
            if name.lower() in line.lower() and "REG_" in line:
                val = line.split(None, 2)[-1].strip().lower()
                if val in bad:
                    items.append(_h_entry("protection disabled", label, val, key,
                                        risk="warn"))
    return items


# ─────────────────────── Linux ───────────────────────

def accounts_linux() -> list[dict]:
    """Root-privileged or passwordless accounts, and sudoers additions."""
    items = []
    try:
        with open("/etc/passwd", errors="replace") as f:
            for line in f:
                p = line.strip().split(":")
                if len(p) < 7:
                    continue
                name, uid, shell = p[0], p[2], p[6]
                # Any UID 0 account other than root is a second root by definition
                if uid == "0" and name != "root":
                    items.append(_h_entry(
                        "root-privileged account", name,
                        f"UID 0, identical to root (shell: {shell})",
                        "/etc/passwd", risk="critical"))
    except Exception:
        pass

    try:
        with open("/etc/shadow", errors="replace") as f:
            for line in f:
                p = line.split(":")
                if len(p) > 1 and p[1] == "" :
                    items.append(_h_entry("passwordless account", p[0],
                                        "can be logged into without authenticating",
                                        "/etc/shadow", risk="critical"))
    except Exception:
        pass      # requires root; its absence is not an error

    for path in ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*")):
        try:
            with open(path, errors="replace") as f:
                for i, line in enumerate(f, 1):
                    s = line.strip()
                    if s.startswith("#") or not s:
                        continue
                    if "NOPASSWD" in s and "ALL" in s:
                        items.append(_h_entry(
                            "passwordless sudo", f"{os.path.basename(path)}:{i}",
                            s[:160], path, risk="warn"))
        except Exception:
            pass
    return items


def ssh_config_linux() -> list[dict]:
    """SSH settings that leave the door wide open."""
    items = []
    risky = {
        "permitrootlogin": (("yes", "without-password", "prohibit-password"),
                            "direct root login is permitted"),
        "passwordauthentication": (("yes",),
                                   "password login allowed — open to guessing"),
        "permitemptypasswords": (("yes",), "empty passwords are accepted"),
        "gatewayports": (("yes", "clientspecified"),
                         "allows reverse tunnels to be published to the network"),
        "allowtcpforwarding": (("yes",), "port forwarding allowed — enables tunnels"),
    }
    paths = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*"))
    for path in paths:
        try:
            with open(path, errors="replace") as f:
                for i, line in enumerate(f, 1):
                    s = line.strip()
                    if s.startswith("#") or not s:
                        continue
                    parts = s.split(None, 1)
                    if len(parts) != 2:
                        continue
                    k, v = parts[0].lower(), parts[1].strip().lower()
                    if k in risky and v in risky[k][0]:
                        sev = "critical" if k in ("permitemptypasswords",) else "warn"
                        items.append(_h_entry("SSH setting", f"{parts[0]} {parts[1]}",
                                            risky[k][1], f"{path}:{i}", risk=sev))
        except Exception:
            pass
    return items


def scan_hardening(errors: list[str] | None = None) -> list[dict]:
    """Every static-state check available on this system."""
    def sub(label: str, fn) -> list[dict]:
        """A failing sub-check becomes a reported gap, not a shorter list."""
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = []
    if IS_WINDOWS:
        items += sub("Sticky Keys", sticky_keys_windows)
        items += sub("RDP settings", rdp_settings_windows)
        items += sub("local accounts", local_accounts_windows)
        items += sub("Defender status", defender_status_windows)
        items += sub("SmartScreen", smartscreen_windows)
    else:
        items += sub("accounts", accounts_linux)
        items += sub("SSH configuration", ssh_config_linux)
    return items


# ──────────────────────────────────────────────────────────────
# Known-vulnerable remote-access versions
# ──────────────────────────────────────────────────────────────

# Compiled: 2026-08. Each entry is (fixed_version, CVE, severity, summary).
# `below` means every build strictly older than this string is affected.
KNOWN_VULNERABLE = {
    "SimpleHelp": [
        {"below": "5.5.16", "cve": "CVE-2026-48558", "severity": "critical",
         "note": "OIDC authentication bypass. An unauthenticated attacker can "
                 "create a Technician account and remote into every managed "
                 "endpoint, bypassing MFA. In CISA's Known Exploited "
                 "Vulnerabilities catalogue."},
        {"below": "5.5.8", "cve": "CVE-2024-57727", "severity": "critical",
         "note": "Path traversal exposing serverconfig.xml, which holds "
                 "hashed admin and technician passwords. Chained with "
                 "CVE-2024-57726 (privilege escalation) and CVE-2024-57728 "
                 "(arbitrary file upload). Used by ransomware operators."},
    ],
    "ScreenConnect": [
        {"below": "25.2.4", "cve": "CVE-2025-3935", "severity": "critical",
         "note": "ViewState code injection allowing arbitrary code execution "
                 "on the server. Multiple threat groups exploited it while "
                 "unpatched instances remained widespread."},
        {"below": "23.9.8", "cve": "CVE-2024-1709", "severity": "critical",
         "note": "Authentication bypass giving full administrative access. "
                 "Mass-exploited within days of disclosure."},
    ],
    "BeyondTrust Remote Support": [
        {"below": "24.3.1", "cve": "CVE-2024-12356", "severity": "critical",
         "note": "Command injection. Exploited against government targets."},
    ],
}

# ScreenConnect Client is the same product under a different process name
KNOWN_VULNERABLE["ScreenConnect Client"] = KNOWN_VULNERABLE["ScreenConnect"]
KNOWN_VULNERABLE["ConnectWise Control"] = KNOWN_VULNERABLE["ScreenConnect"]

DATA_DATE = "2026-08"

VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")


def parse_version(text: str) -> tuple[int, ...] | None:
    """Pulls a dotted version out of arbitrary text."""
    m = VERSION_RE.search(text or "")
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compares versions of differing length by zero-padding the shorter."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _safe_to_execute(path: str) -> bool:
    """May we run this binary just to ask its version?

    Only if the system vouches for it: owned by root, not writable by anyone
    else, and living in a package-managed directory. Anything the user or an
    attacker could have placed is read about, never run.
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    if st.st_uid != 0:
        return False
    if st.st_mode & 0o022:          # group- or world-writable
        return False
    low = path.lower()
    return any(low.startswith(p) for p in
               ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
                "/bin/", "/sbin/", "/opt/", "/snap/"))


def _package_version(path: str) -> str:
    """Asks the package manager which version owns this file. Never executes it."""
    for query, fmt in ((["dpkg", "-S", path], "dpkg"), (["rpm", "-qf", path], "rpm")):
        try:
            r = subprocess.run(query, capture_output=True, text=True,
                               timeout=8, errors="replace")
        except Exception:
            continue
        out = (r.stdout or "").strip()
        if r.returncode != 0 or not out:
            continue
        if fmt == "dpkg":
            pkg = out.split(":")[0].strip()
            if not pkg:
                continue
            try:
                v = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Version}", pkg],
                    capture_output=True, text=True, timeout=8, errors="replace")
                if v.returncode == 0 and (v.stdout or "").strip():
                    return v.stdout.strip()
            except Exception:
                continue
        else:
            return out          # rpm -qf already prints name-version-release
    return ""


def file_version(path: str) -> str:
    """Reads the version of an executable without trusting it.

    Windows keeps the version in the PE resource block, so it is read, never
    run. On Linux there is no equivalent block; the package manager is asked
    first, and the binary itself is only invoked when the system vouches for
    it (see _safe_to_execute). Running an unverified executable to find out
    whether it is malicious would hand it exactly what it wants.

    An empty result is normal and means "unknown", never "safe".
    """
    if not path or not os.path.exists(path):
        return ""

    if IS_WINDOWS:
        # The path travels in the environment, not in the command text, so a
        # filename containing quotes cannot break out and run its own code.
        ps = ("(Get-Item -LiteralPath $env:MAXPORT_TARGET)"
              ".VersionInfo.FileVersion")
        try:
            env = dict(os.environ, MAXPORT_TARGET=path)
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=20, env=env,
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW)
            return (r.stdout or "").strip()
        except Exception:
            return ""

    pkg = _package_version(path)
    if pkg and VERSION_RE.search(pkg):
        return pkg

    if not _safe_to_execute(path):
        return ""

    for flag in ("--version", "-version", "-v"):
        try:
            r = subprocess.run([path, flag], capture_output=True, text=True,
                               timeout=6, errors="replace")
            out = (r.stdout or "") + (r.stderr or "")
            if VERSION_RE.search(out):
                return out.strip().splitlines()[0][:120]
        except Exception:
            continue
    return ""


def check(tool: str, exe: str) -> dict | None:
    """Returns vulnerability details if this build has a known exploited flaw.

    Returns None both when the tool is patched and when the version could not
    be read. Those two cases are genuinely different, so callers that need to
    distinguish them should call file_version() themselves rather than
    treating None as proof of safety.
    """
    entries = KNOWN_VULNERABLE.get(tool)
    if not entries:
        return None

    raw = file_version(exe)
    current = parse_version(raw)
    if not current:
        return None

    for entry in entries:
        fixed = parse_version(entry["below"])
        if fixed and _cmp(current, fixed) < 0:
            return {
                "tool": tool,
                "version": ".".join(str(x) for x in current),
                "fixed_in": entry["below"],
                "cve": entry["cve"],
                "severity": entry["severity"],
                "note": entry["note"],
            }
    return None


def advisory_note() -> str:
    return (f"Vulnerability data compiled {DATA_DATE}. A clean result means "
            "no match in this list, not that the software is current — "
            "check the vendor's advisories for anything newer.")


# ──────────────────────────────────────────────────────────────
# Abused signed system binaries
# ──────────────────────────────────────────────────────────────

# Binary -> (what it is for, how it gets abused)
NETWORK_CAPABLE = {
    "certutil.exe": ("certificate utility",
                     "downloads arbitrary files and decodes base64 payloads"),
    "bitsadmin.exe": ("background transfer service",
                      "downloads files and can run one on completion"),
    "curl.exe": ("HTTP client",
                 "downloads payloads while looking like normal traffic"),
    "esentutl.exe": ("database utility",
                     "copies files from remote shares"),
    "finger.exe": ("user lookup utility",
                   "used as a covert download and exfiltration channel"),
    "expand.exe": ("archive expander", "fetches files from remote paths"),
    "makecab.exe": ("cabinet packer", "packs data for exfiltration"),
    "replace.exe": ("file replacement tool", "copies files from remote shares"),
    "hh.exe": ("help viewer", "opens remote help files containing script"),
    "msiexec.exe": ("installer",
                    "installs a package straight from a remote URL"),
    "wget.exe": ("HTTP client", "downloads payloads"),
}

EXECUTION_CAPABLE = {
    "mshta.exe": ("HTML application host",
                  "runs script from a file or a remote URL"),
    "rundll32.exe": ("DLL entry point runner",
                     "runs code inside a signed, trusted process"),
    "regsvr32.exe": ("COM registration tool",
                     "runs remote script without writing to disk"),
    "wscript.exe": ("script host", "runs VBScript and JScript"),
    "cscript.exe": ("console script host", "runs scripts without a window"),
    "installutil.exe": (".NET installer", "runs .NET code bypassing controls"),
    "regasm.exe": (".NET assembly registration", "runs .NET code"),
    "regsvcs.exe": (".NET services tool", "runs .NET code"),
    "msbuild.exe": ("build tool", "compiles and runs code from a project file"),
    "cmstp.exe": ("connection manager profile installer",
                  "runs script from an INF file, bypassing prompts"),
    "forfiles.exe": ("file iteration tool", "runs a command per matched file"),
    "pcalua.exe": ("compatibility assistant", "launches another program"),
    "conhost.exe": ("console host", "used to launch a hidden process"),
    "scriptrunner.exe": ("script runner", "runs an arbitrary command"),
    "wmic.exe": ("WMI command line",
                 "runs commands locally or on a remote machine"),
    "odbcconf.exe": ("ODBC configuration tool", "loads and runs a DLL"),
    "xwizard.exe": ("wizard host", "loads a remote COM object"),
}

# A parent that has no business launching a network program at all
NEVER_A_PARENT = (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "onenote.exe", "msaccess.exe",
)

ALL = {**NETWORK_CAPABLE, **EXECUTION_CAPABLE}


def identify(proc_name: str) -> tuple[str, str] | None:
    """Returns (purpose, abuse) if this is a known abusable system binary."""
    n = (proc_name or "").lower()
    if not n.endswith(".exe"):
        n += ".exe"
    return ALL.get(n)


def is_network_capable(proc_name: str) -> bool:
    n = (proc_name or "").lower()
    if not n.endswith(".exe"):
        n += ".exe"
    return n in NETWORK_CAPABLE


def assess(proc_name: str, cmdline: str, ancestry: str,
           has_connection: bool) -> dict | None:
    """Judges whether this binary is being used outside its purpose.

    Presence is never the finding. What matters is context: is it holding a
    network connection it has no reason to hold, was it launched by a
    document, or is its command line carrying a URL?
    """
    info = identify(proc_name)
    if not info:
        return None
    purpose, abuse = info

    low = (cmdline or "").lower()
    anc = (ancestry or "").lower()
    reasons, severity = [], "warn"

    if any(p in anc for p in NEVER_A_PARENT):
        parent = next(p for p in NEVER_A_PARENT if p in anc)
        reasons.append(f"launched by {parent}, which never legitimately "
                       "starts a system utility")
        severity = "critical"

    if has_connection and is_network_capable(proc_name):
        reasons.append("holding a live network connection, which is how this "
                       "binary is used to fetch a payload")
        severity = "critical"
    elif has_connection:
        reasons.append("holding a network connection, which is outside its purpose")

    if any(u in low for u in ("http://", "https://", "ftp://", "\\\\")):
        reasons.append("a remote address appears in its command line")
        severity = "critical"

    if any(f in low for f in ("-decode", "/decode", "-urlcache", "/urlcache",
                              "frombase64", "-enc", "-encodedcommand")):
        reasons.append("using flags associated with fetching or decoding payloads")
        severity = "critical"

    if not reasons:
        return None      # present and idle is normal, not a finding

    return {
        "binary": proc_name,
        "purpose": purpose,
        "abuse": abuse,
        "reasons": reasons,
        "severity": severity,
    }


# ──────────────────────────────────────────────────────────────
# Machine profiles
# ──────────────────────────────────────────────────────────────

DESKTOP = "desktop"
SECURITY = "security"

# Files present on offensive distributions and almost nowhere else
KALI_MARKERS = (
    "/etc/os-release",          # checked for content, see detect()
    "/usr/share/kali-menu",
    "/usr/share/metasploit-framework",
    "/etc/kali_version",
)

PARROT_MARKERS = ("/usr/share/parrot-menu", "/etc/parrot_version")

# Tooling expected on a security workstation. Its presence is not a finding
# there; the same names on an ordinary machine remain one.
EXPECTED_TOOLS = {
    "chisel", "frpc", "frps", "gost", "iodine", "dnscat2", "socat",
    "ncat", "nc", "netcat", "proxychains", "proxychains4", "sshuttle",
    "msfconsole", "msfvenom", "ruby", "responder", "bettercap",
    "ettercap", "mitmproxy", "mitmdump", "burpsuite", "zaproxy",
    "empire", "sliver", "sliver-client", "havoc", "villain",
    "ligolo", "ligolo-ng", "revsocks", "pwncat", "evil-winrm",
}

# Ports these tools habitually listen on during normal work
EXPECTED_PORTS = {4444, 4445, 5555, 8080, 8081, 8443, 1080, 9050, 9051,
                  1337, 31337, 4443, 8000, 8888}


def detect() -> str:
    """Identifies the machine profile from what the system actually is."""
    if platform.system() == "Windows":
        return DESKTOP

    for marker in PARROT_MARKERS:
        if os.path.exists(marker):
            return SECURITY
    for marker in KALI_MARKERS[1:]:
        if os.path.exists(marker):
            return SECURITY

    try:
        with open("/etc/os-release", errors="replace") as f:
            content = f.read().lower()
        if any(d in content for d in ("kali", "parrot", "blackarch",
                                      "pentoo", "athena")):
            return SECURITY
    except Exception:
        pass

    # A stock install of several offensive tools is itself the signal
    found = sum(1 for t in ("msfconsole", "chisel", "responder", "bettercap",
                            "proxychains", "sqlmap", "hydra")
                if shutil.which(t))
    return SECURITY if found >= 3 else DESKTOP


# Names are matched as whole tokens, never as substrings. The list contains
# "nc", and a substring test made it match any text containing those two
# letters — "ScreenConnect", "VNC", "unencrypted", a path with "Sync" in it.
# The effect was the exact opposite of the intent: real remote-control
# findings were downgraded on precisely the machines this module targets.
_TOKEN_SPLIT = re.compile(r"[^a-z0-9+]+")


def _tokens(text: str) -> set[str]:
    """Words in a string, lowercased, punctuation and separators removed."""
    return {t for t in _TOKEN_SPLIT.split((text or "").lower()) if t}


def is_expected(profile: str, name: str = "", port: int = 0) -> bool:
    """Is this tool or port ordinary for this kind of machine?"""
    if profile != SECURITY:
        return False
    if name:
        base = os.path.basename(name).lower().removesuffix(".exe")
        if base in EXPECTED_TOOLS:
            return True
        # A path such as /usr/share/sliver/sliver-server: match on any
        # component, still as a whole token.
        if _tokens(base) & EXPECTED_TOOLS:
            return True
    return bool(port) and port in EXPECTED_PORTS


# Categories where "expected on this machine" is never a sufficient
# explanation, so they keep their severity on every profile.
NEVER_DOWNGRADED = {"Remote control", "Hijacked tool", "Vulnerable version",
                    "Silent install"}

NOTE = ("Downgraded: expected on a security workstation. Reviewed rather "
        "than hidden, because an intruder would happily hide behind exactly "
        "these tools.")


def adjust(findings: list, profile: str) -> tuple[list, int]:
    """Downgrades findings that are routine for this profile.

    Returns (findings, count downgraded). Nothing is removed: severity drops
    and a note is appended, so the finding stays on screen and the user can
    still judge it.
    """
    if profile != SECURITY:
        return findings, 0

    lowered = 0
    for f in findings:
        # Some categories are never routine, whatever the machine is. A live
        # commercial remote-control session or a hijacked tool means someone
        # is on the machine now; "the owner runs offensive tooling" explains
        # neither, and downgrading them defeats the purpose of the scan.
        if f.category in NEVER_DOWNGRADED:
            continue

        name = ""
        for key in ("Process", "Program", "Path"):
            if f.evidence.get(key):
                name = f.evidence[key]
                break
        # The tunnel category carries the tool name in the title instead
        hit = bool(_tokens(f"{name} {f.title}") & EXPECTED_TOOLS)

        if not hit and f.port:
            hit = f.port in EXPECTED_PORTS

        if hit and f.severity == "critical":
            f.severity = "warn"
            f.detail += " " + NOTE
            lowered += 1
        elif hit and f.severity == "warn":
            f.severity = "info"
            f.detail += " " + NOTE
            lowered += 1
    return findings, lowered


# ──────────────────────────────────────────────────────────────
# Historical record
# ──────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    raddr TEXT, rport INTEGER,
    lport INTEGER, proto TEXT, status TEXT,
    pid INTEGER, pname TEXT, exe TEXT, sha256 TEXT,
    tool TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);
CREATE INDEX IF NOT EXISTS idx_obs_raddr ON observations(raddr);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    severity TEXT, category TEXT, title TEXT,
    detail TEXT, evidence TEXT
);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    action TEXT, target TEXT, ok INTEGER, message TEXT
);

CREATE TABLE IF NOT EXISTS baseline (
    key TEXT PRIMARY KEY,
    first_seen REAL, last_seen REAL, count INTEGER,
    approved INTEGER DEFAULT 0,
    note TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    severity TEXT, kind TEXT, title TEXT, detail TEXT,
    key TEXT, ip TEXT, port INTEGER, pid INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ev_ts ON events(ts);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

# Columns added after the first release, applied to existing databases
MIGRATIONS = [
    ("baseline", "note", "TEXT DEFAULT ''"),
]


def _real_home() -> str:
    """The home of the person running the tool, not of root.

    Under sudo or pkexec, expanduser("~") resolves to /root with sudo -E
    keeping the user's HOME instead — so the database moved depending on how
    the tool was started. Two histories accumulated, the baseline was useless
    in both, and the elevated run left root-owned files that the ordinary run
    could no longer write.
    """
    for var in ("SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(var)
        if not val:
            continue
        try:
            import pwd
            rec = (pwd.getpwuid(int(val)) if var == "PKEXEC_UID"
                   else pwd.getpwnam(val))
            if rec.pw_dir and os.path.isdir(rec.pw_dir):
                return rec.pw_dir
        except Exception:
            continue
    return os.path.expanduser("~")


def _chown_to_real_user(path: str) -> None:
    """Hands ownership back, so a later unprivileged run can still write."""
    uid = os.environ.get("PKEXEC_UID")
    user = os.environ.get("SUDO_USER")
    if not uid and not user:
        return
    try:
        import pwd
        rec = pwd.getpwuid(int(uid)) if uid else pwd.getpwnam(user)
        os.chown(path, rec.pw_uid, rec.pw_gid)
    except Exception:
        pass


def default_path() -> str:
    if platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    else:
        base = os.path.join(_real_home(), ".local", "share")
    d = os.path.join(base, "MaxPort")
    os.makedirs(d, exist_ok=True)
    _chown_to_real_user(d)
    return os.path.join(d, "maxport.db")


class Store:
    """SQLite history, safe to share between threads.

    check_same_thread=False only removes sqlite3's own guard; it does not
    make the connection safe to use concurrently. Three threads reach this
    object — the interface, the scan worker and the monitor — so every
    statement is serialised through one lock. WAL keeps readers from
    blocking on the writer.
    """

    def __init__(self, path: str | None = None):
        self.path = path or default_path()
        self._lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False,
                                  timeout=15)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            try:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.execute("PRAGMA busy_timeout=15000")
            except sqlite3.Error:
                pass          # a read-only filesystem still works, just slower
            self.db.executescript(SCHEMA)
            self._migrate()
            self.db.commit()
        _chown_to_real_user(self.path)

    def _migrate(self) -> None:
        """Adds new columns to an old database instead of refusing to open it.

        Caller already holds the lock.
        """
        for table, column, decl in MIGRATIONS:
            cols = {r["name"] for r in
                    self.db.execute(f"PRAGMA table_info({table})").fetchall()}
            if column not in cols:
                self.db.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    # ---------------- observations ----------------

    def record(self, conns) -> None:
        with self._lock:
            now = time.time()
            rows = [(now, c.raddr, c.rport, c.lport, c.family, c.status,
                     c.proc.pid, c.proc.name, c.proc.exe, c.proc.sha256, c.tool)
                    for c in conns]
            self.db.executemany(
                "INSERT INTO observations (ts,raddr,rport,lport,proto,status,"
                "pid,pname,exe,sha256,tool) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            for c in conns:
                key = f"{c.proc.name}|{c.raddr}:{c.rport}" if c.raddr else \
                      f"{c.proc.name}|LISTEN:{c.lport}"
                self.db.execute(
                    "INSERT INTO baseline (key, first_seen, last_seen, count) "
                    "VALUES (?,?,?,1) ON CONFLICT(key) DO UPDATE SET "
                    "last_seen=excluded.last_seen, count=count+1", (key, now, now))
            self.db.commit()

        # ---------------- known-good list ----------------

    def approve(self, key: str, note: str = "") -> None:
        """Marks a behaviour as known so it stops raising alerts.

        Without it the tool shouts about the AnyDesk the user installed
        themselves on every scan, until they stop reading alerts entirely.
        """
        with self._lock:
            now = time.time()
            self.db.execute(
                "INSERT INTO baseline (key, first_seen, last_seen, count, approved, note) "
                "VALUES (?,?,?,0,1,?) ON CONFLICT(key) DO UPDATE SET "
                "approved=1, note=excluded.note", (key, now, now, note))
            self.db.commit()

    def unapprove(self, key: str) -> None:
        with self._lock:
            self.db.execute("UPDATE baseline SET approved=0 WHERE key=?", (key,))
            self.db.commit()

    def is_approved(self, key: str) -> bool:
        with self._lock:
            row = self.db.execute(
                "SELECT approved FROM baseline WHERE key=?", (key,)).fetchone()
            return bool(row and row["approved"])

    def approved_keys(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT key, note, last_seen FROM baseline WHERE approved=1 "
                "ORDER BY key").fetchall()
            return [dict(r) for r in rows]

        # ---------------- settings ----------------

    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self.db.execute(
                "SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO settings (key,value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            self.db.commit()

        # ---------------- monitoring events ----------------

    def log_event(self, ev) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO events (ts,severity,kind,title,detail,key,ip,port,pid) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ev.ts, ev.severity, ev.kind, ev.title, ev.detail, ev.key,
                 ev.ip, ev.port, ev.pid))
            self.db.commit()

    def recent_events(self, limit: int = 300) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def is_new(self, key: str, min_age_hours: int = 24) -> bool:
        """Is this behaviour new? New behaviour deserves a look."""
        with self._lock:
            row = self.db.execute(
                "SELECT first_seen FROM baseline WHERE key=?", (key,)).fetchone()
            if not row:
                return True
            return (time.time() - row["first_seen"]) < min_age_hours * 3600

    def peer_history(self, ip: str, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT ts,rport,pname,status FROM observations WHERE raddr=? "
                "ORDER BY ts DESC LIMIT ?", (ip, limit)).fetchall()
            return [dict(r) for r in rows]

    def top_peers(self, hours: int = 24, limit: int = 40) -> list[dict]:
        with self._lock:
            since = time.time() - hours * 3600
            rows = self.db.execute(
                "SELECT raddr, COUNT(*) n, MAX(ts) last, "
                "GROUP_CONCAT(DISTINCT pname) procs FROM observations "
                "WHERE ts>? AND raddr!='' GROUP BY raddr ORDER BY n DESC LIMIT ?",
                (since, limit)).fetchall()
            return [dict(r) for r in rows]

        # ---------------- findings and actions ----------------

    def save_findings(self, findings) -> None:
        with self._lock:
            now = time.time()
            self.db.executemany(
                "INSERT INTO findings (ts,severity,category,title,detail,evidence) "
                "VALUES (?,?,?,?,?,?)",
                [(now, f.severity, f.category, f.title, f.detail,
                  json.dumps(f.evidence, ensure_ascii=False)) for f in findings])
            self.db.commit()

    def log_action(self, action: str, target: str, ok: bool, message: str) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO actions (ts,action,target,ok,message) VALUES (?,?,?,?,?)",
                (time.time(), action, target, int(ok), message))
            self.db.commit()

    def recent_actions(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM actions ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def recent_findings(self, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM findings ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self.db.close()


# ──────────────────────────────────────────────────────────────
# Continuous monitoring
# ──────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────
# Response actions
# ──────────────────────────────────────────────────────────────

RULE_PREFIX = "MaxPort"


@dataclass
class ActionResult:
    ok: bool
    message: str






NFT_TABLE = RULE_PREFIX.lower()

# The project was renamed. These are the names a previous release used, kept
# only so its leftovers can be found and cleaned up — never written.
LEGACY_NAME = "NetGuard"
LEGACY_RULE_PREFIX = "NetGuard"
LEGACY_NFT_TABLE = "netguard"
LEGACY_WATCHDOG_UNIT = "netguard-isolate-revert"


def _ip_version(ip: str) -> int:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return 0


def _nft_set_for(ip: str) -> str:
    """Which set the address belongs in — IPv4 or IPv6."""
    v = _ip_version(ip)
    return {4: "blocked4", 6: "blocked6"}.get(v, "")


def _iptables_for(ip: str) -> str:
    """iptables handles IPv4 only; IPv6 needs ip6tables.

    Sending a v6 address to iptables fails, and a failure that only prints a
    message leaves the address reachable while the interface says "blocked".
    """
    return {4: "iptables", 6: "ip6tables"}.get(_ip_version(ip), "")


def _nft_ensure() -> None:
    """Creates the nft table with sets that support add and delete.

    Sets rather than individual rules, because removing an element from a
    set is direct, while deleting a rule means tracking its handle and
    breaks easily. Safe to call repeatedly — each command is a no-op if
    """
    # "nft add" is idempotent, so we no longer skip on an existing table: a
    # table left by an older version can be missing sets this version needs,
    # and the early return meant every later add silently failed.
    _sh_rc(["nft", "add", "table", "inet", NFT_TABLE])
    for name, typ in (("blocked4", "ipv4_addr"), ("blocked6", "ipv6_addr"),
                      ("closed_tcp", "inet_service"),
                      ("closed_udp", "inet_service")):
        _sh_rc(["nft", "add", "set", "inet", NFT_TABLE, name,
              "{ type " + typ + " ; flags interval ; }"])
    # Negative priority so these precede other system rules
    _sh_rc(["nft", "add", "chain", "inet", NFT_TABLE, "ngin",
          "{ type filter hook input priority -10 ; policy accept ; }"])
    _sh_rc(["nft", "add", "chain", "inet", NFT_TABLE, "ngout",
          "{ type filter hook output priority -10 ; policy accept ; }"])
    for chain, rule in (
        ("ngin", ["ip", "saddr", "@blocked4", "drop"]),
        ("ngin", ["ip6", "saddr", "@blocked6", "drop"]),
        ("ngout", ["ip", "daddr", "@blocked4", "drop"]),
        ("ngout", ["ip6", "daddr", "@blocked6", "drop"]),
        ("ngin", ["tcp", "dport", "@closed_tcp", "drop"]),
        ("ngin", ["udp", "dport", "@closed_udp", "drop"]),
    ):
        _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, chain] + rule)


def _firewall_backend() -> str:
    if IS_WINDOWS:
        return "netsh"
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables"):
        return "iptables"
    if shutil.which("ufw"):
        return "ufw"
    return ""


# ------------------------- stopping processes -------------------------

def _verify_identity(p: "psutil.Process", started: float, name: str) -> str:
    """Is this still the process the scan saw, or has the PID been recycled?

    A finding carries the PID as it was during the scan. The user may act on
    it minutes later, by which time the process can have exited and the
    kernel handed the number to something else — possibly something the
    system needs. Killing by a stale number as root is how a security tool
    becomes the incident, so identity is confirmed before anything is done.
    """
    if started:
        try:
            if abs(p.create_time() - started) > 1.0:
                return ("PID {} no longer belongs to that process — it exited "
                        "and the number was reused. Re-scan before acting."
                        ).format(p.pid)
        except Exception:
            return ""
    if name:
        try:
            if p.name() != name:
                return ("PID {} is now '{}', not '{}'. Re-scan before acting."
                        ).format(p.pid, p.name(), name)
        except Exception:
            return ""
    return ""


def stop_process(pid: int, force: bool = False,
                 started: float = 0.0, expect_name: str = "") -> ActionResult:
    """Stops a process. Graceful first, so no data is lost.

    started/expect_name come from the scan that produced the finding and are
    used to prove the PID still refers to the same process.
    """
    try:
        p = psutil.Process(pid)
        mismatch = _verify_identity(p, started, expect_name)
        if mismatch:
            return ActionResult(False, mismatch)
        name = p.name()
        p.kill() if force else p.terminate()
        try:
            p.wait(timeout=5)
        except psutil.TimeoutExpired:
            if not force:
                return ActionResult(False, f"{name} did not respond — use a forced stop")
        return ActionResult(True, f"Stopped {name} (PID {pid})")
    except psutil.NoSuchProcess:
        return ActionResult(True, "the process had already exited")
    except psutil.AccessDenied:
        return ActionResult(False, "Access denied — run as administrator")
    except Exception as e:
        return ActionResult(False, f"Could not stop it: {e}")


def suspend_process(pid: int, started: float = 0.0,
                    expect_name: str = "") -> ActionResult:
    """Freezes rather than kills — halts activity while preserving memory."""
    try:
        p = psutil.Process(pid)
        mismatch = _verify_identity(p, started, expect_name)
        if mismatch:
            return ActionResult(False, mismatch)
        p.suspend()
        return ActionResult(True, f"Froze {p.name()} — memory preserved for analysis")
    except psutil.AccessDenied:
        return ActionResult(False, "Access denied — run as administrator")
    except Exception as e:
        return ActionResult(False, f"Could not freeze it: {e}")


# ------------------------- blocking addresses -------------------------

def block_ip(ip: str) -> ActionResult:
    """Blocks the address in both directions at the firewall."""
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")
    backend = _firewall_backend()

    if backend == "netsh":
        for direction in ("in", "out"):
            code, out = _sh_rc([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={RULE_PREFIX}-Block-{ip}-{direction}",
                f"dir={direction}", "action=block", f"remoteip={ip}",
            ])
            if code != 0:
                return ActionResult(False, f"Block failed: {out.strip()[:160]}")
        return ActionResult(True, f"Blocked {ip} inbound and outbound")

    if backend == "nft":
        _nft_ensure()
        st = _nft_set_for(ip)
        if not st:
            return ActionResult(False, f"Not a valid address: {ip}")
        code, out = _sh_rc(["nft", "add", "element", "inet", NFT_TABLE, st,
                          "{ " + ip + " }"])
        return (ActionResult(True, f"Blocked {ip} inbound and outbound") if code == 0
                else ActionResult(False, out.strip()[:160]))

    if backend == "iptables":
        tool = _iptables_for(ip)
        if not tool:
            return ActionResult(False, f"Not a valid address: {ip}")
        if not shutil.which(tool):
            return ActionResult(
                False, f"{tool} is not installed — cannot block {ip}. "
                       "Without it the address stays reachable over IPv6.")
        c1, o1 = _sh_rc([tool, "-I", "INPUT", "-s", ip, "-j", "DROP"])
        c2, o2 = _sh_rc([tool, "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
        if c1 == 0 and c2 == 0:
            return ActionResult(True, f"Blocked {ip} — rule lasts until reboot")
        return ActionResult(False, (o1 + o2).strip()[:160])

    if backend == "ufw":
        code, out = _sh_rc(["ufw", "deny", "from", ip])
        return (ActionResult(True, f"Blocked {ip}") if code == 0
                else ActionResult(False, out.strip()[:160]))

    return ActionResult(False, "No supported firewall found")


def unblock_ip(ip: str) -> ActionResult:
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")
    backend = _firewall_backend()
    if backend == "netsh":
        for direction in ("in", "out"):
            _sh_rc(["netsh", "advfirewall", "firewall", "delete", "rule",
                  f"name={RULE_PREFIX}-Block-{ip}-{direction}"])
        return ActionResult(True, f"Unblocked {ip}")
    if backend == "nft":
        st = _nft_set_for(ip)
        if not st:
            return ActionResult(False, f"Not a valid address: {ip}")
        code, out = _sh_rc(["nft", "delete", "element", "inet", NFT_TABLE, st,
                          "{ " + ip + " }"])
        return (ActionResult(True, f"Unblocked {ip}") if code == 0
                else ActionResult(False, out.strip()[:160] or "the address was not blocked"))
    if backend == "iptables":
        tool = _iptables_for(ip)
        if not tool:
            return ActionResult(False, f"Not a valid address: {ip}")
        _sh_rc([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"])
        _sh_rc([tool, "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        return ActionResult(True, f"Unblocked {ip}")
    if backend == "ufw":
        _sh_rc(["ufw", "delete", "deny", "from", ip])
        return ActionResult(True, f"Unblocked {ip}")
    return ActionResult(False, "Unblocking is not supported on this system")


# ------------------------- closing ports -------------------------

def close_port(port: int, proto: str = "tcp", pid: int | None = None,
               started: float = 0.0, expect_name: str = "") -> ActionResult:
    """Closes a port at the firewall, optionally stopping the listener too."""
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")

    backend = _firewall_backend()
    notes = []

    if backend == "netsh":
        code, out = _sh_rc([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={RULE_PREFIX}-ClosePort-{port}", "dir=in", "action=block",
            f"protocol={proto.upper()}", f"localport={port}",
        ])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked inbound port {port}/{proto}")
    elif backend == "nft":
        _nft_ensure()
        code, out = _sh_rc(["nft", "add", "element", "inet", NFT_TABLE,
                          f"closed_{proto.lower()}", "{ " + str(port) + " }"])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked inbound port {port}/{proto}")
    elif backend == "iptables":
        code, out = _sh_rc(["iptables", "-I", "INPUT", "-p", proto,
                          "--dport", str(port), "-j", "DROP"])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked port {port}/{proto}")
    elif backend == "ufw":
        code, out = _sh_rc(["ufw", "deny", f"{port}/{proto}"])
        if code != 0:
            return ActionResult(False, out.strip()[:160])
        notes.append(f"Blocked port {port}/{proto}")
    else:
        return ActionResult(False, "No supported firewall found")

    if pid:
        res = stop_process(pid, started=started, expect_name=expect_name)
        notes.append(res.message)

    return ActionResult(True, " — ".join(notes))


# ------------------------- isolation -------------------------

_isolate_timer: "threading.Timer | None" = None
_isolate_deadline: float = 0.0

WATCHDOG_UNIT = "maxport-isolate-revert"
WATCHDOG_TASK = "MaxPort-IsolateRevert"


def _state_path() -> str:
    """Where the isolation state lives — beside the database, owned by root."""
    if IS_WINDOWS:
        base = os.environ.get("PROGRAMDATA") or os.path.expanduser("~")
    else:
        base = "/var/lib" if os.path.isdir("/var/lib") else os.path.expanduser("~")
    d = os.path.join(base, "MaxPort")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.expanduser("~")
    return os.path.join(d, "isolation.json")


def _write_state(deadline: float, keep_lan: bool) -> None:
    import json
    try:
        with open(_state_path(), "w", encoding="utf-8") as f:
            json.dump({"deadline": deadline, "keep_lan": keep_lan,
                       "pid": os.getpid()}, f)
    except Exception:
        pass


def _read_state() -> dict:
    import json
    try:
        with open(_state_path(), encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _clear_state() -> None:
    try:
        os.remove(_state_path())
    except Exception:
        pass


def _revert_shell_command() -> str:
    """The revert, expressed as one shell command an external scheduler can run.

    It must not depend on this program, its interpreter or its files, because
    the whole point is that it still fires when none of them are around.

    The former name is cleaned up alongside the current one. Renaming the
    project renamed the firewall rules and the nftables table, so a machine
    isolated by a version built under the old name would have been left with
    rules this code could no longer see — sealed, with the tool reporting
    nothing to lift.
    """
    if IS_WINDOWS:
        return " & ".join(
            f'netsh advfirewall firewall delete rule name={prefix}-Isolate-{d}'
            for prefix in (RULE_PREFIX, LEGACY_RULE_PREFIX)
            for d in ("in", "out"))
    backend = _firewall_backend()
    if backend == "nft":
        return "; ".join(
            f"nft delete chain inet {table} {chain}"
            for table in (NFT_TABLE, LEGACY_NFT_TABLE)
            for chain in ("ngiso", "ngisoin")) + "; true"
    parts = []
    for tool in ("iptables", "ip6tables"):
        for chain in ("OUTPUT", "INPUT"):
            parts.append(f"{tool} -D {chain} -j DROP")
    return "; ".join(parts) + "; true"


def _state_paths_legacy() -> list[str]:
    """Where a previous release under the old name kept its isolation state."""
    bases = []
    if IS_WINDOWS:
        bases.append(os.environ.get("PROGRAMDATA") or os.path.expanduser("~"))
    else:
        bases += ["/var/lib", os.path.expanduser("~")]
    return [os.path.join(b, LEGACY_NAME, "isolation.json")
            for b in bases if b]


def adopt_legacy_state() -> str:
    """Takes over isolation state written under the previous project name.

    Without this, upgrading while a machine is isolated strands it: the old
    state file is never read, so the automatic revert never happens and
    nothing reports that the machine is still cut off.
    """
    if _read_state():
        return ""
    for old in _state_paths_legacy():
        if not os.path.isfile(old):
            continue
        try:
            import json
            with open(old, encoding="utf-8") as f:
                data = json.load(f) or {}
            if data.get("deadline"):
                _write_state(float(data["deadline"]),
                             bool(data.get("keep_lan", True)))
                os.remove(old)
                return (f"Adopted isolation state left by an earlier version "
                        f"under the previous name ({LEGACY_NAME}).")
        except Exception:
            continue
    return ""


def _arm_watchdog(seconds: int) -> str:
    """Schedules the revert outside this process. Returns the mechanism used.

    An in-process timer is not a dead-man's switch: it dies with the man. If
    the application crashes, is killed, or the user closes it while isolated,
    the firewall rules stay and a machine reached remotely is lost for good.
    The scheduler is the only thing that survives that, so the in-process
    timer becomes the fast path and this becomes the guarantee.
    """
    cmd = _revert_shell_command()

    if IS_WINDOWS:
        when = time.localtime(time.time() + max(60, seconds))
        code, _ = _sh_rc([
            "schtasks", "/create", "/tn", WATCHDOG_TASK,
            "/tr", f'cmd /c "{cmd}"', "/sc", "once",
            "/st", time.strftime("%H:%M", when),
            "/sd", time.strftime("%d/%m/%Y", when),
            "/ru", "SYSTEM", "/rl", "HIGHEST", "/f",
        ])
        return "schtasks" if code == 0 else ""

    if shutil.which("systemd-run"):
        code, _ = _sh_rc([
            "systemd-run", "--collect", f"--unit={WATCHDOG_UNIT}",
            f"--on-active={max(5, seconds)}",
            "/bin/sh", "-c", cmd,
        ])
        if code == 0:
            return "systemd"

    if shutil.which("at"):
        mins = max(1, round(seconds / 60))
        try:
            p = subprocess.run(["at", f"now + {mins} minutes"],
                               input=cmd, capture_output=True, text=True,
                               timeout=15)
            if p.returncode == 0:
                return "at"
        except Exception:
            pass
    return ""


def _clear_legacy_rules() -> None:
    """Removes isolation rules a release under the previous name left behind.

    Silent by design: on the overwhelming majority of machines there is
    nothing to remove, and a message about a name the user never saw would
    only confuse. What matters is that the rules cannot outlive the rename.
    """
    if IS_WINDOWS:
        for d in ("in", "out"):
            _sh_rc(["netsh", "advfirewall", "firewall", "delete", "rule",
                  f"name={LEGACY_RULE_PREFIX}-Isolate-{d}"])
        return
    if _firewall_backend() == "nft":
        for chain in ("ngiso", "ngisoin"):
            _sh_rc(["nft", "delete", "chain", "inet", LEGACY_NFT_TABLE, chain])


def _disarm_watchdog() -> None:
    if IS_WINDOWS:
        _sh_rc(["schtasks", "/delete", "/tn", WATCHDOG_TASK, "/f"])
        return
    # The second name is what a release under the previous project
    # name registered; stopping it here keeps a rename from
    # stranding a scheduled revert.
    for unit in (WATCHDOG_UNIT, LEGACY_WATCHDOG_UNIT):
        _sh_rc(["systemctl", "stop", f"{unit}.timer"])
        _sh_rc(["systemctl", "stop", f"{unit}.service"])
        _sh_rc(["systemctl", "reset-failed", f"{unit}.service"])


def isolate_status() -> tuple[bool, int]:
    """(is isolation on a timer, seconds left before automatic revert)."""
    deadline = _isolate_deadline or _read_state().get("deadline", 0.0)
    if not deadline:
        return False, 0
    left = int(deadline - time.time())
    return (left > 0), max(0, left)


def resume_or_revert() -> ActionResult | None:
    """Called at startup: deals with isolation left behind by a previous run.

    If the deadline has passed while the program was not running, the machine
    is still isolated and nothing is going to lift it, so we lift it now. If
    time remains, the in-process timer is re-armed for the remainder.
    """
    global _isolate_timer, _isolate_deadline
    adopt_legacy_state()
    state = _read_state()
    deadline = state.get("deadline", 0.0)
    if not deadline:
        return None
    keep_lan = bool(state.get("keep_lan", True))
    left = deadline - time.time()

    if left <= 0:
        if not is_elevated():
            return ActionResult(
                False, "This machine was left isolated by an earlier run and "
                       "the revert is overdue. Restart with administrator/root "
                       "privileges to lift it.")
        res = _isolate_apply(False, keep_lan)
        _disarm_watchdog()
        if res.ok:
            _clear_state()
            return ActionResult(True, "Isolation left over from an earlier run "
                                      "has been lifted automatically")
        # The state file stays, so the next run tries again rather than
        # forgetting that this machine is still sealed.
        return ActionResult(
            False, "This machine was left isolated by an earlier run and the "
                   f"revert failed: {res.message}. Lift it manually with: "
                   f"{_revert_shell_command()}")

    _isolate_deadline = deadline
    _isolate_timer = threading.Timer(left, _auto_revert)
    _isolate_timer.daemon = True
    _isolate_timer.start()
    return ActionResult(True, f"Isolation still active — reverts in "
                              f"{int(left // 60)} minutes unless confirmed")


def _auto_revert() -> None:
    """What the in-process timer runs. Clears the state so nothing lingers."""
    _isolate_apply(False, bool(_read_state().get("keep_lan", True)))
    _disarm_watchdog()
    _clear_state()


def confirm_isolation() -> ActionResult:
    """Cancels the automatic revert once you have confirmed you are not locked out."""
    global _isolate_timer, _isolate_deadline
    if _isolate_timer:
        _isolate_timer.cancel()
        _isolate_timer = None
    _isolate_deadline = 0.0
    _disarm_watchdog()
    _clear_state()
    return ActionResult(True, "Isolation pinned — it will not revert automatically")


def isolate(enable: bool = True, auto_revert: int = 600,
            keep_lan: bool = True) -> ActionResult:
    """Cuts external connections while keeping the retreat open.

    We block at the firewall rather than disabling the adapter, because
    disabling it destroys live evidence.

    Paired with a dead-man's switch, because isolation may be triggered on a
    machine you reach remotely and would otherwise cut your own access with
    no way back. The switch has two layers: an in-process timer for the
    normal case, and a scheduled task outside this process that still fires
    if the application crashes or is closed. A timer alone dies with the
    program and would leave the machine sealed for good.

    keep_lan preserves the local network so you retain access from inside it.
    """
    global _isolate_timer, _isolate_deadline
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")

    if not enable:
        if _isolate_timer:
            _isolate_timer.cancel()
            _isolate_timer = None
        _isolate_deadline = 0.0
        _disarm_watchdog()
        _clear_state()
        _clear_legacy_rules()
        return _isolate_apply(False, keep_lan)

    res = _isolate_apply(True, keep_lan)
    if res.ok and auto_revert > 0:
        if _isolate_timer:
            _isolate_timer.cancel()
        _isolate_timer = threading.Timer(auto_revert, _auto_revert)
        _isolate_timer.daemon = True
        _isolate_timer.start()
        _isolate_deadline = time.time() + auto_revert
        _write_state(_isolate_deadline, keep_lan)

        mechanism = _arm_watchdog(auto_revert)
        span = (f"{auto_revert // 60} minutes" if auto_revert >= 60
                else f"{auto_revert} seconds")
        res.message += f" — reverts automatically in {span} unless confirmed"
        if mechanism:
            res.message += f" (survives a crash, via {mechanism})"
        else:
            res.message += (". No scheduler available, so the revert only "
                            "happens while this program keeps running — do "
                            "not close it until you have confirmed access")
    elif res.ok:
        _write_state(0.0, keep_lan)
    return res


def _isolate_apply(enable: bool, keep_lan: bool = True) -> ActionResult:
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")

    # Local ranges, excluded so you keep access from inside your own network
    LAN = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
    LAN6 = ["fe80::/10", "fc00::/7"]
    scope = "external only (LAN still works)" if keep_lan else "all"

    if IS_WINDOWS:
        if enable:
            # remoteip accepts a list; block everything but local when keep_lan.
            # 127.0.0.0/8 and 169.254.0.0/16 are excluded alongside the private
            # ranges so loopback and link-local keep working, matching Linux.
            remote = ("1.0.0.0-9.255.255.255,11.0.0.0-126.255.255.255,"
                      "128.0.0.0-169.253.255.255,169.255.0.0-172.15.255.255,"
                      "172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255"
                      if keep_lan else "any")
            for d in ("in", "out"):
                _sh_rc(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={RULE_PREFIX}-Isolate-{d}", f"dir={d}",
                        "action=block", f"remoteip={remote}"])
            return ActionResult(True, f"Machine isolated — {scope} connections blocked")
        for d in ("in", "out"):
            _sh_rc(["netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={RULE_PREFIX}-Isolate-{d}"])
        return ActionResult(True, "Isolation lifted")

    backend = _firewall_backend()

    if backend == "nft":
        if enable:
            _nft_ensure()
            # Both directions. An output-only chain leaves every listening
            # backdoor reachable while the interface claims the machine is
            # isolated, which is worse than not isolating at all.
            for chain, hook in (("ngiso", "output"), ("ngisoin", "input")):
                _sh_rc(["nft", "add", "chain", "inet", NFT_TABLE, chain,
                      "{ type filter hook " + hook +
                      " priority -5 ; policy accept ; }"])
            _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso",
                    "oifname", "lo", "accept"])
            _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin",
                    "iifname", "lo", "accept"])
            if keep_lan:
                _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso",
                        "ip", "daddr", "{ " + ", ".join(LAN) + " }", "accept"])
                _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso",
                        "ip6", "daddr", "{ " + ", ".join(LAN6) + " }", "accept"])
                _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin",
                        "ip", "saddr", "{ " + ", ".join(LAN) + " }", "accept"])
                _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin",
                        "ip6", "saddr", "{ " + ", ".join(LAN6) + " }", "accept"])
            _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngiso", "drop"])
            _sh_rc(["nft", "add", "rule", "inet", NFT_TABLE, "ngisoin", "drop"])
            return ActionResult(True, f"Machine isolated — {scope} connections blocked")
        _sh_rc(["nft", "delete", "chain", "inet", NFT_TABLE, "ngiso"])
        _sh_rc(["nft", "delete", "chain", "inet", NFT_TABLE, "ngisoin"])
        return ActionResult(True, "Isolation lifted")

    if backend == "iptables":
        # iptables covers IPv4 only. On a dual-stack machine that leaves IPv6
        # wide open while the message says "isolated", so ip6tables is driven
        # in parallel and its absence is reported rather than swallowed.
        gaps = []
        for tool, lan in (("iptables", LAN), ("ip6tables", LAN6)):
            if not shutil.which(tool):
                gaps.append(tool)
                continue
            rules = [["OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                     ["INPUT", "-i", "lo", "-j", "ACCEPT"]]
            if keep_lan:
                for net in lan:
                    rules += [["OUTPUT", "-d", net, "-j", "ACCEPT"],
                              ["INPUT", "-s", net, "-j", "ACCEPT"]]
            rules += [["OUTPUT", "-j", "DROP"], ["INPUT", "-j", "DROP"]]
            # -I inserts in reverse, so we walk backwards to put the accepts first
            for r in reversed(rules):
                _sh_rc([tool, "-I" if enable else "-D", r[0]] + r[1:])
        if not enable:
            return ActionResult(True, "Isolation lifted")
        msg = f"Machine isolated — {scope} connections blocked"
        if "ip6tables" in gaps:
            msg += (". Warning: ip6tables is missing, so IPv6 traffic is NOT "
                    "blocked — the machine is only half isolated")
        return ActionResult(True, msg)

    return ActionResult(False, "No supported firewall found")


def reopen_port(port: int, proto: str = "tcp") -> ActionResult:
    """Reopens a port, so close_port is never a one-way action."""
    if not is_elevated():
        return ActionResult(False, "requires administrator/root privileges")
    backend = _firewall_backend()

    if backend == "netsh":
        _sh_rc(["netsh", "advfirewall", "firewall", "delete", "rule",
              f"name={RULE_PREFIX}-ClosePort-{port}"])
    elif backend == "nft":
        code, out = _sh_rc(["nft", "delete", "element", "inet", NFT_TABLE,
                          f"closed_{proto.lower()}", "{ " + str(port) + " }"])
        if code != 0:
            return ActionResult(False, out.strip()[:160] or "the port was not blocked")
    elif backend == "iptables":
        _sh_rc(["iptables", "-D", "INPUT", "-p", proto,
              "--dport", str(port), "-j", "DROP"])
    elif backend == "ufw":
        _sh_rc(["ufw", "delete", "deny", f"{port}/{proto}"])
    else:
        return ActionResult(False, "No supported firewall found")
    return ActionResult(True, f"Reopened port {port}/{proto}")


def list_our_rules() -> list[str]:
    """Rules this tool added — so nothing is left behind and forgotten."""
    if _firewall_backend() == "nft":
        _, out = _sh_rc(["nft", "list", "table", "inet", NFT_TABLE])
        return [l.strip() for l in out.splitlines()
                if "elements" in l or "@blocked" in l or "@closed" in l]
    if IS_WINDOWS:
        _, out = _sh_rc(["netsh", "advfirewall", "firewall", "show", "rule",
                       "name=all"])
        return [l.split(":", 1)[1].strip() for l in out.splitlines()
                if l.strip().startswith("Rule Name") and RULE_PREFIX in l]
    rules = []
    for tool in ("iptables", "ip6tables"):
        if not shutil.which(tool):
            continue
        _, out = _sh_rc([tool, "-S"])
        rules += [f"{tool}: {l}" for l in out.splitlines() if "DROP" in l]
    return rules


# ──────────────────────────────────────────────────────────────
# Scan engine and verdict
# ──────────────────────────────────────────────────────────────

CRITICAL, WARN, INFO = "critical", "warn", "info"

VERDICT_CONTROLLED = "controlled"
VERDICT_EXPOSED = "exposed"
VERDICT_CLEAR = "clear"


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)
    pid: int | None = None
    ip: str = ""
    port: int = 0
    key: str = ""            # suppression key — silences this finding alone
    # Identity of the process at scan time. The user may act minutes later,
    # by which point the PID can belong to something else entirely.
    proc_started: float = 0.0
    proc_name: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    started: float = 0.0
    duration: float = 0.0
    verdict: str = VERDICT_CLEAR
    verdict_text: str = ""
    findings: list[Finding] = field(default_factory=list)
    connections: list = field(default_factory=list)
    listening: list = field(default_factory=list)
    persistence: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    unattended: list = field(default_factory=list)
    exposure: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    arp: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    suppressed: int = 0          # findings hidden by the known-good list
    hardening: list = field(default_factory=list)
    exectrace: list = field(default_factory=list)
    profile: str = "desktop"     # desktop | security workstation
    downgraded: int = 0          # findings routine for this profile

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]


# ------------------------- the checks -------------------------

def _check_remote_tools(conns) -> list[Finding]:
    out, seen = [], set()
    for c in conns:
        if not c.tool or c.proc.pid in seen:
            continue
        seen.add(c.proc.pid)
        live = c.status == "ESTABLISHED" and c.raddr
        out.append(Finding(
            severity=CRITICAL if live else WARN,
            category="Remote control",
            title=(f"{c.tool} has an active session" if live
                   else f"{c.tool} is running in the background"),
            detail=(f"Live session with {c.raddr}:{c.rport} — this is an active "
                    if live else
                    "The program is running and ready to accept a session, but none is open."),
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "User": c.proc.username,
                      "Uptime": collectors.uptime_of(c.proc),
                      "Launched by": c.proc.ancestry or "—",
                      "Other party": f"{c.raddr}:{c.rport}" if c.raddr else "—"},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
        ))
    return out


def _check_listening(listening) -> list[Finding]:
    out = []
    for c in listening:
        desc = signatures.describe_port(c.lport)
        exposed = c.laddr in ("0.0.0.0", "::", "")
        if desc:
            note, conf = desc
            if conf == "noisy":
                sev = INFO
            elif conf == "admin" and exposed:
                sev = CRITICAL
            else:
                sev = WARN
            out.append(Finding(
                severity=sev,
                category="Open port",
                title=f"Port {c.lport} is open — {note}",
                detail=("Reachable from any network; anything that can reach you can try to get in."
                        if exposed else
                        "Open on a limited interface only."),
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Address": f"{c.laddr}:{c.lport}",
                          "Launched by": c.proc.ancestry or "—",
                          "Protocol": c.family},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, port=c.lport, key=conn_key(c),
            ))
        elif exposed and c.proc.trust == "untrusted" and c.family == "tcp":
            out.append(Finding(
                severity=WARN,
                category="Open port",
                title=f"An untrusted program is listening on port {c.lport}",
                detail=c.proc.trust_note or "The executable is unsigned and not part of the system.",
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Launched by": c.proc.ancestry or "—",
                          "SHA-256": c.proc.sha256 or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, port=c.lport, key=conn_key(c),
            ))
    return out


def _check_untrusted_outbound(conns) -> list[Finding]:
    out, seen = [], set()
    for c in conns:
        if c.status != "ESTABLISHED" or not c.raddr:
            continue
        if c.proc.pid in seen or c.tool:
            continue
        hint = collectors.path_looks_suspicious(c.proc.exe)
        parent = collectors.parent_is_suspicious(c.proc)
        # "unknown" alone is not enough to alert on, or false alarms would flood
        if c.proc.trust == "untrusted" or hint or parent:
            seen.add(c.proc.pid)
            if parent:
                title = f"{c.proc.name} is calling out, launched by {parent}"
                detail = ("The launch chain is abnormal: this kind of program "
                          "is not expected to start a network program.")
                sev = CRITICAL
            elif hint:
                title = f"{c.proc.name} is calling out from a temporary path"
                detail = (f"Running from {hint} — installed software does not live there.")
                sev = WARN
            else:
                title = f"{c.proc.name} is calling out and is untrusted"
                detail = c.proc.trust_note
                sev = WARN
            out.append(Finding(
                severity=sev, category="Outbound connection",
                title=title, detail=detail,
                evidence={"Path": c.proc.exe, "Destination": f"{c.raddr}:{c.rport}",
                          "Launched by": c.proc.ancestry or "—",
                          "Command": c.proc.cmdline[:200],
                          "SHA-256": c.proc.sha256 or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
    return out


def _check_network(arp, dns, hosts, proxy) -> list[Finding]:
    out = []

    for alert in netcheck.detect_arp_spoof(arp):
        out.append(Finding(
            severity=CRITICAL, category="Network",
            title="Sign of a man-in-the-middle attack",
            detail=(f"The hardware address {alert['mac']} is answering for "
                    f"{alert.get('count', len(alert['ips']))} different hosts on "
                    "the same subnet. One device claiming to be several is how "
                    "traffic gets intercepted."),
            evidence={"MAC": alert["mac"], "Addresses": ", ".join(alert["ips"]),
                      "Vendor": alert.get("vendor") or "unknown"},
            key=f"arp|{alert['mac']}",
        ))

    for h in hosts:
        if h["blocks_security"]:
            out.append(Finding(
                severity=CRITICAL, category="Network",
                title="hosts file is blocking security sites",
                detail="Redirecting antivirus or update sites is something "
                       "malware does to avoid being found.",
                evidence={"Line": str(h["line"]), "Address": h["ip"],
                          "Domains": h["names"]},
                key=f"hosts|{h['ip']}|{h['names']}",
            ))
        elif h["redirect"]:
            out.append(Finding(
                severity=WARN, category="Network",
                title="Redirect in the hosts file",
                detail="A domain pointed at an external address instead of resolving normally.",
                evidence={"Address": h["ip"], "Domains": h["names"]},
                key=f"hosts|{h['ip']}|{h['names']}",
            ))

    if proxy.get("enabled"):
        out.append(Finding(
            severity=WARN, category="Network",
            title="A proxy is enabled on this machine",
            detail="All browsing passes through this server. Make sure you set it.",
            evidence={"Server": proxy.get("server", ""),
                      "Source": proxy.get("source", "")},
            key=f"proxy|{proxy.get('server','')}",
        ))

    known = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
             "208.67.222.222", "208.67.220.220", "127.0.0.1", "127.0.0.53"}
    unknown = [d for d in dns if d not in known
               and not d.startswith(("192.168.", "10.", "172.16.", "fe80"))]
    if unknown:
        out.append(Finding(
            severity=INFO, category="Network",
            title="Unfamiliar DNS servers",
            detail="Not from common providers and not your router. "
                   "Confirm they belong to your ISP.",
            evidence={"Servers": ", ".join(unknown)},
            key=f"dns|{','.join(sorted(unknown))}",
        ))
    return out


def _check_persistence(items) -> list[Finding]:
    out = []
    for it in items:
        if it["risk"] == "critical":
            out.append(Finding(
                severity=CRITICAL, category="Persistence",
                title=f"Suspicious command in {it['name']}",
                detail="A line that runs automatically and contains a download or reverse shell.",
                evidence={"Source": it["source"], "Content": it["value"]},
                key=f"persist|{it['source']}|{it['name']}",
            ))
        elif it["kind"] == "SSH key":
            out.append(Finding(
                severity=WARN, category="Persistence",
                title=f"Authorised SSH key: {it['name']}",
                detail="Anyone holding the matching key logs in without a password. "
                       "Remove any you do not recognise.",
                evidence={"File": it["source"], "Fingerprint": it["value"]},
                key=f"persist|{it['source']}|{it['name']}",
            ))
        elif it["risk"] == "warn":
            out.append(Finding(
                severity=INFO, category="Persistence",
                title=f"{it['kind']}: {it['name']}",
                detail="Runs automatically from outside the system paths — review it.",
                evidence={"Path": it["value"], "Source": it["source"]},
                key=f"persist|{it['source']}|{it['name']}",
            ))
    return out


# ------------------------- the verdict -------------------------

def _decide(findings: list[Finding]) -> tuple[str, str]:
    live = [f for f in findings
            if f.severity == CRITICAL and f.category == "Remote control"]
    if live:
        names = ", ".join(sorted({f.title.split(" has an")[0] for f in live}))
        return VERDICT_CONTROLLED, f"A control session is active right now: {names}"

    crit = [f for f in findings if f.severity == CRITICAL]
    if crit:
        return VERDICT_EXPOSED, f"{len(crit)} critical issues need a decision now"

    warns = [f for f in findings if f.severity == WARN]
    if warns:
        return VERDICT_EXPOSED, f"{len(warns)} items worth reviewing, nothing critical"

    # A clean sheet only counts if every check actually ran
    gaps = [f for f in findings if f.category == "Incomplete scan"]
    if gaps:
        return VERDICT_EXPOSED, (f"{len(gaps)} checks failed to run — the "
                                 "result is incomplete, not clean")

    return VERDICT_CLEAR, "No remote control session and no exposed admin ports"


# ------------------------- execution -------------------------

def _check_hijacked_tool(conns: list) -> list[Finding]:
    """A legitimate control tool talking to a server that is not its vendor's.

    This is the practical difference between "the user installed it" and "it
    was hijacked": the official tool routes through vendor servers, a hijacked
    one is driven from a private one. We resolve the reverse name to tell them apart.
    """
    out = []
    for c in conns:
        if not c.tool or c.status != "ESTABLISHED" or not c.raddr:
            continue
        if intel.classify(c.raddr) != "internet":
            continue
        if not c.rhost:
            c.rhost = intel.reverse_dns(c.raddr)
        match = signatures.vendor_match(c.tool, c.rhost)
        if match is None:
            continue          # no domain on record, or no reverse name — do not accuse
        if match:
            # The name claims the vendor. Confirm it forward, because a PTR
            # record is set by whoever owns the address block.
            if intel.forward_confirmed(c.raddr, c.rhost):
                continue
            detail = ("The address presents a vendor name in reverse DNS, but "
                      "that name does not resolve back to this address. A "
                      "reverse record is set by whoever owns the address "
                      "block, so this is what an operator borrowing the "
                      "vendor's name looks like.")
        else:
            detail = ("The program itself is legitimate, but its session does "
                      "not route through vendor infrastructure — the pattern "
                      "of a sound admin tool being used as a backdoor.")
        out.append(Finding(
            severity=CRITICAL, category="Hijacked tool",
            title=f"{c.tool} is talking to a server that is not the vendor's",
            detail=detail,
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "Destination": f"{c.raddr}:{c.rport}",
                      "Reverse name": c.rhost or "none — raw address",
                      "Launched by": c.proc.ancestry or "—"},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
        ))
    return out


def _check_tunnels(conns: list) -> list[Finding]:
    """Tunnels invert the connection, bypassing firewall and router.

    A tunnel opens no port: the machine dials out, so nothing looks exposed.
    And because the session routes through the tunnel provider, the
    visible address is not the controller's, so IP profiling will not help.
    """
    out, seen = [], set()
    for c in conns:
        # A mesh VPN is a product people install on purpose. It belongs on
        # the report so the user can recognise it, not at a severity that
        # teaches them to ignore the whole tunnel category.
        if c.mesh and c.proc.pid not in seen:
            seen.add(c.proc.pid)
            out.append(Finding(
                severity=INFO, category="Tunnel",
                title=f"{c.mesh} is running on this machine",
                detail=("A mesh VPN, commonly installed deliberately. It does "
                        "give remote access to this machine, so confirm you "
                        "set it up and that you recognise every device on the "
                        "network."),
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—",
                          "Launched by": c.proc.ancestry or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
            continue

        if c.tunnel and c.proc.pid not in seen:
            seen.add(c.proc.pid)
            live = c.status == "ESTABLISHED"
            out.append(Finding(
                severity=CRITICAL if live else WARN,
                category="Tunnel",
                title=(f"{c.tunnel} is running with a live session" if live
                       else f"{c.tunnel} is running on this machine"),
                detail=("A tunnel makes the machine dial outward, passing the "
                        "firewall and router without opening any port. The "
                        "visible address is the provider's, not the controller's."),
                evidence={"Process": c.proc.name, "Path": c.proc.exe,
                          "Command": c.proc.cmdline[:220],
                          "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—",
                          "Launched by": c.proc.ancestry or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
            continue

        # A tunnel or dynamic-DNS domain, even when the process is unknown
        if c.status == "ESTABLISHED" and c.raddr and c.proc.pid not in seen:
            if intel.classify(c.raddr) != "internet":
                continue
            if not c.rhost:
                c.rhost = intel.reverse_dns(c.raddr)
            flag = signatures.domain_flags(c.rhost)
            if not flag:
                continue
            seen.add(c.proc.pid)
            kind, domain = flag
            if kind == "tunnel":
                title = f"{c.proc.name} is connected through a tunnel ({domain})"
                detail = ("The destination is a tunnelling service. It may be "
                          "legitimate developer use, or a covert control channel.")
            else:
                title = f"{c.proc.name} is connected to a dynamic domain ({domain})"
                detail = ("Dynamic DNS lets an operator change address without "
                          "changing the malware — common in control channels.")
            out.append(Finding(
                severity=WARN, category="Tunnel",
                title=title, detail=detail,
                evidence={"Path": c.proc.exe, "Reverse name": c.rhost,
                          "Destination": f"{c.raddr}:{c.rport}",
                          "Launched by": c.proc.ancestry or "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
    return out


def _check_exectrace(items: list) -> list[Finding]:
    """Commands that already ran — the ClickFix trail after the process exits.

    This is the only check that looks backwards in time. A fetch-and-run
    payload fires in seconds and disappears, so a connection scan finds
    nothing; the Run-box and shell histories still hold the command verbatim.
    """
    sev_map = {"critical": CRITICAL, "warn": WARN, "info": INFO}
    out = []
    for it in items:
        out.append(Finding(
            severity=sev_map.get(it["risk"], WARN),
            category="Executed command",
            title=f"{it['kind']}: {it['name']}",
            detail=("A command matching the shape of a paste-and-run payload "
                    "was recorded. " + it["value"]),
            evidence={"Source": it["source"]},
            key=f"exec|{it['source']}|{it['name']}|{it['value'][:40]}",
        ))
    return out


def _check_hardening(items: list) -> list[Finding]:
    """Dormant doors: no process, port or connection points to them."""
    sev_map = {"critical": CRITICAL, "warn": WARN, "info": INFO}
    out = []
    for it in items:
        out.append(Finding(
            severity=sev_map.get(it["risk"], INFO),
            category="System configuration",
            title=f"{it['kind']}: {it['name']}",
            detail=it["value"],
            evidence={"Source": it["source"]},
            key=f"harden|{it['source']}|{it['name']}",
        ))
    return out


def _check_lolbins(conns: list) -> list[Finding]:
    """Signed system binaries doing work outside their purpose.

    Our trust model treats a valid signature as reassurance, and for these
    binaries that is precisely backwards: they are genuinely signed by the
    vendor and can still fetch and run a payload. An attacker using them
    brings no file of their own, so there is nothing unsigned to catch.
    """
    out, seen = [], set()
    sev_map = {"critical": CRITICAL, "warn": WARN}
    for c in conns:
        if c.proc.pid in seen or c.proc.pid <= 0:
            continue
        live = bool(c.raddr) and c.status == "ESTABLISHED"
        res = lolbins.assess(c.proc.name, c.proc.cmdline,
                             c.proc.ancestry, live)
        if not res:
            continue
        seen.add(c.proc.pid)
        out.append(Finding(
            severity=sev_map.get(res["severity"], WARN),
            category="System binary abuse",
            title=f"{res['binary']} is being used outside its purpose",
            detail=(f"This is the {res['purpose']}, signed by the vendor and "
                    f"present on every machine. It {res['abuse']}. "
                    + "; ".join(res["reasons"]).capitalize() + "."),
            evidence={"Command": c.proc.cmdline[:220],
                      "Launched by": c.proc.ancestry or "—",
                      "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—",
                      "Path": c.proc.exe},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
        ))
    return out


def _check_vulnerable_versions(conns: list) -> list[Finding]:
    """Is an installed remote-access tool on a build with a known exploited flaw?

    Detecting that ScreenConnect is present answers half the question. The
    other half is which build, because an attacker who exploits an unpatched
    flaw needs no credentials at all — and the owner feels safe precisely
    because the software is legitimate and signed.
    """
    out, seen = [], set()
    for c in conns:
        if not c.tool or not c.proc.exe:
            continue
        if c.proc.exe in seen:
            continue
        seen.add(c.proc.exe)
        res = vulncheck.check(c.tool, c.proc.exe)
        if not res:
            continue
        out.append(Finding(
            severity=CRITICAL if res["severity"] == "critical" else WARN,
            category="Vulnerable version",
            title=f"{res['tool']} {res['version']} has an exploited flaw ({res['cve']})",
            detail=(res["note"] + f" Fixed in {res['fixed_in']}; update or "
                    "remove it before anything else."),
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "Installed version": res["version"],
                      "Fixed in": res["fixed_in"],
                      "CVE": res["cve"],
                      "Data compiled": vulncheck.DATA_DATE},
            pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, key=f"vuln|{res['cve']}|{c.proc.exe}",
        ))
    return out


def _check_multiple_rmm(conns: list) -> list[Finding]:
    """More than one remote-access product on one machine.

    Any single one has an innocent explanation. Several rarely do. Operators
    install a second and third deliberately, so that removing the one that
    gets noticed does not remove their access, and so the traces are spread
    across products nobody correlates.

    This costs nothing to check — the tools are already identified — and it
    is the rare signal that grows stronger the more ordinary each individual
    piece looks.
    """
    tools: dict[str, list] = {}
    for c in conns:
        if c.tool:
            tools.setdefault(c.tool, []).append(c)
    if len(tools) < 2:
        return []

    names = sorted(tools)
    return [Finding(
        severity=CRITICAL if len(names) > 2 else WARN,
        category="Remote control",
        title=f"{len(names)} different remote-access tools are running",
        detail=("One remote-access tool is ordinary. Several at once is a "
                "pattern operators create on purpose: if the obvious one is "
                "removed, the others keep the way in, and no single product's "
                "logs show the whole picture. Confirm you installed every one "
                "of these, and remove the ones you did not."),
        evidence={"Tools": ", ".join(names),
                  "Processes": ", ".join(
                      sorted({c.proc.name for group in tools.values()
                              for c in group}))[:300]},
        key="multi-rmm|" + "|".join(names),
    )]


def _check_extensions(items: list[dict]) -> list[Finding]:
    """Browser extensions whose permissions amount to session theft."""
    out = []
    for ext in items:
        concerns = ext.get("concerns") or []
        if not concerns:
            continue
        sideloaded = not ext.get("from_store", True)
        severity = CRITICAL if (sideloaded and concerns) else WARN
        why = concerns[0]
        detail = (f"This extension {why}. That is not proof of anything — a "
                  "password manager needs much the same access — but it is "
                  "the whole capability required to take over an account "
                  "without a password, so it is worth being certain you "
                  "installed it on purpose.")
        if sideloaded:
            detail += (" It also did not come from the browser's store, "
                       "which means something placed it here rather than you "
                       "choosing it from a listing.")
        out.append(Finding(
            severity=severity, category="Browser extension",
            title=f"{ext['name']} can read every session in {ext['browser']}",
            detail=detail,
            evidence={
                "Extension": ext["name"],
                "Browser": f"{ext['browser']} ({ext.get('profile') or '—'})",
                "Identifier": ext.get("id", ""),
                "Version": ext.get("version", ""),
                "Installed from the store": "no" if sideloaded else "yes",
                "It can": "; ".join(
                    extensions.describe_permissions(ext))[:400],
                "Path": ext.get("path", ""),
            },
            key=f"ext|{ext.get('browser')}|{ext.get('id')}",
        ))
    return out


def _check_direct_dns(conns: list, resolvers: list) -> list[Finding]:
    """A program resolving names through a server the system never chose.

    Malware families hard-code their own resolver so that filtering applied
    at the machine's configured DNS never sees the lookup. The system
    resolver is the only thing that should be talking to port 53; anything
    else has gone around the machine's own settings to ask someone
    unaccountable.
    """
    configured = set()
    for r in resolvers or []:
        addr = r.get("server") if isinstance(r, dict) else str(r)
        if addr:
            configured.add(addr.strip())

    out, seen = [], set()
    for c in conns:
        if c.rport != 53 or not c.raddr:
            continue
        if c.raddr in configured:
            continue
        if intel.classify(c.raddr) != "internet":
            continue
        name = (c.proc.name or "").lower()
        # The system's own resolver legitimately talks to whatever it likes
        if name in ("systemd-resolve", "systemd-resolved", "dnsmasq",
                    "unbound", "named", "nscd", "resolvconf", "svchost.exe",
                    "svchost", "dnscache", "connmand", "networkmanager"):
            continue
        if c.proc.pid in seen:
            continue
        seen.add(c.proc.pid)
        out.append(Finding(
            severity=WARN, category="Network",
            title=f"{c.proc.name or 'A program'} is using its own DNS server",
            detail=("This program is asking a name server the machine was "
                    "never configured to use. Going around the system "
                    "resolver is how a lookup avoids any filtering applied "
                    "here, and it is a documented step in current "
                    "paste-and-run campaigns."),
            evidence={"Process": c.proc.name, "Path": c.proc.exe,
                      "Server it asked": c.raddr,
                      "Configured servers": ", ".join(sorted(configured))
                                            or "none detected",
                      "Launched by": c.proc.ancestry or "—"},
            pid=c.proc.pid, proc_started=c.proc.started,
            proc_name=c.proc.name, ip=c.raddr, port=53, key=conn_key(c),
        ))
    return out


def _check_unattended(items: list[dict]) -> list[Finding]:
    """Remote-access tools set up to admit someone with nobody present."""
    out = []
    for item in items:
        sev = {"critical": CRITICAL, "warn": WARN}.get(item.get("risk"), INFO)
        out.append(Finding(
            severity=sev, category="Remote control",
            title=f"{item['tool']}: {item['setting']}",
            detail=item["detail"],
            evidence={"Tool": item["tool"], "Setting": item["setting"],
                      "Configuration file": item.get("path", "")},
            key=f"unattended|{item['tool']}|{item['setting']}",
        ))
    return out


def _check_install_chain(conns: list) -> list[Finding]:
    """Abnormal launch chains — shells do not normally install software."""
    out, seen = [], set()
    for c in conns:
        low = (c.proc.cmdline or "").lower()
        anc = (c.proc.ancestry or "").lower()
        if c.proc.pid in seen:
            continue
        silent = ("msiexec" in low and ("/qn" in low or "/quiet" in low))
        # Whole-name comparison: "sh(" as a substring matched "flush(12)"
        from_shell = bool(
            set(collectors._ancestry_names(c.proc.ancestry)) &
            {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta"})
        if silent and from_shell:
            seen.add(c.proc.pid)
            out.append(Finding(
                severity=CRITICAL, category="Silent install",
                title="A silent install launched by a shell",
                detail=("A command shell ran an installer in silent mode and it "
                        "then reached the network — how a control tool gets "
                        "installed without the user knowing."),
                evidence={"Command": c.proc.cmdline[:220],
                          "Launched by": c.proc.ancestry or "—",
                          "Destination": f"{c.raddr}:{c.rport}" if c.raddr else "—"},
                pid=c.proc.pid, proc_started=c.proc.started, proc_name=c.proc.name, ip=c.raddr, port=c.rport, key=conn_key(c),
            ))
    return out


def _safely(res: ScanResult, label: str, fn, *args):
    """Runs one check, turning a crash into a visible gap rather than silence.

    A check that raises used to contribute nothing, and nothing is
    indistinguishable from "found nothing" — the scan then reports a clean
    machine on the strength of a check that never ran. Here the failure
    becomes a warning the user sees and a finding they can act on.
    """
    try:
        return fn(*args)
    except Exception as e:
        res.warnings.append(f"The {label} check failed: {type(e).__name__}: "
                            f"{str(e)[:120]}")
        res.findings.append(Finding(
            severity=WARN, category="Incomplete scan",
            title=f"The {label} check did not run",
            detail=("This part of the scan failed, so anything it would have "
                    "found is missing from the verdict. Treat the result as "
                    "incomplete rather than clean."),
            evidence={"Error": f"{type(e).__name__}: {str(e)[:200]}"},
            key=f"scanfail|{label}",
        ))
        return []


def _build_timeline(res: "ScanResult") -> list[dict]:
    """The findings in the order they happened, when that is knowable.

    A list of findings answers "what is wrong". It does not answer the
    question people actually arrive with, which is "what happened to me".
    Ordering by time does: a remote-access tool installed at 14:02, a
    connection out at 14:03 and an autostart entry at 14:05 is not three
    findings, it is one afternoon, and seeing it laid out is often the
    moment someone recognises the support call they took.
    """
    events = []

    for c in res.connections:
        if c.tool and c.proc.started:
            events.append({
                "when": c.proc.started,
                "what": f"{c.tool} started",
                "detail": c.proc.exe or c.proc.name,
                "severity": CRITICAL if c.status == "ESTABLISHED" else WARN,
            })

    for item in res.persistence or []:
        when = item.get("modified") or item.get("created") or 0
        if when:
            events.append({
                "when": when,
                "what": f"Autostart entry: {item.get('name', '')}",
                "detail": item.get("detail", "")[:160],
                "severity": WARN,
            })

    for item in res.exectrace or []:
        when = item.get("when") or item.get("modified") or 0
        if when:
            events.append({
                "when": when,
                "what": item.get("kind", "Command run"),
                "detail": item.get("detail", "")[:160],
                "severity": CRITICAL if item.get("risk") == "critical" else WARN,
            })

    for ext in res.extensions or []:
        if ext.get("installed") and ext.get("concerns"):
            events.append({
                "when": ext["installed"],
                "what": f"Extension installed: {ext['name']}",
                "detail": f"{ext['browser']} — {ext['concerns'][0][:120]}",
                "severity": WARN,
            })

    events.sort(key=lambda e: e["when"])

    # Events close together are usually one action, not several. Marking the
    # gaps is what turns a list into a story.
    for i, event in enumerate(events):
        gap = 0.0 if i == 0 else event["when"] - events[i - 1]["when"]
        event["seconds_after_previous"] = round(gap, 1)
        event["same_episode"] = bool(i and gap < 600)
    return events


def run_scan(deep: bool = True, store: Store | None = None,
             progress=None, vt_key: str = "") -> ScanResult:
    """Runs the full scan. progress(percent, text) for live updates."""
    def step(pct: int, text: str):
        if progress:
            progress(pct, text)

    res = ScanResult(started=time.time())
    t0 = time.perf_counter()

    step(5, "Reading active connections…")
    conns, warn = collectors.collect_connections(deep=deep)
    res.connections = conns
    if warn:
        res.warnings.append(warn)

    res.listening = collectors.listening_ports(conns)

    step(30, "Matching remote-control signatures…")
    res.findings += _safely(res, "remote-control", _check_remote_tools, conns)
    res.findings += _safely(res, "multiple-tool", _check_multiple_rmm, conns)
    res.findings += _safely(res, "listening-port", _check_listening, res.listening)
    res.findings += _safely(res, "outbound", _check_untrusted_outbound, conns)
    res.findings += _safely(res, "install-chain", _check_install_chain, conns)
    res.findings += _safely(res, "system-binary", _check_lolbins, conns)

    step(38, "Checking remote-access tool versions…")
    res.findings += _safely(res, "vulnerable-version",
                            _check_vulnerable_versions, conns)

    step(42, "Checking tunnels and covert channels…")
    res.findings += _safely(res, "tunnel", _check_tunnels, conns)

    step(50, "Verifying control tool destinations…")
    # Needs reverse DNS over the network, so deep scans only
    if deep:
        res.findings += _safely(res, "hijacked-tool", _check_hijacked_tool, conns)

    step(55, "Inspecting the network…")
    res.arp = _safely(res, "ARP-table", netcheck.arp_table)
    res.arp += _safely(res, "IPv6-neighbour", netcheck.neighbour_table)
    res.dns = _safely(res, "DNS-server", netcheck.dns_servers)
    res.hosts = _safely(res, "hosts-file", netcheck.hosts_entries)
    res.interfaces = _safely(res, "interface", netcheck.interfaces)
    res.findings += _safely(res, "network", _check_network, res.arp, res.dns,
                            res.hosts, netcheck.proxy_settings())
    res.findings += _safely(res, "direct-DNS", _check_direct_dns, conns,
                            res.dns)

    step(72, "Checking persistence points…")
    sub_errors: list[str] = []
    res.persistence = _safely(res, "persistence", persistence.scan, sub_errors)
    res.findings += _safely(res, "persistence", _check_persistence, res.persistence)

    step(78, "Reading what recently executed…")
    res.exectrace = _safely(res, "execution-trace", exectrace.scan_exectrace,
                            sub_errors)
    res.findings += _safely(res, "execution-trace", _check_exectrace, res.exectrace)

    step(80, "Reading browser extensions…")
    res.extensions = _safely(res, "browser-extension",
                             extensions.scan_extensions, sub_errors)
    res.findings += _safely(res, "browser-extension", _check_extensions,
                            res.extensions)

    step(81, "Checking remote-access configuration…")
    res.unattended = _safely(res, "unattended-access",
                             rmmconfig.scan_unattended, sub_errors)
    res.findings += _safely(res, "unattended-access", _check_unattended,
                            res.unattended)

    step(82, "Checking dormant doors and protection settings…")
    res.hardening = _safely(res, "hardening", hardening.scan_hardening,
                            sub_errors)
    res.findings += _safely(res, "hardening", _check_hardening, res.hardening)

    # A sub-check that failed removed its whole category from the results.
    # Reported, so the absence of findings in that area is not read as their
    # absence on the machine.
    for err in sub_errors:
        res.warnings.append(f"Part of the scan did not run — {err}")
        res.findings.append(Finding(
            severity=WARN, category="Incomplete scan",
            title=f"The {err.split(':')[0]} check did not run",
            detail=("This part of the scan failed, so anything it would have "
                    "found is missing. Treat the result as incomplete rather "
                    "than clean."),
            evidence={"Error": err},
            key=f"scanfail|{err.split(':')[0]}",
        ))

    step(86, "Applying the machine profile…")
    res.profile = profiles.detect()
    res.findings, res.downgraded = profiles.adjust(res.findings, res.profile)

    step(88, "Applying the known-good list…")
    if store:
        kept = []
        for f in res.findings:
            if f.key and store.is_approved(f.key):
                res.suppressed += 1
                continue
            kept.append(f)
        res.findings = kept

    if vt_key:
        step(90, "Asking VirusTotal about file hashes…")
        # Critical findings only: the free tier allows 4 queries a minute
        for f in res.findings[:8]:
            h = f.evidence.get("SHA-256", "")
            if not h or h == "—":
                continue
            text, sev = intel.vt_summary(intel.virustotal(h, vt_key))
            if not text:
                continue
            f.evidence["VirusTotal"] = text
            if sev == "critical":
                f.severity = CRITICAL
                f.detail += f" — {text}."

    # Static data ages. A clean result must not be read as a guarantee.
    res.warnings.append(vulncheck.advisory_note())

    step(90, "Assembling the timeline…")
    res.timeline = _safely(res, "timeline", _build_timeline, res)

    # The exposure list is only built when something was actually found.
    # Handing someone a list of credentials to revoke on a clean machine
    # teaches them to ignore it on the day it matters.
    if any(f.severity in (CRITICAL, WARN) and
           f.category not in ("Incomplete scan",) for f in res.findings):
        res.exposure = _safely(res, "exposure", triage.build_checklist,
                               sub_errors)

    step(92, "Assembling the verdict…")
    order = {CRITICAL: 0, WARN: 1, INFO: 2}
    res.findings.sort(key=lambda f: order.get(f.severity, 3))
    res.verdict, res.verdict_text = _decide(res.findings)

    if store:
        store.record(conns)
        store.save_findings(res.findings)

    res.duration = time.perf_counter() - t0
    step(100, "Complete")
    return res


# ──────────────────────────────────────────────────────────────
# Text mode
# ──────────────────────────────────────────────────────────────

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
        pass  # (relative import removed when merging)
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
    pass  # (relative import removed when merging)
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


# ──────────────────────────────────────────────────────────────
# Terminal and agent interface
# ──────────────────────────────────────────────────────────────

SCHEMA_VERSION = 1
VERSION = "2.0.0"

# Exit codes. Documented, stable, and meaningful enough that a caller never
# has to parse prose to find out what happened.
EXIT_CLEAR = 0           # scan completed, nothing found
EXIT_FINDINGS = 1        # scan completed, something worth reviewing
EXIT_CONTROLLED = 2      # a remote-control session is active right now
EXIT_INCOMPLETE = 3      # the scan ran but part of it could not
EXIT_NEEDS_PRIVILEGE = 4 # cannot see enough, and cannot ask for consent here
EXIT_USAGE = 5           # bad arguments
EXIT_REFUSED = 6         # an action was blocked by a safety gate
EXIT_ERROR = 7           # unexpected failure

VERDICT_EXIT = {
    engine.VERDICT_CLEAR: EXIT_CLEAR,
    engine.VERDICT_EXPOSED: EXIT_FINDINGS,
    engine.VERDICT_CONTROLLED: EXIT_CONTROLLED,
}


# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------

def is_interactive() -> bool:
    """Is a person present to answer a prompt?

    Both streams are checked. An agent typically has neither, a redirected
    run has one, and only a real terminal session has both.
    """
    try:
        return bool(sys.stdin and sys.stdin.isatty()
                    and sys.stdout and sys.stdout.isatty())
    except Exception:
        return False


def _host_info() -> dict:
    return {
        "name": socket.gethostname(),
        "os": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "elevated": elevate.is_elevated(),
        "interactive": is_interactive(),
    }


def _emit(payload: dict, as_json: bool, human: str = "") -> None:
    """One object on stdout in JSON mode, prose otherwise."""
    if as_json:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2,
                  default=str)
        sys.stdout.write("\n")
    elif human:
        print(human)


def _fail(message: str, code: int, as_json: bool, **extra) -> int:
    """A failure the caller can act on, in whichever format they asked for.

    Errors go to stdout in JSON mode so a caller reading only stdout still
    receives a parseable object rather than an empty stream.
    """
    payload = {"schema": SCHEMA_VERSION, "tool": "maxport", "ok": False,
               "error": message, "exit_code": code}
    payload.update(extra)
    if as_json:
        _emit(payload, True)
    else:
        print(message, file=sys.stderr)
    return code


# --------------------------------------------------------------------------
# privilege handling
# --------------------------------------------------------------------------

def ensure_privilege(as_json: bool, allow_partial: bool,
                     no_elevate: bool) -> int | None:
    """Returns an exit code if the caller must act, or None to continue.

    Without privileges the scan cannot name the process behind a connection,
    which is most of its value. With a person present we offer the OS
    consent prompt. Without one we stop, because the alternative — spawning
    a dialog nobody will see and exiting successfully — reports a clean
    machine that was never examined.
    """
    if elevate.is_elevated():
        return None
    if allow_partial:
        return None

    if is_interactive() and not no_elevate:
        started, status = elevate.try_elevate()
        if started:
            # An elevated instance has taken over this run.
            return EXIT_CLEAR
        hint = elevate.instruction()
    else:
        hint = elevate.instruction()

    return _fail(
        "Not running with administrator/root privileges, so connections "
        "cannot be tied to processes and several checks return nothing. "
        f"{hint} Add --allow-partial to scan anyway and accept a blind spot.",
        EXIT_NEEDS_PRIVILEGE, as_json,
        remedy=hint, allow_partial_flag="--allow-partial")


# --------------------------------------------------------------------------
# serialisation
# --------------------------------------------------------------------------

def finding_id(f) -> str:
    """A stable identifier, so a caller can follow one finding across scans.

    Derived from what the finding *is* rather than where it appeared in a
    list, so it survives reordering and unrelated changes elsewhere.
    """
    import hashlib
    basis = f.key or f"{f.category}|{f.title}|{f.ip}|{f.port}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:12]


def finding_to_dict(f) -> dict:
    return {
        "id": finding_id(f),
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "detail": f.detail,
        "evidence": f.evidence,
        "pid": f.pid,
        "process": f.proc_name or None,
        "ip": f.ip or None,
        "port": f.port or None,
        "key": f.key,
    }


def _conn_to_dict(c) -> dict:
    return {
        "local_port": getattr(c, "lport", 0),
        "remote_address": getattr(c, "raddr", ""),
        "remote_port": getattr(c, "rport", 0),
        "remote_host": getattr(c, "rhost", ""),
        "status": getattr(c, "status", ""),
        "family": getattr(c, "family", ""),
        "tool": getattr(c, "tool", None),
        "tunnel": getattr(c, "tunnel", None),
        "mesh_vpn": getattr(c, "mesh", None),
        "pid": getattr(c.proc, "pid", None),
        "process": getattr(c.proc, "name", ""),
        "path": getattr(c.proc, "exe", ""),
        "trust": getattr(c.proc, "trust", ""),
        "launched_by": getattr(c.proc, "ancestry", ""),
    }


def result_to_dict(res, full: bool = False) -> dict:
    """The scan as data. `full` adds the raw inventories as well as findings."""
    incomplete = [f.title for f in res.findings
                  if f.category == "Incomplete scan"]
    payload = {
        "schema": SCHEMA_VERSION,
        "tool": "maxport",
        "version": VERSION,
        "ok": True,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": _host_info(),
        "verdict": {
            "code": res.verdict,
            "text": res.verdict_text,
            "exit_code": VERDICT_EXIT.get(res.verdict, EXIT_FINDINGS),
        },
        "profile": res.profile,
        "duration_seconds": round(res.duration, 3),
        "counts": {
            "critical": len(res.by_severity(engine.CRITICAL)),
            "warn": len(res.by_severity(engine.WARN)),
            "info": len(res.by_severity(engine.INFO)),
            "connections": len(res.connections),
            "listening": len(res.listening),
            "suppressed": res.suppressed,
            "downgraded": res.downgraded,
        },
        "complete": not incomplete,
        "incomplete_checks": incomplete,
        "warnings": res.warnings,
        "findings": [finding_to_dict(f) for f in res.findings],
        # The timeline and the revocation list are the parts an agent can act
        # on directly, so they are always present rather than gated behind
        # the inventory flag.
        "timeline": res.timeline,
        "exposure": res.exposure,
    }
    if full:
        payload["connections"] = [_conn_to_dict(c) for c in res.connections]
        payload["listening"] = [_conn_to_dict(c) for c in res.listening]
        payload["persistence"] = res.persistence
        payload["browser_extensions"] = res.extensions
        payload["unattended_access"] = res.unattended
        payload["hardening"] = res.hardening
        payload["execution_trace"] = res.exectrace
        payload["network"] = {"arp": res.arp, "dns": res.dns,
                              "hosts": res.hosts, "interfaces": res.interfaces}
    return payload


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def capabilities() -> list[dict]:
    """What this machine actually lets the tool do, and why not otherwise.

    Exists because "the scan found nothing" and "the scan could not look"
    are indistinguishable from the outside. A caller planning what to trust
    should be able to ask first rather than infer from silence.
    """
    import shutil

    is_windows = platform.system() == "Windows"
    elevated = elevate.is_elevated()
    caps: list[dict] = []

    def add(name, ok, detail, remedy=""):
        caps.append({"capability": name, "available": bool(ok),
                     "detail": detail, "remedy": remedy})

    add("privileges", elevated,
        "running as administrator/root" if elevated
        else "unprivileged — connections will have no process names",
        "" if elevated else elevate.instruction())

    try:
        import psutil
        conns = psutil.net_connections(kind="inet")
        named = sum(1 for c in conns if c.pid)
        add("connection ownership", named > 0,
            f"{named} of {len(conns)} connections resolve to a process",
            "" if named else "run with administrator/root privileges")
    except Exception as e:
        add("connection ownership", False, f"psutil failed: {e}",
            "pip install --upgrade psutil")

    if is_windows:
        ps = bool(shutil.which("powershell"))
        add("signature verification", ps,
            "Authenticode checks via PowerShell" if ps
            else "no PowerShell — executables cannot be checked for a valid "
                 "signature",
            "" if ps else "PowerShell not found on PATH")
        netsh = bool(shutil.which("netsh"))
        add("firewall control", netsh,
            "netsh advfirewall" if netsh else "no netsh — cannot block or "
                                              "isolate",
            "" if netsh else "netsh not found on PATH")
        task = bool(shutil.which("schtasks"))
        add("scheduled revert", task,
            "isolation dead-man's switch survives a crash" if task
            else "isolation would revert only while this program keeps "
                 "running",
            "" if task else "schtasks not found on PATH")
    else:
        backend = respond._firewall_backend()
        add("firewall control", bool(backend),
            f"backend: {backend}" if backend else "no nft, iptables or ufw",
            "" if backend else "install nftables or iptables")
        v6 = bool(shutil.which("ip6tables") or backend == "nft")
        add("IPv6 blocking", v6,
            "IPv6 addresses can be blocked and isolated" if v6
            else "no ip6tables and no nft — IPv6 traffic will NOT be blocked, "
                 "so an isolated machine is only half isolated",
            "" if v6 else "install ip6tables or nftables")
        sched = shutil.which("systemd-run") or shutil.which("at")
        add("scheduled revert", bool(sched),
            f"dead-man's switch via {os.path.basename(sched)}, survives a "
            "crash" if sched else "isolation would revert only while this "
                                  "program keeps running",
            "" if sched else "install systemd or at")
        pkg = bool(shutil.which("dpkg") or shutil.which("rpm"))
        add("package version lookup", pkg,
            "versions read from the package manager, without executing the "
            "binary" if pkg else "no dpkg or rpm — versions can only be read "
                                 "for binaries the system vouches for",
            "" if pkg else "expected on Debian/Kali and RHEL; unusual to lack")

    try:
        pass  # (relative import removed when merging)
        # An empty table is a legitimate state on an isolated host, so the
        # capability is whether it could be read, not whether it had rows.
        entries = netcheck.arp_table()
        add("ARP table", True, f"readable, {len(entries)} entries")
    except Exception as e:
        add("ARP table", False, f"unreadable: {type(e).__name__}: {e}",
            "ARP and MITM detection will not run")

    try:
        import PySide6  # noqa: F401
        add("graphical interface", True, "PySide6 present")
    except ImportError:
        add("graphical interface", False, "PySide6 not installed",
            "pip install PySide6-Essentials (not needed for terminal use)")

    return caps


def cmd_doctor(args) -> int:
    caps = capabilities()
    missing = [c for c in caps if not c["available"]]
    if args.json:
        _emit({"schema": SCHEMA_VERSION, "tool": "maxport", "ok": True,
               "host": _host_info(), "capabilities": caps,
               "degraded": bool(missing)}, True)
    else:
        print(f"\n  MaxPort {VERSION} on {platform.system()} "
              f"{platform.release()}\n")
        for c in caps:
            mark = "ok  " if c["available"] else "MISS"
            print(f"  [{mark}] {c['capability']}: {c['detail']}")
            if c["remedy"]:
                print(f"         -> {c['remedy']}")
        print()
    return EXIT_CLEAR if not missing else EXIT_INCOMPLETE


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def cmd_scan(args) -> int:
    gate = ensure_privilege(args.json, args.allow_partial, args.no_elevate)
    if gate is not None:
        return gate

    store = None
    if not args.no_history:
        try:
            store = Store()
        except Exception as e:
            if args.json:
                pass          # recorded in warnings below, not fatal
            else:
                print(f"  ! history unavailable: {e}", file=sys.stderr)

    def progress(pct, text):
        if not args.json and not args.quiet:
            print(f"  {pct:3d}%  {text}", file=sys.stderr)

    try:
        res = engine.run_scan(deep=not args.fast, store=store,
                              progress=progress)
    except Exception as e:
        return _fail(f"The scan failed: {type(e).__name__}: {e}",
                     EXIT_ERROR, args.json)

    if args.json:
        _emit(result_to_dict(res, full=args.full), True)
    else:
        pass  # (relative import removed when merging)
        print(report(res, show_all=args.all))

    code = VERDICT_EXIT.get(res.verdict, EXIT_FINDINGS)
    # An incomplete scan never reports success, whatever it happened to find.
    if any(f.category == "Incomplete scan" for f in res.findings):
        code = max(code, EXIT_INCOMPLETE)
    return code


def cmd_status(args) -> int:
    """Cheap state query — no scan, safe to poll."""
    isolated, seconds_left = respond.isolate_status()
    payload = {
        "schema": SCHEMA_VERSION, "tool": "maxport", "ok": True,
        "host": _host_info(),
        "isolation": {"active": isolated, "seconds_until_revert": seconds_left},
        "firewall_rules": respond.list_our_rules(),
    }
    if args.json:
        _emit(payload, True)
    else:
        print(f"  host       : {payload['host']['name']} "
              f"({payload['host']['os']})")
        print(f"  privileges : "
              f"{'elevated' if payload['host']['elevated'] else 'limited'}")
        print(f"  isolation  : "
              f"{'ACTIVE, reverts in %ds' % seconds_left if isolated else 'off'}")
        for rule in payload["firewall_rules"]:
            print(f"  rule       : {rule}")
    return EXIT_CLEAR


# --------------------------------------------------------------------------
# actions
# --------------------------------------------------------------------------

ACTION_GATE = (
    "Refused: this changes the state of the machine. Re-run with "
    "--allow-actions to permit it. Actions are opt-in because an automated "
    "caller acting on a misread finding can stop a process the system needs."
)

ISOLATE_GATE = (
    "Refused: isolation cuts network access and can lock you out of a "
    "machine you reach remotely. It needs --allow-actions and "
    "--i-am-at-this-machine together."
)


def cmd_act(args) -> int:
    """Response actions, each behind an explicit grant."""
    as_json = args.json

    if not args.allow_actions:
        return _fail(ISOLATE_GATE if args.action == "isolate" else ACTION_GATE,
                     EXIT_REFUSED, as_json, action=args.action)

    if args.action == "isolate" and not args.i_am_at_this_machine:
        return _fail(ISOLATE_GATE, EXIT_REFUSED, as_json, action=args.action)

    if not elevate.is_elevated():
        return _fail(
            f"'{args.action}' needs administrator/root privileges. "
            f"{elevate.instruction()}", EXIT_NEEDS_PRIVILEGE, as_json)

    if args.dry_run:
        preview = {
            "isolate": respond._revert_shell_command(),
            "block": f"block {args.target} at the firewall, both directions",
            "unblock": f"remove the firewall block for {args.target}",
            "stop": f"terminate process {args.target} after verifying identity",
            "confirm-isolation": "cancel the automatic revert",
        }.get(args.action, "")
        return _fail_ok({"action": args.action, "dry_run": True,
                         "would_run": preview}, as_json)

    try:
        if args.action == "block":
            res = respond.block_ip(args.target)
        elif args.action == "unblock":
            res = respond.unblock_ip(args.target)
        elif args.action == "stop":
            res = respond.stop_process(int(args.target), force=args.force)
        elif args.action == "isolate":
            res = respond.isolate(True, auto_revert=args.revert_after)
        elif args.action == "release":
            res = respond.isolate(False)
        elif args.action == "confirm-isolation":
            res = respond.confirm_isolation()
        else:
            return _fail(f"Unknown action: {args.action}", EXIT_USAGE, as_json)
    except ValueError:
        return _fail(f"'{args.target}' is not valid for {args.action}",
                     EXIT_USAGE, as_json)
    except Exception as e:
        return _fail(f"{args.action} failed: {type(e).__name__}: {e}",
                     EXIT_ERROR, as_json)

    try:
        Store().log_action(args.action, str(args.target or ""), res.ok,
                           res.message)
    except Exception:
        pass          # an unrecordable action still happened; do not hide it

    payload = {"schema": SCHEMA_VERSION, "tool": "maxport", "ok": res.ok,
               "action": args.action, "target": args.target,
               "message": res.message}
    if as_json:
        _emit(payload, True)
    else:
        print(("  " if res.ok else "  ! ") + res.message)
    return EXIT_CLEAR if res.ok else EXIT_ERROR


def _fail_ok(payload: dict, as_json: bool) -> int:
    """A successful no-op, such as a dry run."""
    payload = {"schema": SCHEMA_VERSION, "tool": "maxport", "ok": True,
               **payload}
    if as_json:
        _emit(payload, True)
    else:
        print(f"  would run: {payload.get('would_run')}")
    return EXIT_CLEAR


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="maxport",
        description="Detects remote control, backdoors and exposure on this "
                    "machine.",
        epilog="Exit codes: 0 clear · 1 findings · 2 remote session active · "
               "3 incomplete · 4 needs privileges · 5 usage · 6 refused · "
               "7 error",
    )
    p.add_argument("--version", action="version",
                   version=f"maxport {VERSION} (schema {SCHEMA_VERSION})")

    def common(sp):
        sp.add_argument("--json", action="store_true",
                        help="structured output for programs")
        sp.add_argument("--quiet", action="store_true",
                        help="suppress progress on stderr")
        return sp

    sub = p.add_subparsers(dest="command")

    s = common(sub.add_parser("scan", help="run a full scan"))
    s.add_argument("--fast", action="store_true",
                   help="skip hashing and network lookups")
    s.add_argument("--full", action="store_true",
                   help="include raw inventories in JSON output")
    s.add_argument("--all", action="store_true",
                   help="include informational findings in the report")
    s.add_argument("--allow-partial", action="store_true",
                   help="scan without privileges and accept the blind spot")
    s.add_argument("--no-elevate", action="store_true",
                   help="never offer to relaunch with privileges")
    s.add_argument("--no-history", action="store_true",
                   help="do not read or write the local database")
    s.set_defaults(func=cmd_scan)

    d = common(sub.add_parser(
        "doctor", help="report what this machine lets the tool do"))
    d.set_defaults(func=cmd_doctor)

    st = common(sub.add_parser(
        "status", help="isolation state and active rules — no scan"))
    st.set_defaults(func=cmd_status)

    a = common(sub.add_parser("act", help="response actions (opt-in)"))
    a.add_argument("action", choices=["block", "unblock", "stop", "isolate",
                                      "release", "confirm-isolation"])
    a.add_argument("target", nargs="?", default="",
                   help="an IP address, or a PID for stop")
    a.add_argument("--allow-actions", action="store_true",
                   help="required: permit changing the machine's state")
    a.add_argument("--i-am-at-this-machine", action="store_true",
                   help="required for isolate: confirms you have physical "
                        "or console access and can recover from a lockout")
    a.add_argument("--force", action="store_true",
                   help="kill rather than terminate")
    a.add_argument("--revert-after", type=int, default=600, metavar="SECONDS",
                   help="automatic revert delay for isolate (default 600)")
    a.add_argument("--dry-run", action="store_true",
                   help="print what would happen and change nothing")
    a.set_defaults(func=cmd_act)

    return p


def run_cmdline(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # The interface and the older flag style keep working; anything that is
    # not a subcommand falls through to the legacy path so existing scripts
    # and documentation do not break.
    legacy = {"--cli", "--watch", "--all", "--no-elevate"}
    known = {"scan", "doctor", "status", "act", "--help", "-h", "--version"}
    if argv and argv[0] not in known and set(argv) & legacy:
        pass  # (relative import removed when merging)
        return run(["maxport"] + argv)

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n  interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(run_cmdline())


# ──────────────────────────────────────────────────────────────
# MCP server for agent access
# ──────────────────────────────────────────────────────────────

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
            pass  # (relative import removed when merging)
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


# ──────────────────────────────────────────────────────────────
# Design system
# ──────────────────────────────────────────────────────────────

INK = "#0E1519"
INK_TEXT = "#E8EEF1"      # bright text on the dark instrument panel
PANEL = "#141D23"
RAISED = "#1B262D"
RULE = "#24323A"
TEXT = "#CBD8DE"
MUTED = "#71858F"

STEEL = "#4E9FBE"      # normal reading
AMBER = "#C89438"      # worth a look
ALARM = "#D8564E"      # live control session — used for nothing else
CLEAR = "#57A87E"      # healthy

SEVERITY = {
    "critical": ALARM,
    "warn": AMBER,
    "info": STEEL,
}

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "warn": "WARNING",
    "info": "NOTE",
}

VERDICT_COLOR = {
    "controlled": ALARM,
    "exposed": AMBER,
    "clear": CLEAR,
}

VERDICT_HEAD = {
    "controlled": "Your machine is under external control",
    "exposed": "This machine is partly exposed",
    "clear": "No external control found",
}

MONO = '"JetBrains Mono","Cascadia Mono","DejaVu Sans Mono","Consolas",monospace'
UI = '"Segoe UI","Noto Sans Arabic","Tahoma",sans-serif'

STYLESHEET = f"""
QWidget {{
    background: {INK};
    color: {TEXT};
    font-family: {UI};
    font-size: 14px;
}}

QLabel {{
    background: transparent;
}}

QLabel#verdictHead {{
    font-size: 26px;
    font-weight: 600;
    padding: 0;
}}
QLabel#verdictBody {{
    font-size: 15px;
    color: {TEXT};
}}
QLabel#verdictMeta {{
    font-size: 12px;
    color: {MUTED};
    font-family: {MONO};
}}
QFrame#verdictBar {{
    background: {PANEL};
    border: none;
    border-bottom: 1px solid {RULE};
}}
QFrame#verdictStripe {{
    border: none;
}}

QFrame#navRail {{
    background: {PANEL};
    border-right: 1px solid {RULE};
}}
QPushButton#navItem {{
    background: transparent;
    border: none;
    border-left: 2px solid transparent;
    padding: 11px 16px;
    text-align: left;
    color: {MUTED};
    font-size: 14px;
}}
QPushButton#navItem:hover {{
    color: {TEXT};
    background: {RAISED};
}}
QPushButton#navItem:checked {{
    color: {TEXT};
    border-left: 2px solid {STEEL};
    background: {RAISED};
}}
QLabel#navCount {{
    color: {MUTED};
    font-family: {MONO};
    font-size: 12px;
}}

QPushButton#primary {{
    background: {STEEL};
    color: {INK};
    border: none;
    border-radius: 3px;
    padding: 9px 20px;
    font-weight: 600;
}}
QPushButton#primary:hover {{ background: #63B2D0; }}
QPushButton#primary:disabled {{ background: {RULE}; color: {MUTED}; }}

QPushButton#ghost {{
    background: transparent;
    color: {TEXT};
    border: 1px solid {RULE};
    border-radius: 3px;
    padding: 7px 14px;
}}
QPushButton#ghost:hover {{ border-color: {STEEL}; color: {STEEL}; }}

QPushButton#danger {{
    background: transparent;
    color: {AMBER};
    border: 1px solid {AMBER};
    border-radius: 3px;
    padding: 7px 14px;
}}
QPushButton#danger:hover {{ background: {AMBER}; color: {INK}; }}

QFrame#card {{
    background: {PANEL};
    border: 1px solid {RULE};
    border-radius: 4px;
}}
QLabel#cardTitle {{ font-size: 15px; font-weight: 600; }}
QLabel#cardDetail {{ color: {MUTED}; font-size: 13px; }}
QLabel#sevTag {{
    font-size: 11px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 2px;
}}
QLabel#evidence {{
    font-family: {MONO};
    font-size: 12px;
    color: {MUTED};
}}
QLabel#sectionTitle {{
    font-size: 13px;
    color: {MUTED};
    font-weight: 600;
    letter-spacing: 1px;
}}
QLabel#hint {{ color: {MUTED}; font-size: 12px; }}
QLabel#mono {{ font-family: {MONO}; font-size: 12px; }}

QTableWidget {{
    background: {PANEL};
    alternate-background-color: {RAISED};
    border: 1px solid {RULE};
    border-radius: 4px;
    gridline-color: transparent;
    font-family: {MONO};
    font-size: 12px;
    selection-background-color: {RULE};
    selection-color: {TEXT};
}}
QTableWidget::item {{ padding: 6px 8px; border: none; }}
QHeaderView::section {{
    background: {INK};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {RULE};
    padding: 8px;
    font-family: {UI};
    font-size: 12px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {INK}; border: none; }}

QScrollArea {{ border: none; background: {INK}; }}
QScrollBar:vertical {{
    background: {INK}; width: 9px; margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {RULE}; border-radius: 4px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar:horizontal {{ background: {INK}; height: 9px; }}
QScrollBar::handle:horizontal {{ background: {RULE}; border-radius: 4px; }}

QProgressBar {{
    background: {RULE};
    border: none;
    height: 2px;
    text-align: center;
}}
QProgressBar::chunk {{ background: {STEEL}; }}

QTextEdit, QPlainTextEdit {{
    background: {PANEL};
    border: 1px solid {RULE};
    border-radius: 4px;
    font-family: {MONO};
    font-size: 12px;
    padding: 8px;
}}
QLineEdit {{
    background: {PANEL};
    border: 1px solid {RULE};
    border-radius: 3px;
    padding: 7px 10px;
    font-family: {MONO};
}}
QLineEdit:focus {{ border-color: {STEEL}; }}

QToolTip {{
    background: {RAISED};
    color: {TEXT};
    border: 1px solid {RULE};
    padding: 6px;
}}
QMessageBox {{ background: {PANEL}; }}
"""


# ──────────────────────────────────────────────────────────────
# Interface components
# ──────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────
# Monitoring page
# ──────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────
# Agent access page
# ──────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────
# Startup animation
# ──────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────
# Main window
# ──────────────────────────────────────────────────────────────

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
        pass  # (relative import removed when merging)
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
        pass  # (relative import removed when merging)
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
        pass  # (relative import removed when merging)
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
        pass  # (relative import removed when merging)
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
        pass  # (relative import removed when merging)
        return run(sys.argv)

    # Without privileges the scan is half-blind. Offer to relaunch elevated
    # before drawing anything, unless the user explicitly declined with
    # --no-elevate (useful when they know they cannot, and want the partial
    # scan anyway).
    pass  # (relative import removed when merging)
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



if __name__ == "__main__":
    sys.exit(main())
