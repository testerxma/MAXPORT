"""Regaining privileges by relaunching, rather than only complaining.

Without administrator on Windows or root on Linux the tool sees a fraction
of what matters: connections show no owning process, the firewall refuses
every action, and whole checks return nothing. Detecting that state and
printing a warning — which is all the tool did before — leaves the user to
fix it themselves, and most will simply run the crippled scan and trust its
reassuring "nothing found".

So this module tries to relaunch the tool with privileges the moment it
notices it lacks them. Each platform has one correct mechanism, and each can
fail for legitimate reasons (a user who cancels the prompt, a system with no
polkit agent), so every path degrades to a clear instruction rather than a
crash.

The relaunch is never silent or automatic-on-import: the caller decides when
to offer it, and the user always sees the OS consent prompt. Nothing here
escalates without an explicit human click.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys

IS_WINDOWS = platform.system() == "Windows"


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
