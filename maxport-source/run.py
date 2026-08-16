#!/usr/bin/env python3
"""MaxPort entry point.

For complete results, run it with administrator/root privileges:
  Windows : open PowerShell as Administrator, then  python run.py
  Linux   : sudo -E python3 run.py

Text mode is dispatched before the interface is imported, so --cli and
--watch work on a machine with no PySide6 installed. That matters: the
machine someone is checking in a hurry is exactly the one least likely to
have a GUI toolkit ready.
"""
import sys

if __name__ == "__main__":
    if any(a in sys.argv for a in ("--cli", "--watch")):
        from maxport.cli import run
        sys.exit(run(sys.argv))
    try:
        from maxport.ui.app import main
    except ImportError as e:
        print(f"The graphical interface could not start: {e}\n"
              "  pip install PySide6-Essentials\n"
              "Text mode works without it:  python run.py --cli")
        sys.exit(1)
    sys.exit(main())
