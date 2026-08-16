"""Design system.

The idea is a cool instrument panel. Red is reserved for exactly one state,
a live control session, and appears nowhere else. Seeing it means one thing.

All network data (IPs, MACs, ports, hashes, paths) is set in a monospaced
face so columns align and a hash can be read character by character.
"""

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
