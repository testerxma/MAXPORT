"""Historical record kept in SQLite.

A point-in-time scan misses intermittent connections, and many remote
control tools connect for seconds every few minutes. History exposes them.
"""

from __future__ import annotations

import json
import os
import platform
import sqlite3
import threading
import time

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
