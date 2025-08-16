import sqlite3
from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime, timedelta, timezone

DB_PATH = Path("/data/nemesis.db")

def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    with _conn() as conn:
        c = conn.cursor()
        # Rules
        c.execute("""
CREATE TABLE IF NOT EXISTS rules_shadow(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        c.execute("""
CREATE TABLE IF NOT EXISTS rules_live(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        # Findings / Job-Logs
        c.execute("""
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  details TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        c.execute("""
CREATE TABLE IF NOT EXISTS jobs_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job TEXT NOT NULL,
  level TEXT NOT NULL,
  msg TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        # Bounty-Plattformen
        c.execute("""
CREATE TABLE IF NOT EXISTS bounty_platforms(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  base_url TEXT,
  api_key TEXT,
  enabled INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        # Targets
        c.execute("""
CREATE TABLE IF NOT EXISTS bounty_targets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  platform_id INTEGER,
  target TEXT NOT NULL,
  scope TEXT,
  status TEXT DEFAULT 'queued',       -- queued, scanning, scanned, error
  last_scanned_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(platform_id) REFERENCES bounty_platforms(id)
)""")
        # Module Status
        c.execute("""
CREATE TABLE IF NOT EXISTS modules_status(
  module TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  message TEXT,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        # Workers
        c.execute("""
CREATE TABLE IF NOT EXISTS workers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'online', -- online/offline
  last_heartbeat DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        conn.commit()

# --- Rules / Findings / Jobs ---
def add_shadow_rule(pattern: str) -> int:
    with _conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO rules_shadow(pattern) VALUES(?)", (pattern,))
        conn.commit()
        return c.lastrowid

def get_latest_shadow_rule_id() -> Optional[int]:
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT id FROM rules_shadow ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else None

def list_recent_shadow_ids(limit: int = 10) -> List[int]:
    with _conn() as conn:
        c = conn.cursor()
        rows = c.execute("SELECT id FROM rules_shadow ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [r[0] for r in rows]

def promote_shadow_to_live(rule_id: int) -> Optional[int]:
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT pattern FROM rules_shadow WHERE id=?", (rule_id,)).fetchone()
        if not row:
            return None
        pattern = row[0]
        c.execute("INSERT INTO rules_live(pattern) VALUES(?)", (pattern,))
        conn.commit()
        return c.lastrowid

def add_finding(title: str, severity: str, details: str = "") -> int:
    with _conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO findings(title,severity,details) VALUES(?,?,?)", (title, severity, details))
        conn.commit()
        return c.lastrowid

def log_job(job: str, level: str, msg: str):
    with _conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO jobs_log(job,level,msg) VALUES(?,?,?)", (job, level, msg))
        conn.commit()

def recent_findings(limit: int = 25) -> List[Tuple]:
    with _conn() as conn:
        c = conn.cursor()
        return c.execute("SELECT id,title,severity,details,created_at FROM findings ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

def list_rules(limit: int = 50):
    with _conn() as conn:
        c = conn.cursor()
        shadow = c.execute("SELECT id,pattern,created_at FROM rules_shadow ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        live   = c.execute("SELECT id,pattern,created_at FROM rules_live ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return shadow, live

def recent_jobs(limit: int = 50):
    with _conn() as conn:
        c = conn.cursor()
        return c.execute("SELECT id,job,level,msg,created_at FROM jobs_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

# --- Bounty Platforms / Targets ---
def upsert_platform(name: str, base_url: str | None, api_key: str | None, enabled: bool = True) -> int:
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT id FROM bounty_platforms WHERE name=?", (name,)).fetchone()
        if row:
            c.execute("UPDATE bounty_platforms SET base_url=?, api_key=?, enabled=?, created_at=CURRENT_TIMESTAMP WHERE id=?",
                      (base_url, api_key, 1 if enabled else 0, row[0]))
            conn.commit()
            return row[0]
        c.execute("INSERT INTO bounty_platforms(name, base_url, api_key, enabled) VALUES(?,?,?,?)",
                  (name, base_url, api_key, 1 if enabled else 0))
        conn.commit()
        return c.lastrowid

def list_platforms():
    with _conn() as conn:
        c = conn.cursor()
        return c.execute("SELECT id,name,base_url,enabled,created_at FROM bounty_platforms ORDER BY id DESC").fetchall()

def set_platform_enabled(pid: int, enabled: bool):
    with _conn() as conn:
        c = conn.cursor()
        c.execute("UPDATE bounty_platforms SET enabled=? WHERE id=?", (1 if enabled else 0, pid))
        conn.commit()

def add_or_queue_target(platform_id: int, target: str, scope: str | None = None):
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT id FROM bounty_targets WHERE platform_id=? AND target=?", (platform_id, target)).fetchone()
        if row:
            return row[0]
        c.execute("INSERT INTO bounty_targets(platform_id,target,scope,status) VALUES(?,?,?,'queued')",
                  (platform_id, target, scope))
        conn.commit()
        return c.lastrowid

def list_targets(limit: int = 50):
    with _conn() as conn:
        c = conn.cursor()
        return c.execute("""
SELECT t.id, p.name, t.target, t.scope, t.status, t.last_scanned_at, t.created_at
FROM bounty_targets t
LEFT JOIN bounty_platforms p ON p.id=t.platform_id
ORDER BY t.id DESC LIMIT ?
""", (limit,)).fetchall()

def pop_next_queued_target() -> Optional[tuple]:
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT id,platform_id,target,scope FROM bounty_targets WHERE status='queued' ORDER BY id ASC LIMIT 1").fetchone()
        if not row:
            return None
        c.execute("UPDATE bounty_targets SET status='scanning' WHERE id=?", (row[0],))
        conn.commit()
        return row

def mark_target_scanned(tid: int, ok: bool, when: str):
    with _conn() as conn:
        c = conn.cursor()
        new_status = 'scanned' if ok else 'error'
        c.execute("UPDATE bounty_targets SET status=?, last_scanned_at=? WHERE id=?", (new_status, when, tid))
        conn.commit()

# --- Module status helpers ---
def set_module_status(module: str, status: str, message: str = ""):
    with _conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO modules_status(module,status,message,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) "
                  "ON CONFLICT(module) DO UPDATE SET status=excluded.status, message=excluded.message, updated_at=CURRENT_TIMESTAMP",
                  (module, status, message))
        conn.commit()

def get_all_module_status():
    with _conn() as conn:
        c = conn.cursor()
        return c.execute("SELECT module,status,message,updated_at FROM modules_status ORDER BY module ASC").fetchall()

# --- Metrics ---
def count_running_scans() -> int:
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT COUNT(*) FROM bounty_targets WHERE status='scanning'").fetchone()
        return row[0] if row else 0

def research_progress() -> dict:
    with _conn() as conn:
        c = conn.cursor()
        total = c.execute("SELECT COUNT(*) FROM bounty_targets").fetchone()[0]
        scanned = c.execute("SELECT COUNT(*) FROM bounty_targets WHERE status IN ('scanned','error')").fetchone()[0]
        percent = int((scanned / total) * 100) if total else 0
        return {"total": total, "scanned": scanned, "percent": percent}

# --- Workers ---
def register_worker(name: str, token: str):
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT id FROM workers WHERE name=?", (name,)).fetchone()
        if row:
            c.execute("UPDATE workers SET token=?, status='online', last_heartbeat=? WHERE id=?", (token, now, row[0]))
            conn.commit()
            return row[0]
        c.execute("INSERT INTO workers(name, token, status, last_heartbeat) VALUES(?,?, 'online', ?)",
                  (name, token, now))
        conn.commit()
        return c.lastrowid

def heartbeat_worker(name: str, token: str) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT id, token FROM workers WHERE name=?", (name,)).fetchone()
        if not row:
            return False
        if row[1] != token:
            return False
        c.execute("UPDATE workers SET status='online', last_heartbeat=? WHERE id=?", (now, row[0]))
        conn.commit()
        return True

def list_workers():
    with _conn() as conn:
        c = conn.cursor()
        return c.execute("SELECT id,name,status,last_heartbeat,created_at FROM workers ORDER BY id DESC").fetchall()

def count_workers_online(minutes: int = 5) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    with _conn() as conn:
        c = conn.cursor()
        row = c.execute("SELECT COUNT(*) FROM workers WHERE status='online' AND (last_heartbeat IS NOT NULL AND last_heartbeat >= ?)", (cutoff,)).fetchone()
        return row[0] if row else 0

def mark_stale_workers_offline(minutes: int = 5) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    with _conn() as conn:
        c = conn.cursor()
        c.execute("UPDATE workers SET status='offline' WHERE last_heartbeat IS NULL OR last_heartbeat < ?", (cutoff,))
        conn.commit()
        return c.rowcount
