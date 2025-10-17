#!/usr/bin/env python3
"""
SQLite storage helper for menuscript.

Provides:
- init_db()             -> create DB & tables
- insert_scan(scan)     -> insert a scan dict, returns scan_id
- update_scan(scan_id, **fields)
- get_scans(limit, tool)
- get_scan(scan_id)
- simple migration helper to import old history JSON entries
"""
from pathlib import Path
import sqlite3
import json
from typing import Optional, List, Dict, Any
from ..utils import ensure_dirs, HISTORY_FILE, read_json

DB_PATH = Path.home() / ".menuscript" / "menuscript.db"
ensure_dirs()  # ensure ~/.menuscript exists

def _get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        tool TEXT,
        target TEXT,
        label TEXT,
        args TEXT,
        log_path TEXT,
        raw_path TEXT,
        summary TEXT,
        per_host TEXT,
        status TEXT,
        rc INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool);
    CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
    CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);
    """)
    conn.commit()
    conn.close()

def insert_scan(entry: Dict[str, Any]) -> int:
    """
    Insert a scan entry (dict). Fields expected:
      ts, tool, target, label, args (list), log, xml, summary (dict), per_host (list), status, rc
    Returns the inserted scan id.
    """
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO scans (ts, tool, target, label, args, log_path, raw_path, summary, per_host, status, rc)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.get("ts"),
        entry.get("tool"),
        entry.get("target"),
        entry.get("label"),
        json.dumps(entry.get("args") or []),
        entry.get("log"),
        entry.get("xml"),
        json.dumps(entry.get("summary") or {}),
        json.dumps(entry.get("per_host") or []),
        entry.get("status") or "pending",
        entry.get("rc")
    ))
    conn.commit()
    rowid = cur.lastrowid
    conn.close()
    return rowid

def update_scan(scan_id: int, **fields):
    """
    Update fields for a scan id. Values are JSON-serialized if needed.
    """
    if not fields:
        return
    allowed = {"ts","tool","target","label","args","log_path","raw_path","log","xml","summary","per_host","status","rc"}
    set_clauses, values = [], []
    for k, v in fields.items():
        if k == "log":  # support legacy key
            k_db = "log_path"
        elif k == "xml":
            k_db = "raw_path"
        else:
            k_db = k
        if k_db not in ("ts","tool","target","label","args","log_path","raw_path","summary","per_host","status","rc"):
            continue
        if k_db in ("args","summary","per_host"):
            set_clauses.append(f"{k_db} = ?")
            values.append(json.dumps(v))
        else:
            set_clauses.append(f"{k_db} = ?")
            values.append(v)
    if not set_clauses:
        return
    sql = "UPDATE scans SET " + ", ".join(set_clauses) + " WHERE id = ?"
    values.append(scan_id)
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(sql, values)
    conn.commit()
    conn.close()

def get_scans(limit: int=100, tool: Optional[str]=None) -> List[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    if tool:
        cur.execute("SELECT * FROM scans WHERE tool = ? ORDER BY id DESC LIMIT ?", (tool, limit))
    else:
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "ts": r["ts"],
            "tool": r["tool"],
            "target": r["target"],
            "label": r["label"],
            "args": json.loads(r["args"] or "[]"),
            "log": r["log_path"],
            "xml": r["raw_path"],
            "summary": json.loads(r["summary"] or "{}"),
            "per_host": json.loads(r["per_host"] or "[]"),
            "status": r["status"],
            "rc": r["rc"]
        })
    return out

def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "ts": row["ts"],
        "tool": row["tool"],
        "target": row["target"],
        "label": row["label"],
        "args": json.loads(row["args"] or "[]"),
        "log": row["log_path"],
        "xml": row["raw_path"],
        "summary": json.loads(row["summary"] or "{}"),
        "per_host": json.loads(row["per_host"] or "[]"),
        "status": row["status"],
        "rc": row["rc"]
    }

def import_json_history_to_db():
    """
    If an old HISTORY_FILE (JSON list) exists, import entries into DB.
    This is idempotent-ish: it inserts entries and does not remove the file.
    """
    try:
        old = read_json(HISTORY_FILE)
    except Exception:
        old = []
    if not old:
        return 0
    init_db()
    inserted = 0
    for e in reversed(old):  # oldest first
        entry = {
            "ts": e.get("ts"),
            "tool": e.get("tool", "nmap"),
            "target": e.get("target"),
            "label": e.get("label"),
            "args": e.get("args") or [],
            "log": e.get("log"),
            "xml": e.get("xml"),
            "summary": e.get("summary") or {},
            "per_host": (e.get("summary") or {}).get("per_host") or []
        }
        insert_scan(entry)
        inserted += 1
    return inserted
