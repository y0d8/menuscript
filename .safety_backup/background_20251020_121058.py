#!/usr/bin/env python3
"""
menuscript.engine.background — cleaned v1

Simple job queue + worker for menuscript.

Design choices (v1):
- Single-worker loop (safe, easy to reason about)
- Jobs persisted to ~/.menuscript/jobs.db using sqlite3
- Args stored as JSON lists (['-u','http://...','-w','wl.txt'])
- run_scan_sync imported at module level so tests can monkeypatch it
- Lightweight TypedDict for JobRecord (T2)
- start_worker/stop_worker with sane guards
- C4-style comments peppered in — readable and cheeky
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
import json
import time
import threading
import traceback
from typing import Optional, List, Dict, Any, TypedDict

# ---- Module-level imports (clean + testable) -------------------------------
# Import the manager-runner at module load time so tests can monkeypatch it.
# This avoids trying to import inside the worker loop and causing attribute errors.
try:
    # preferred local import
    from .manager import run_scan_sync  # type: ignore
except Exception:
    # fallback absolute import (rare environments)
    from menuscript.engine.manager import run_scan_sync  # type: ignore

# ---- DB path & helpers -----------------------------------------------------
JOBS_DB = Path.home() / ".menuscript" / "jobs.db"
JOBS_DB.parent.mkdir(parents=True, exist_ok=True)

def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _conn():
    return sqlite3.connect(str(JOBS_DB))

# ---- TypedDict for Job record (T2) ---------------------------------------
class JobRecord(TypedDict, total=False):
    id: int
    tool: str
    target: str
    args: List[str]
    label: str
    status: str
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    result_scan_id: Optional[int]
    error: Optional[str]

# ---------------- DB init / CRUD --------------------------------------------
def init_jobs_db() -> None:
    """Create table if missing; idempotent."""
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT,
                target TEXT,
                args TEXT,
                label TEXT,
                status TEXT,
                created_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                result_scan_id INTEGER,
                error TEXT
            )
            """
        )
        c.commit()

def enqueue_job(tool: str, target: str, args: List[str], label: Optional[str]=None) -> int:
    """Add a job (status=queued) and return its id."""
    init_jobs_db()
    ts = _now_ts()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO jobs (tool,target,args,label,status,created_at) VALUES (?,?,?,?,?,?)",
            (tool, target, json.dumps(args), label or "", "queued", ts),
        )
        c.commit()
        return int(cur.lastrowid)

def get_job(job_id: int) -> Optional[JobRecord]:
    """Fetch single job by id or return None."""
    init_jobs_db()
    with _conn() as c:
        r = c.execute(
            "SELECT id,tool,target,args,label,status,created_at,started_at,finished_at,result_scan_id,error FROM jobs WHERE id=?",
            (job_id,),
        ).fetchone()
    if not r:
        return None
    return JobRecord(
        id=r[0],
        tool=r[1],
        target=r[2],
        args=json.loads(r[3] or "[]"),
        label=r[4],
        status=r[5],
        created_at=r[6],
        started_at=r[7],
        finished_at=r[8],
        result_scan_id=r[9],
        error=r[10],
    )

def list_jobs(limit: int = 200, status: Optional[str] = None) -> List[JobRecord]:
    """Return list of jobs (newest first)."""
    init_jobs_db()
    q = "SELECT id,tool,target,args,label,status,created_at,started_at,finished_at,result_scan_id FROM jobs"
    params: List[Any] = []
    if status:
        q += " WHERE status=?"
        params.append(status)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _conn() as c:
        rows = c.execute(q, params).fetchall()
    out: List[JobRecord] = []
    for r in rows:
        out.append(JobRecord(
            id=r[0],
            tool=r[1],
            target=r[2],
            args=json.loads(r[3] or "[]"),
            label=r[4],
            status=r[5],
            created_at=r[6],
            started_at=r[7],
            finished_at=r[8],
            result_scan_id=r[9],
        ))
    return out

# ----------------- internal state setters -----------------------------------
def _set_job_started(job_id: int) -> None:
    ts = _now_ts()
    with _conn() as c:
        c.execute("UPDATE jobs SET status=?, started_at=? WHERE id=?", ("running", ts, job_id))
        c.commit()

def _set_job_finished(job_id: int, scan_id: Optional[int], error: Optional[str] = None) -> None:
    ts = _now_ts()
    status = "done" if not error else "failed"
    with _conn() as c:
        c.execute(
            "UPDATE jobs SET status=?, finished_at=?, result_scan_id=?, error=? WHERE id=?",
            (status, ts, scan_id or None, error or "", job_id),
        )
        c.commit()

def _set_job_error(job_id: int, err: str) -> None:
    ts = _now_ts()
    with _conn() as c:
        c.execute("UPDATE jobs SET status=?, finished_at=?, error=? WHERE id=?", ("failed", ts, err, job_id))
        c.commit()

# ----------------- Worker loop & control -----------------------------------
_worker_thread: Optional[threading.Thread] = None
_worker_stop = threading.Event()
_worker_lock = threading.Lock()

def worker_loop(poll_interval: float = 2.0):
    """
    Run queued jobs in FIFO order. Each job calls run_scan_sync(tool, target, args, label).
    This function is safe to run in thread context.
    """
    init_jobs_db()
    print("menuscript background worker: starting loop (ctrl-C to stop)")

    while not _worker_stop.is_set():
        try:
            with _conn() as c:
                row = c.execute("SELECT id,tool,target,args,label FROM jobs WHERE status='queued' ORDER BY id ASC LIMIT 1").fetchone()
            if row:
                job_id, tool, target, args_json, label = row
                args = json.loads(args_json or "[]")
                _set_job_started(job_id)
                try:
                    # call the manager to run the plugin, synchronous call that records history
                    scan_id = run_scan_sync(tool, target, args, label or "", save_xml=False)
                    _set_job_finished(job_id, scan_id, None)
                except Exception as e:
                    tb = traceback.format_exc()
                    _set_job_error(job_id, tb)
                # immediately continue to next job
                continue
            # nothing queued: sleep until signalled or timeout
            _worker_stop.wait(poll_interval)
        except Exception:
            traceback.print_exc()
            _worker_stop.wait(poll_interval)

def start_worker(detach: bool = False) -> threading.Thread:
    """
    Start the worker in a thread.
    - detach=True => daemon thread (won't block process exit)
    - returns thread object; if already running returns existing thread
    """
    global _worker_thread, _worker_stop
    with _worker_lock:
        if _worker_thread and _worker_thread.is_alive():
            return _worker_thread
        _worker_stop.clear()
        t = threading.Thread(target=worker_loop, daemon=detach)
        _worker_thread = t
        t.start()
        return t

def stop_worker(timeout: float = 2.0) -> None:
    """Signal worker to stop and join thread (best-effort)."""
    global _worker_thread, _worker_stop
    _worker_stop.set()
    if _worker_thread:
        _worker_thread.join(timeout=timeout)
