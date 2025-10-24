#!/usr/bin/env python3
"""
menuscript.engine.background — plugin-aware job queue + worker (file-backed)

Design notes:
 - Small, robust JSON-backed job store (data/jobs/jobs.json)
 - Logs to data/jobs/<job_id>.log
 - Plugin-first execution: attempt to call plugin.run(target, args, label, log_path)
 - Fallback to subprocess.run([tool, ...]) if plugin not available
 - Worker supports foreground (--fg) and background start
 - Long-running tool kill timeout: 300s (5 minutes)
 - Minimal, clean logging to worker.log and per-job logs
 - Auto-parse results into database when jobs complete
"""

from __future__ import annotations
import os
import sys
import json
import time
import tempfile
import shutil
import subprocess
import threading
import inspect
from typing import List, Dict, Optional, Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR = os.path.join(ROOT, "data")
JOBS_DIR = os.path.join(DATA_DIR, "jobs")
LOGS_DIR = os.path.join(DATA_DIR, "logs")
JOBS_FILE = os.path.join(JOBS_DIR, "jobs.json")
WORKER_LOG = os.path.join(LOGS_DIR, "worker.log")
JOB_TIMEOUT_SECONDS = 3600  # 1 hour (changed from 300s/5min)

_lock = threading.Lock()

def _ensure_dirs():
    os.makedirs(JOBS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

def _read_jobs() -> List[Dict[str,Any]]:
    _ensure_dirs()
    if not os.path.exists(JOBS_FILE):
        return []
    try:
        with open(JOBS_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        try:
            corrupt = JOBS_FILE + ".corrupt." + str(int(time.time()))
            shutil.move(JOBS_FILE, corrupt)
            _append_worker_log(f"jobs file corrupt; moved to {corrupt}")
        except Exception:
            pass
        return []

def _write_jobs(jobs: List[Dict[str,Any]]):
    _ensure_dirs()
    tmp = tempfile.NamedTemporaryFile("w", delete=False, dir=JOBS_DIR, encoding="utf-8")
    try:
        json.dump(jobs, tmp, indent=2, ensure_ascii=False)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.replace(tmp.name, JOBS_FILE)
    finally:
        if os.path.exists(tmp.name):
            try:
                os.remove(tmp.name)
            except Exception:
                pass

def _append_worker_log(msg: str):
    _ensure_dirs()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"{ts} {msg}\n"
    with open(WORKER_LOG, "a", encoding="utf-8", errors="replace") as fh:
        fh.write(line)

def _next_job_id(jobs: List[Dict[str,Any]]) -> int:
    maxid = 0
    for j in jobs:
        try:
            if isinstance(j.get("id"), int) and j["id"] > maxid:
                maxid = j["id"]
        except Exception:
            continue
    return maxid + 1

def enqueue_job(tool: str, target: str, args: List[str], label: str="") -> int:
    with _lock:
        jobs = _read_jobs()
        jid = _next_job_id(jobs)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        job = {
            "id": jid,
            "tool": tool,
            "target": target,
            "args": args or [],
            "label": label or "",
            "status": "queued",
            "created_at": now,
            "started_at": None,
            "finished_at": None,
            "result_scan_id": None,
            "error": None,
            "log": os.path.join(JOBS_DIR, f"{jid}.log"),
            "pid": None
        }
        jobs.append(job)
        _write_jobs(jobs)
    _append_worker_log(f"enqueued job {jid}: {tool} {target}")
    return jid

def list_jobs(limit:int=100) -> List[Dict[str,Any]]:
    jobs = _read_jobs()
    return sorted(jobs, key=lambda x: x.get("created_at",""), reverse=True)[:limit]

def get_job(jid:int) -> Optional[Dict[str,Any]]:
    jobs = _read_jobs()
    for j in jobs:
        if j.get("id") == jid:
            return j
    return None

def kill_job(jid: int) -> bool:
    """
    Kill a job by removing it from queue or sending SIGTERM to its process.

    Args:
        jid: Job ID to kill

    Returns:
        True if job was killed/removed, False if not found
    """
    job = get_job(jid)
    if not job:
        return False

    status = job.get('status')
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Handle queued jobs - just mark as killed
    if status == 'queued':
        _update_job(jid, status="killed", finished_at=now)
        _append_worker_log(f"job {jid}: removed from queue")
        return True
    
    # Handle error jobs - mark as killed
    if status == 'error':
        _update_job(jid, status="killed", finished_at=now)
        _append_worker_log(f"job {jid}: marked as killed")
        return True

    # Handle running jobs - send signal
    if status == 'running':
        pid = job.get('pid')
        if not pid:
            _update_job(jid, status="killed", finished_at=now)
            return True

        try:
            import signal
            # Try SIGTERM first (graceful)
            os.kill(pid, signal.SIGTERM)
            _append_worker_log(f"job {jid}: sent SIGTERM to PID {pid}")

            # Update job status
            _update_job(jid, status="killed", finished_at=now, pid=None)
            return True
        except ProcessLookupError:
            # Process already dead
            _update_job(jid, status="killed", finished_at=now, pid=None)
            return True
        except PermissionError:
            _append_worker_log(f"job {jid}: permission denied to kill PID {pid}")
            return False
        except Exception as e:
            _append_worker_log(f"job {jid}: error killing process: {e}")
            return False

    # Job is in some other state (done, killed, etc.)
    return False

def _update_job(jid:int, **fields):
    with _lock:
        jobs = _read_jobs()
        changed = False
        for j in jobs:
            if j.get("id") == jid:
                j.update(fields)
                changed = True
                break
        if changed:
            _write_jobs(jobs)

def _try_run_plugin(tool: str, target: str, args: List[str], label: str, log_path: str) -> tuple:
    try:
        from .loader import discover_plugins
        
        plugins = discover_plugins()
        plugin = None
        
        plugin = plugins.get(tool.lower())
        
        if not plugin:
            for key, p in plugins.items():
                try:
                    plugin_tool = getattr(p, "tool", "").lower()
                    plugin_name = getattr(p, "name", "").lower()
                    if tool.lower() in (plugin_tool, plugin_name):
                        plugin = p
                        break
                except Exception:
                    continue
        
        if not plugin:
            return (False, 0)
        
        run_method = getattr(plugin, "run", None)
        if not callable(run_method):
            return (False, 0)
        
        sig = inspect.signature(run_method)
        params = list(sig.parameters.keys())
        
        with open(log_path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(f"=== Plugin: {getattr(plugin, 'name', tool)} ===\n")
            fh.write(f"Target: {target}\n")
            fh.write(f"Args: {args}\n")
            fh.write(f"Label: {label}\n")
            fh.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
        
        try:
            if 'log_path' in params or len(params) >= 4:
                rc = run_method(target, args or [], label or "", log_path)
            else:
                result = run_method(target, args or [], label or "")
                
                if isinstance(result, tuple) and len(result) >= 2:
                    rc, old_logpath = result[0], result[1]
                    if old_logpath and os.path.exists(old_logpath) and old_logpath != log_path:
                        try:
                            with open(old_logpath, "r", encoding="utf-8", errors="replace") as src:
                                with open(log_path, "a", encoding="utf-8", errors="replace") as dst:
                                    dst.write("\n=== Plugin Output ===\n")
                                    dst.write(src.read())
                        except Exception as e:
                            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                                fh.write(f"\nWarning: Could not copy old log: {e}\n")
                elif isinstance(result, int):
                    rc = result
                else:
                    rc = 0
            
            if not isinstance(rc, int):
                rc = 0 if rc is None else 1
            
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\n=== Completed: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} ===\n")
                fh.write(f"Exit Code: {rc}\n")
            
            return (True, rc)
            
        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\n=== PLUGIN ERROR ===\n")
                fh.write(f"{type(e).__name__}: {e}\n")
            return (True, 1)
    
    except Exception as e:
        _append_worker_log(f"plugin loading error: {e}")
        return (False, 0)

def _run_subprocess(tool: str, target: str, args: List[str], log_path: str, jid: int = None, timeout: int = JOB_TIMEOUT_SECONDS) -> int:
    cmd = [tool] + (args or [])
    cmd = [c.replace("<target>", target) for c in cmd]

    with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
        fh.write(f"=== Subprocess Execution ===\n")
        fh.write(f"Command: {' '.join(cmd)}\n")
        fh.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
        fh.flush()

        try:
            proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT)

            # Store PID if job ID provided
            if jid is not None:
                _update_job(jid, pid=proc.pid)
                _append_worker_log(f"job {jid}: running with PID {proc.pid}")

            # Wait for process with timeout
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                fh.write(f"\nERROR: Command timed out after {timeout} seconds\n")
                return 124

            fh.write(f"\n=== Completed: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} ===\n")
            fh.write(f"Exit Code: {proc.returncode}\n")
            return proc.returncode

        except FileNotFoundError:
            fh.write(f"\nERROR: Tool not found: {cmd[0]}\n")
            return 127
        except Exception as e:
            fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1

def run_job(jid: int) -> None:
    job = get_job(jid)
    if not job:
        _append_worker_log(f"run_job: job {jid} not found")
        return
    
    log_path = job.get("log") or os.path.join(JOBS_DIR, f"{jid}.log")
    _ensure_dirs()
    
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _update_job(jid, status="running", started_at=now)
    _append_worker_log(f"job {jid} started: {job.get('tool')} {job.get('target')}")
    
    try:
        tool = job.get("tool", "")
        target = job.get("target", "")
        args = job.get("args", [])
        label = job.get("label", "")
        
        plugin_executed, rc = _try_run_plugin(tool, target, args, label, log_path)

        if not plugin_executed:
            _append_worker_log(f"job {jid}: no plugin found for '{tool}', using subprocess")
            rc = _run_subprocess(tool, target, args, log_path, jid=jid, timeout=JOB_TIMEOUT_SECONDS)
        
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        status = "done" if rc == 0 else "error"
        _update_job(jid, status=status, finished_at=now, pid=None)
        
        # Try to parse results into database
        try:
            from .result_handler import handle_job_result
            # Re-fetch job to get updated data
            job = get_job(jid)
            parse_result = handle_job_result(job)
            if parse_result:
                if 'error' in parse_result:
                    _append_worker_log(f"job {jid} parse error: {parse_result['error']}")
                else:
                    _append_worker_log(f"job {jid} parsed: {parse_result}")
        except Exception as e:
            _append_worker_log(f"job {jid} parse exception: {e}")
        
        _append_worker_log(f"job {jid} finished: status={status} rc={rc}")
        
    except Exception as e:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _update_job(jid, status="error", error=str(e), finished_at=now)
        _append_worker_log(f"job {jid} crashed: {e}")

def worker_loop(poll_interval: float = 2.0):
    _ensure_dirs()
    _append_worker_log("menuscript background worker: starting loop")
    
    try:
        while True:
            jobs = _read_jobs()
            queued = [j for j in jobs if j.get("status") == "queued"]
            
            if not queued:
                time.sleep(poll_interval)
                continue
            
            queued_sorted = sorted(queued, key=lambda x: x.get("created_at", ""))
            job = queued_sorted[0]
            jid = job.get("id")
            
            try:
                run_job(jid)
            except Exception as e:
                _append_worker_log(f"run_job exception for {jid}: {e}")
            
    except KeyboardInterrupt:
        _append_worker_log("worker: KeyboardInterrupt, shutting down")
    except Exception as e:
        _append_worker_log(f"worker loop stopped with exception: {e}")

def start_worker(detach: bool = True, fg: bool = False):
    if fg:
        worker_loop()
        return
    
    if detach:
        python = sys.executable or "python3"
        cmd = [python, "-u", "-c", 
               "import sys; from menuscript.engine.background import worker_loop; worker_loop()"]
        subprocess.Popen(cmd, stdout=open(WORKER_LOG, "a"), stderr=subprocess.STDOUT, close_fds=True)
        _append_worker_log("Started background worker (detached)")
