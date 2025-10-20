import pytest
import sqlite3
from pathlib import Path
import json
import time

# ensure the module is importable
import menuscript.engine.background as bg

def fake_run_scan_sync(tool, target, args, label, save_xml=False):
    # Fake a scan run and return a fake scan id.
    # Simulate a short delay to exercise the worker loop.
    time.sleep(0.01)
    return 12345

def test_enqueue_and_list(monkeypatch, tmp_path):
    # point jobs.db to a temp location for isolation
    jobs_db = Path.home() / ".menuscript" / "jobs.db"
    # backup existing DB if present
    if jobs_db.exists():
        bak = jobs_db.with_suffix('.bak.test')
        jobs_db.replace(bak)
    try:
        # ensure clean DB
        if jobs_db.exists():
            jobs_db.unlink()
        # monkeypatch run_scan_sync for the worker
        monkeypatch.setattr("menuscript.engine.background.run_scan_sync", fake_run_scan_sync)
        # enqueue a job
        jid = bg.enqueue_job("gobuster", "http://example.com", ["dir","-u","http://example.com","-w","/dev/null"], "unittest")
        assert isinstance(jid, int)
        jobs = bg.list_jobs()
        assert any(j['id'] == jid for j in jobs)
        # run worker briefly: start and stop
        t = bg.start_worker(detach=False)
        # allow worker some time to pick job
        time.sleep(0.2)
        bg.stop_worker()
        # check job status finished
        rec = bg.get_job(jid)
        assert rec is not None
        assert rec['status'] in ('done', 'failed')
    finally:
        # restore old DB if we moved it
        if jobs_db.with_suffix('.bak.test').exists():
            jobs_db.with_suffix('.bak.test').replace(jobs_db)
