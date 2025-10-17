#!/usr/bin/env python3
"""
Manager that schedules runs (sync + background) and writes results to DB.

This manager contains a small built-in adapter for "nmap" that uses your existing
menuscript.scanner.run_nmap function. Later plugins can be added by implementing
ScannerPlugin in their own modules and registering them here.
"""
import threading
import time
from typing import Optional, Dict, Any
from ..storage.db import init_db, insert_scan, update_scan, get_scan, get_scans
from ..utils import timestamp_str
import importlib

# lazy import existing run_nmap (your project has menuscript/scanner.py)
def _run_nmap_adapter(target, args, label, save_xml=False):
    from .. import scanner as scanner_module
    # scanner.run_nmap should return (logpath, rc, xmlpath, summary)
    return scanner_module.run_nmap(target, args, label, save_xml=save_xml)

def run_scan_sync(tool: str, target: str, args: list, label: Optional[str]=None, save_xml: bool=False) -> int:
    """
    Run a scan synchronously and return the DB scan id.
    Currently supports 'nmap' as a built-in. Creates a DB record, runs, updates DB.
    """
    init_db()
    ts = timestamp_str()
    entry = {
        "ts": ts,
        "tool": tool,
        "target": target,
        "label": label,
        "args": args,
        "log": None,
        "xml": None,
        "summary": {},
        "per_host": [],
        "status": "pending",
        "rc": None
    }
    scan_id = insert_scan(entry)

    try:
        if tool.lower() == "nmap":
            logpath, rc, xmlpath, summary = _run_nmap_adapter(target, args, label, save_xml=save_xml)
            # ensure per_host in summary (some parsers provide it)
            per_host = summary.get("per_host") if isinstance(summary, dict) else []
            update_scan(scan_id, status="done", rc=rc, log=logpath, xml=xmlpath, summary=summary, per_host=per_host)
        else:
            # try to import a plugin module by convention menuscript.plugins.<tool>
            try:
                mod = importlib.import_module(f"menuscript.plugins.{tool}")
                PluginClass = getattr(mod, "Plugin", None)
                if PluginClass:
                    plugin = PluginClass()
                    prepared = plugin.prepare(target, args, label)
                    result = plugin.run(prepared)
                    update_scan(scan_id, status=result.get("status","done"), rc=result.get("rc"), log=result.get("log"), xml=result.get("xml"), summary=result.get("summary"), per_host=result.get("per_host"))
                else:
                    update_scan(scan_id, status="failed")
            except Exception as e:
                update_scan(scan_id, status="failed")
    except Exception as e:
        update_scan(scan_id, status="failed")
    return scan_id

def run_scan_background(tool: str, target: str, args: list, label: Optional[str]=None, save_xml: bool=False) -> int:
    """
    Run the scan in a background thread and return the DB id immediately.
    """
    init_db()
    ts = timestamp_str()
    entry = {
        "ts": ts,
        "tool": tool,
        "target": target,
        "label": label,
        "args": args,
        "log": None,
        "xml": None,
        "summary": {},
        "per_host": [],
        "status": "pending",
        "rc": None
    }
    scan_id = insert_scan(entry)

    def worker(sid):
        try:
            # reuse sync runner to keep logic centralized
            run_scan_sync(tool, target, args, label, save_xml=save_xml)
        except Exception:
            update_scan(sid, status="failed")

    t = threading.Thread(target=worker, args=(scan_id,), daemon=True)
    t.start()
    return scan_id
