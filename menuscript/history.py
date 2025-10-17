#!/usr/bin/env python3
from .utils import HISTORY_FILE, ensure_dirs, read_json, write_json, timestamp_str

def load_history():
    ensure_dirs()
    return read_json(HISTORY_FILE)

def add_history_entry(target, args, label, logpath, xmlpath=None):
    ensure_dirs()
    history = load_history()
    entry = {
        "ts": timestamp_str(),
        "target": target,
        "args": args,
        "label": label,
        "log": str(logpath),
        "xml": str(xmlpath) if xmlpath else None
    }
    history.insert(0, entry)
    history = history[:200]
    write_json(HISTORY_FILE, history)
    return entry
