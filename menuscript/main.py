#!/usr/bin/env python3
"""
menuscript main entrypoint.

- Default: launch interactive UI
- Subcommand: `menuscript migrate` performs one-time migration from legacy JSON history
  to SQLite DB, then deletes the old JSON file (no backup).
"""
import sys
from pathlib import Path

from .ui import run_menu_loop
from .storage.db import init_db, import_json_history_to_db
from .utils import HISTORY_FILE

def _cmd_migrate():
    """Manual migration: import legacy history.json into DB, then delete history.json."""
    init_db()
    imported = import_json_history_to_db()  # imports if file exists; 0 otherwise
    # Delete legacy JSON history (no backup per user choice C3)
    try:
        Path(HISTORY_FILE).unlink(missing_ok=True)  # Python 3.8+: ignore if missing
    except Exception:
        pass
    # No prints (silent), but return code signals success
    return 0

def main():
    # Support: menuscript migrate
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("migrate", "--migrate", "upgrade", "db-migrate"):
        rc = _cmd_migrate()
        sys.exit(rc)

    # Default: interactive menu
    try:
        run_menu_loop()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")

if __name__ == '__main__':
    main()
