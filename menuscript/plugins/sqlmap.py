#!/usr/bin/env python3
"""
menuscript.plugins.sqlmap

SQLMap SQL injection detection and exploitation plugin with unified interface.
"""
import subprocess
import time
from typing import List, Optional

from .plugin_base import PluginBase

HELP = {
    "name": "SQLMap",
    "description": "SQLMap - automatic SQL injection detection and exploitation tool",
    "usage": "menuscript jobs enqueue sqlmap <target_url> --args \"--batch\"",
    "examples": [
        "menuscript jobs enqueue sqlmap \"http://example.com/page.php?id=1\" --args \"--batch\"",
        "menuscript jobs enqueue sqlmap \"http://example.com/page.php?id=1\" --args \"--batch --dbs\"",
        "menuscript jobs enqueue sqlmap \"http://example.com/login\" --args \"--batch --forms\"",
    ],
    "flags": [
        ["--batch", "Never ask for user input, use default behavior"],
        ["--dbs", "Enumerate databases"],
        ["--tables", "Enumerate tables"],
        ["--dump", "Dump database table entries"],
        ["--forms", "Parse and test forms"],
        ["-p <param>", "Testable parameter(s)"],
        ["--level <1-5>", "Level of tests (1-5, default 1)"],
        ["--risk <1-3>", "Risk of tests (1-3, default 1)"],
    ],
    "presets": [
        {
            "name": "Quick Test",
            "args": ["--batch", "--level=1", "--risk=1"],
            "desc": "Quick SQL injection test (safe)"
        },
        {
            "name": "Deep Test",
            "args": ["--batch", "--level=3", "--risk=2"],
            "desc": "Thorough SQL injection test"
        },
        {
            "name": "Forms Test",
            "args": ["--batch", "--forms", "--crawl=2"],
            "desc": "Test forms and crawl 2 levels"
        },
        {
            "name": "Enumerate DBs",
            "args": ["--batch", "--dbs"],
            "desc": "Detect SQLi and enumerate databases"
        },
    ]
}


class SqlmapPlugin(PluginBase):
    name = "SQLMap"
    tool = "sqlmap"
    category = "web"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """
        Execute sqlmap scan and write output to log_path.

        Args:
            target: Target URL (e.g. "http://example.com/page.php?id=1")
            args: SQLMap arguments (e.g. ["--batch", "--dbs"])
            label: Optional label for this scan
            log_path: Path to write output (required for background jobs)

        Returns:
            int: Exit code (0=success, non-zero=error)
        """
        args = args or []

        # Build sqlmap command
        # SQLMap takes URL as -u parameter or directly
        if "-u" not in args:
            cmd = ["sqlmap", "-u", target] + args
        else:
            cmd = ["sqlmap"] + args + [target]

        # Replace <target> placeholder if present
        cmd = [arg.replace("<target>", target) for arg in cmd]

        if not log_path:
            # Fallback for direct calls (shouldn't happen in background jobs)
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=600, check=False)
                return proc.returncode
            except Exception:
                return 1

        # Run with logging
        try:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"Command: {' '.join(cmd)}\n")
                fh.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
                fh.flush()

                proc = subprocess.run(
                    cmd,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    timeout=600,  # SQLMap can take a while
                    check=False
                )

                fh.write(f"\nCompleted: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
                fh.write(f"Exit Code: {proc.returncode}\n")

                return proc.returncode

        except subprocess.TimeoutExpired:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: SQLMap timed out after 600 seconds\n")
            return 124

        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: sqlmap not found in PATH\n")
            return 127

        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1


# Export plugin instance
plugin = SqlmapPlugin()
