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
        "menuscript jobs enqueue sqlmap \"http://example.com/page.php?id=1\" --args \"--batch --level=5 --risk=3\"",
        "menuscript jobs enqueue sqlmap \"http://example.com/page.php\" --args \"--batch --data='username=admin&password=pass' -p username\"",
    ],
    "flags": [
        ["--batch", "Never ask for user input, use default behavior"],
        ["--dbs", "Enumerate databases"],
        ["--tables", "Enumerate tables"],
        ["--columns", "Enumerate columns"],
        ["--dump", "Dump database table entries"],
        ["--dump-all", "Dump all database tables"],
        ["--forms", "Parse and test forms"],
        ["--crawl=N", "Crawl website starting from target URL (depth N)"],
        ["-p <param>", "Testable parameter(s)"],
        ["--data=<data>", "Data string to be sent through POST"],
        ["--cookie=<cookie>", "HTTP Cookie header value"],
        ["--level <1-5>", "Level of tests (1-5, default 1)"],
        ["--risk <1-3>", "Risk of tests (1-3, default 1)"],
        ["--technique=<tech>", "SQL injection techniques to use (default BEUSTQ)"],
        ["--dbms=<dbms>", "Force back-end DBMS (MySQL, Oracle, PostgreSQL, etc.)"],
        ["--os-shell", "Prompt for an interactive OS shell"],
        ["--sql-shell", "Prompt for an SQL shell"],
        ["--tamper=<script>", "Use tamper script(s) for WAF/IPS evasion"],
    ],
    "preset_categories": {
        "basic_detection": [
            {
                "name": "Quick Test",
                "args": ["--batch", "--level=1", "--risk=1"],
                "desc": "Quick SQL injection test (safe, low risk)"
            },
            {
                "name": "Standard Test",
                "args": ["--batch", "--level=2", "--risk=1"],
                "desc": "Standard detection (includes cookies/headers)"
            }
        ],
        "form_crawl": [
            {
                "name": "Forms Quick",
                "args": ["--batch", "--forms", "--level=1"],
                "desc": "Test forms only (no crawl)"
            },
            {
                "name": "Forms + Crawl",
                "args": ["--batch", "--forms", "--crawl=2"],
                "desc": "Test forms and crawl 2 levels"
            }
        ],
        "enumeration": [
            {
                "name": "Current User Info",
                "args": ["--batch", "--current-user", "--current-db", "--hostname"],
                "desc": "Get current user, database, and hostname"
            }
        ],
        "exploitation_workflow": [
            {
                "name": "Discover Databases",
                "args": ["--batch", "--dbs", "--level=3", "--crawl=2"],
                "desc": "Enumerate databases with deep crawl"
            },
            {
                "name": "Enumerate Tables",
                "args": ["--batch", "-D", "<DB_NAME>", "--tables", "--crawl=2"],
                "desc": "List tables in database (replace <DB_NAME>)"
            },
            {
                "name": "Enumerate Columns",
                "args": ["--batch", "-D", "<DB_NAME>", "-T", "<TABLE>", "--columns", "--crawl=2"],
                "desc": "List columns in table (replace <DB_NAME> and <TABLE>)"
            },
            {
                "name": "Extract Table Data",
                "args": ["--batch", "-D", "<DB_NAME>", "-T", "<TABLE>", "--dump", "--crawl=2"],
                "desc": "Dump entire table (replace <DB_NAME> and <TABLE>)"
            },
            {
                "name": "Extract Column Data",
                "args": ["--batch", "-D", "<DB_NAME>", "-T", "<TABLE>", "-C", "<COLUMNS>", "--dump", "--crawl=2"],
                "desc": "Dump specific columns (e.g., username,password)"
            }
        ]
    },
    "presets": [
        # Flattened list for backward compatibility
        {"name": "Quick Test", "args": ["--batch", "--level=1", "--risk=1"], "desc": "Quick SQL injection test (safe, low risk)"},
        {"name": "Standard Test", "args": ["--batch", "--level=2", "--risk=1"], "desc": "Standard detection (includes cookies/headers)"},
        {"name": "Forms Quick", "args": ["--batch", "--forms", "--level=1"], "desc": "Test forms only (no crawl)"},
        {"name": "Forms + Crawl", "args": ["--batch", "--forms", "--crawl=2"], "desc": "Test forms and crawl 2 levels"},
        {"name": "Current User Info", "args": ["--batch", "--current-user", "--current-db", "--hostname"], "desc": "Get current user, database, and hostname"},
        {"name": "Discover Databases", "args": ["--batch", "--dbs", "--level=3", "--crawl=2"], "desc": "Enumerate databases with deep crawl"},
        {"name": "Enumerate Tables", "args": ["--batch", "-D", "<DB_NAME>", "--tables", "--crawl=2"], "desc": "List tables in database (replace <DB_NAME>)"},
        {"name": "Enumerate Columns", "args": ["--batch", "-D", "<DB_NAME>", "-T", "<TABLE>", "--columns", "--crawl=2"], "desc": "List columns in table (replace <DB_NAME> and <TABLE>)"},
        {"name": "Extract Table Data", "args": ["--batch", "-D", "<DB_NAME>", "-T", "<TABLE>", "--dump", "--crawl=2"], "desc": "Dump entire table (replace <DB_NAME> and <TABLE>)"},
        {"name": "Extract Column Data", "args": ["--batch", "-D", "<DB_NAME>", "-T", "<TABLE>", "-C", "<COLUMNS>", "--dump", "--crawl=2"], "desc": "Dump specific columns (e.g., username,password)"}
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
