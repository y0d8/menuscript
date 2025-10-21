#!/usr/bin/env python3
"""
menuscript.plugins.nikto

Nikto web server scanner plugin with unified interface.
"""
import subprocess
import time
from typing import List, Optional

from .plugin_base import PluginBase

HELP = {
    "name": "Nikto",
    "description": "Nikto web server scanner - comprehensive web vulnerability assessment",
    "usage": "menuscript jobs enqueue nikto <target> --args \"-h <host>\"",
    "examples": [
        "menuscript jobs enqueue nikto http://example.com --args \"-h http://example.com\"",
        "menuscript jobs enqueue nikto https://example.com --args \"-h https://example.com -ssl\"",
    ],
    "flags": [
        ["-h <host>", "Target host"],
        ["-ssl", "Force SSL mode"],
        ["-port <port>", "Specify port"],
        ["-Tuning <1-9>", "Scan tuning (1=Interesting, 9=SQL injection)"],
    ],
    "presets": [
        {
            "name": "Quick Scan",
            "args": ["-h", "<target>"],
            "desc": "Basic vulnerability scan"
        },
        {
            "name": "SSL Scan",
            "args": ["-h", "<target>", "-ssl"],
            "desc": "HTTPS vulnerability scan"
        },
        {
            "name": "Full Scan",
            "args": ["-h", "<target>", "-Tuning", "123456789"],
            "desc": "Comprehensive scan (all tests)"
        },
    ]
}


class NiktoPlugin(PluginBase):
    name = "Nikto"
    tool = "nikto"
    category = "web"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """
        Execute nikto scan and write output to log_path.
        
        Args:
            target: Target URL or host
            args: Nikto arguments (e.g. ["-h", "http://example.com"])
            label: Optional label for this scan
            log_path: Path to write output (required for background jobs)
        
        Returns:
            int: Exit code (0=success, non-zero=error)
        """
        args = args or []
        
        # Build nikto command
        # If -h not in args, add target as -h argument
        cmd = ["nikto"] + args
        if "-h" not in args:
            cmd.extend(["-h", target])
        
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
                    timeout=600,  # Nikto can take longer
                    check=False
                )
                
                fh.write(f"\nCompleted: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
                fh.write(f"Exit Code: {proc.returncode}\n")
                
                return proc.returncode
                
        except subprocess.TimeoutExpired:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: Nikto timed out after 600 seconds\n")
            return 124
            
        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: nikto not found in PATH\n")
            return 127
            
        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1


# Export plugin instance
plugin = NiktoPlugin()
