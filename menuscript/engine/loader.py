#!/usr/bin/env python3
"""
menuscript.plugins.gobuster

Plugin for Gobuster directory/vhost discovery with new unified interface.
"""
from __future__ import annotations
import subprocess
import time
from typing import List

from .plugin_base import PluginBase

HELP = {
    "name": "Gobuster",
    "description": "Gobuster: directory/file and DNS/vhost brute force tool. Use with permission and appropriate wordlists.",
    "usage": "menuscript jobs enqueue gobuster <target> --args \"dir -u <url> -w <wordlist> -t <threads>\"",
    "examples": [
        "menuscript jobs enqueue gobuster http://example.com --args \"dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -t 10\""
    ],
    "flags": [
        ["dir", "Dir mode"],
        ["dns", "DNS mode"],
        ["-w <wordlist>", "Wordlist path"],
        ["-t <threads>", "Threads"],
    ],
    "presets": [
        {
            "name": "Dir Quick",
            "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "10"],
            "desc": "Common wordlist quick"
        },
        {
            "name": "Dir Deep",
            "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "-t", "20"],
            "desc": "Large wordlist deep scan"
        },
    ]
}


class GobusterPlugin(PluginBase):
    name = "Gobuster"
    tool = "gobuster"
    category = "web"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """
        Execute gobuster scan and write output to log_path.
        
        Args:
            target: Target URL or domain
            args: Gobuster arguments (e.g. ["dir", "-u", "http://example.com", "-w", "/path/to/wordlist"])
            label: Optional label for this scan
            log_path: Path to write output (required for background jobs)
        
        Returns:
            int: Exit code (0=success, non-zero=error)
        """
        args = args or []
        
        # Build gobuster command
        # Replace <target> placeholder if present in args
        processed_args = [arg.replace("<target>", target) for arg in args]
        cmd = ["gobuster"] + processed_args
        
        if not log_path:
            # Fallback: run without logging (shouldn't happen in background jobs)
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=300, check=False)
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
                    timeout=300,
                    check=False
                )
                
                fh.write(f"\nCompleted: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
                fh.write(f"Exit Code: {proc.returncode}\n")
                
                return proc.returncode
                
        except subprocess.TimeoutExpired:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: Gobuster timed out after 300 seconds\n")
            return 124
            
        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: gobuster not found in PATH\n")
            return 127
            
        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1


# Export plugin instance
plugin = GobusterPlugin()
