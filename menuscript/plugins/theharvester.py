#!/usr/bin/env python3
"""
menuscript.plugins.theharvester

theHarvester OSINT plugin with unified interface.
"""
import subprocess
import time
from typing import List, Optional

from .plugin_base import PluginBase

HELP = {
    "name": "theHarvester (OSINT)",
    "description": "theHarvester - gather emails, subdomains, hosts, employee names from public sources",
    "usage": "menuscript jobs enqueue theharvester <domain> --args \"-b google\"",
    "examples": [
        "menuscript jobs enqueue theharvester example.com --args \"-b google\"",
        "menuscript jobs enqueue theharvester example.com --args \"-b all\"",
    ],
    "flags": [
        ["-b <source>", "Data source (google, bing, linkedin, all, etc.)"],
        ["-l <limit>", "Limit results (default 500)"],
        ["-s <start>", "Start at result number X"],
    ],
    "presets": [
        {
            "name": "Google Search",
            "args": ["-b", "google", "-l", "500"],
            "desc": "Search Google for emails/subdomains"
        },
        {
            "name": "All Sources",
            "args": ["-b", "all", "-l", "500"],
            "desc": "Search all available sources"
        },
        {
            "name": "Quick Scan",
            "args": ["-b", "google,bing", "-l", "100"],
            "desc": "Quick scan (Google + Bing)"
        },
    ]
}


class TheHarvesterPlugin(PluginBase):
    name = "theHarvester (OSINT)"
    tool = "theharvester"
    category = "osint"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """
        Execute theHarvester scan and write output to log_path.
        
        Args:
            target: Target domain (e.g. "example.com")
            args: theHarvester arguments (e.g. ["-b", "google"])
            label: Optional label for this scan
            log_path: Path to write output (required for background jobs)
        
        Returns:
            int: Exit code (0=success, non-zero=error)
        """
        args = args or []
        
        # Build theHarvester command
        # theHarvester uses -d for domain
        cmd = ["theHarvester", "-d", target] + args
        
        if not log_path:
            # Fallback for direct calls
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
                fh.write("\nERROR: theHarvester timed out after 300 seconds\n")
            return 124
            
        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: theHarvester not found in PATH\n")
            return 127
            
        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1


# Export plugin instance
plugin = TheHarvesterPlugin()
