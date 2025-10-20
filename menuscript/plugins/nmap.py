#!/usr/bin/env python3
"""
menuscript.plugins.nmap

Nmap plugin supporting both old and new interfaces.
"""
from typing import List, Optional
import subprocess
import os
import time

from .plugin_base import PluginBase

HELP = {
    "name": "Nmap (core)",
    "description": "Nmap network scanner (wrapped for help/presets).",
    "usage": "menuscript jobs enqueue nmap <target> --args \"<nmap flags>\"",
    "examples": [
        "menuscript jobs enqueue nmap 10.0.0.0/24 --args \"-sn\"",
    ],
    "flags": [
        ["-sn", "Ping scan"],
        ["-sV", "Service detection"],
        ["-O", "OS detection"]
    ],
    "presets": [
        {"name": "Discovery", "args": ["-sn"], "desc": "Ping sweep"},
        {"name": "Fast", "args": ["-v", "-PS", "-F"], "desc": "Fast probes"},
        {"name": "Full", "args": ["-sV", "-O", "-p1-65535"], "desc": "Service+OS, full ports"}
    ]
}


class NmapPlugin(PluginBase):
    name = "Nmap"
    tool = "nmap"
    category = "network"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """
        Execute nmap scan and write output to log_path.
        
        Args:
            target: Target IP/domain/CIDR
            args: Nmap arguments (e.g. ["-sV", "-p80,443"])
            label: Optional label for this scan
            log_path: Path to write output (required for background jobs)
        
        Returns:
            int: Exit code (0=success, non-zero=error)
        """
        args = args or []
        
        # Build nmap command
        cmd = ["nmap"] + args + [target]
        
        # If log_path provided, use new-style execution
        if log_path:
            return self._run_with_logpath(cmd, log_path)
        
        # Otherwise, fall back to old-style (for backward compatibility)
        return self._run_legacy(target, args, label)

    def _run_with_logpath(self, cmd: List[str], log_path: str) -> int:
        """New-style: write directly to log_path."""
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
                fh.write("\nERROR: Nmap timed out after 300 seconds\n")
            return 124
            
        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: nmap not found in PATH\n")
            return 127
            
        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1

    def _run_legacy(self, target: str, args: List[str], label: str):
        """
        Old-style execution for backward compatibility.
        Uses run_nmap() from scanner module if available.
        """
        try:
            from ..scanner import run_nmap
            logpath, rc, xmlpath, summary = run_nmap(target, args, label, save_xml=False)
            return rc
        except ImportError:
            # If scanner module not available, just run subprocess
            cmd = ["nmap"] + (args or []) + [target]
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=300, check=False)
                return proc.returncode
            except Exception:
                return 1


# Export plugin instance
plugin = NmapPlugin()
