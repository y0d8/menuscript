#!/usr/bin/env python3
"""
menuscript.plugins.nmap
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
        "menuscript jobs enqueue nmap 10.0.0.0/24 --args \"-vv -sn\"",
        "menuscript jobs enqueue nmap 10.0.0.82 --args \"-v -PS -F\"",
        "menuscript jobs enqueue nmap 10.0.0.82 --args \"-vv -sV -O -p1-65535\"",
    ],
    "flags": [
        ["-sn", "Ping scan (no port scan)"],
        ["-sV", "Service/version detection"],
        ["-O", "OS detection"],
        ["-v/-vv", "Verbose/Very verbose output"],
        ["-PS", "TCP SYN ping"],
        ["-F", "Fast scan (top 100 ports)"],
        ["-p1-65535", "Scan all TCP ports"]
    ],
    "presets": [
        {"name": "Discovery", "args": ["-vv", "-sn"], "desc": "Ping sweep (very verbose)"},
        {"name": "Fast", "args": ["-v", "-PS", "-F"], "desc": "Fast port scan (top 100 ports)"},
        {"name": "Full", "args": ["-vv", "-sV", "-O", "-p1-65535"], "desc": "Deep scan (all ports, version, OS)"}
    ]
}


class NmapPlugin(PluginBase):
    name = "Nmap"
    tool = "nmap"
    category = "network"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """Execute nmap scan and write output to log_path."""
        args = args or []

        # Split target on whitespace to handle multiple IPs/hosts
        # e.g., "10.0.0.1 10.0.0.2 10.0.0.3" -> ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        target_list = target.split()

        cmd = ["nmap"] + args + target_list

        if log_path:
            return self._run_with_logpath(cmd, log_path)

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
        """Old-style execution for backward compatibility."""
        try:
            from ..scanner import run_nmap
            logpath, rc, xmlpath, summary = run_nmap(target, args, label, save_xml=False)
            return rc
        except ImportError:
            # Split target on whitespace to handle multiple IPs/hosts
            target_list = target.split()
            cmd = ["nmap"] + (args or []) + target_list
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=300, check=False)
                return proc.returncode
            except Exception:
                return 1


plugin = NmapPlugin()
