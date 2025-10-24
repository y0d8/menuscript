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
    "name": "Nmap — Network Scanner",
    "description": (
        "Nmap is your trusty network prober — fast host discovery, port/service scanning, and fingerprinting wrapped in a "
        "friendly interface so you can scan like a pro with a single command.\n\n"
        "Let Nmap do the heavy lifting: discover live hosts, map open ports, identify running services and versions, and "
        "fingerprint operating systems and network stacks. This wrapped Nmap tool makes common scan types easy to run without "
        "memorizing flags, and captures results in the job log for later triage, correlation, and conversion into Findings — "
        "perfect for building a reconnaissance baseline before you dig deeper.\n\n"
        "Nmap is wildly flexible: run a quick sweep to see what's alive, do a targeted service/version scan for a handful of "
        "hosts, or launch a thorough TCP/UDP probe to find everything that answers. Heads up — deeper scans (UDP, full port "
        "ranges, OS detection) can be slow and noisy, so match your scan intensity to your rules of engagement.\n\n"
        "Quick tips:\n"
        "- Start with a simple discovery sweep to limit your attack surface before deeper scans.\n"
        "- Save XML/grepable output so parsers and the Findings manager can ingest results easily.\n"
        "- UDP and OS detection are powerful but slower and noisier — use them judiciously.\n"
        "- Use --host-timeout to skip unresponsive hosts (e.g., --host-timeout 10m).\n"
        "- Combine Nmap output with service-specific checks (banner grabs, vuln scanners) for richer context.\n"
        "- Always scan with permission — loud scans get noticed.\n"
    ),
    "usage": "menuscript jobs enqueue nmap <target> --args \"<nmap flags>\"",
    "examples": [
        "menuscript jobs enqueue nmap 10.0.0.0/24 --args \"-vv -sn\"",
        "menuscript jobs enqueue nmap 10.0.0.82 --args \"-v -PS -F\"",
        "menuscript jobs enqueue nmap 10.0.0.82 --args \"-vv -sV -O -p1-65535\"",
        "menuscript jobs enqueue nmap 10.0.0.82 --args \"-sU -sV --top-ports 100\"",
        "menuscript jobs enqueue nmap 10.0.0.82 --args \"--script vuln\"",
    ],
    "flags": [
        ["-sn", "Ping scan (no port scan)"],
        ["-sS", "TCP SYN scan (stealth)"],
        ["-sU", "UDP scan"],
        ["-sV", "Service/version detection"],
        ["-O", "OS detection"],
        ["-v/-vv", "Verbose/Very verbose output"],
        ["-F", "Fast scan (top 100 ports)"],
        ["-p1-65535", "Scan all TCP ports"],
        ["--top-ports N", "Scan N most common ports"],
        ["-sC/--script", "Run default/specific NSE scripts"],
        ["-T0 to -T5", "Timing template (0=slowest, 5=fastest)"]
    ],
    "preset_categories": {
        "basic_scans": [
            {
                "name": "Discovery",
                "args": ["-vv", "-sn"],
                "desc": "Ping sweep (no port scan)"
            },
            {
                "name": "Fast Scan",
                "args": ["-v", "-PS", "-F", "-T4", "--host-timeout", "90s"],
                "desc": "Fast port scan (top 100 ports, 90s timeout)"
            },
            {
                "name": "Full Scan",
                "args": ["-vv", "-sV", "-O", "-p1-65535", "-T4", "--host-timeout", "5m"],
                "desc": "Deep scan (all ports, version, OS) with 5min timeout"
            }
        ],
        "service_detection": [
            {
                "name": "Service Detection",
                "args": ["-sV", "-sC", "--open", "-T4"],
                "desc": "Service detection + safe NSE scripts"
            },
            {
                "name": "Vulnerability Scan",
                "args": ["-sV", "--script", "vuln", "--open"],
                "desc": "Detect known vulnerabilities (CVEs)"
            }
        ],
        "specialized": [
            {
                "name": "UDP Scan",
                "args": ["-sU", "-sV", "--top-ports", "100"],
                "desc": "Scan top 100 UDP ports with version detection"
            },
            {
                "name": "SMB Enumeration",
                "args": ["-p445", "--script", "smb-enum-shares,smb-enum-users,smb-os-discovery"],
                "desc": "SMB enumeration scripts"
            }
        ]
    },
    "presets": [
        # Flattened list for backward compatibility
        {"name": "Discovery", "args": ["-vv", "-sn"], "desc": "Ping sweep (no port scan)"},
        {"name": "Fast Scan", "args": ["-v", "-PS", "-F"], "desc": "Fast port scan (top 100 ports)"},
        {"name": "Full Scan", "args": ["-vv", "-sV", "-O", "-p1-65535"], "desc": "Deep scan (all ports, version, OS)"},
        {"name": "Service Detection", "args": ["-sV", "-sC", "--open"], "desc": "Service detection + safe NSE scripts"},
        {"name": "Vulnerability Scan", "args": ["-sV", "--script", "vuln", "--open"], "desc": "Detect known vulnerabilities (CVEs)"},
        {"name": "UDP Scan", "args": ["-sU", "-sV", "--top-ports", "100"], "desc": "Scan top 100 UDP ports with version detection"},
        {"name": "SMB Enumeration", "args": ["-p445", "--script", "smb-enum-shares,smb-enum-users,smb-os-discovery"], "desc": "SMB enumeration scripts"}
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
