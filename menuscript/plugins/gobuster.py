#!/usr/bin/env python3
"""
menuscript.plugins.gobuster
"""
from __future__ import annotations
import subprocess
import time
from typing import List

from .plugin_base import PluginBase

HELP = {
    "name": "Gobuster",
    "description": "Gobuster: directory/file and DNS/vhost brute force tool.",
    "usage": "menuscript jobs enqueue gobuster <target> --args \"dir -u <url> -w <wordlist> -t <threads>\"",
    "examples": [
        "menuscript jobs enqueue gobuster http://example.com --args \"dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -t 10\"",
        "menuscript jobs enqueue gobuster http://example.com --args \"dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 20\"",
        "menuscript jobs enqueue gobuster example.com --args \"dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50\"",
        "menuscript jobs enqueue gobuster http://example.com --args \"vhost -u http://example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50\"",
    ],
    "flags": [
        ["dir", "Directory/file enumeration mode"],
        ["dns", "DNS subdomain enumeration mode"],
        ["vhost", "Virtual host discovery mode"],
        ["-u <url>", "Target URL (dir/vhost modes)"],
        ["-d <domain>", "Target domain (dns mode)"],
        ["-w <wordlist>", "Wordlist path"],
        ["-t <threads>", "Number of threads"],
        ["-x <extensions>", "File extensions to check (comma-separated)"],
        ["-b <codes>", "Status codes to blacklist"],
        ["--wildcard", "Force continued operation when wildcard found"],
    ],
    "preset_categories": {
        "directory_enum": [
            {
                "name": "Quick Scan",
                "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "10"],
                "desc": "Common wordlist (4600 entries)"
            },
            {
                "name": "Standard Scan",
                "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/big.txt", "-t", "20"],
                "desc": "Big wordlist (20,000 entries)"
            },
            {
                "name": "PHP Extensions",
                "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/common.txt", "-x", "php,phps,php3,php4,php5,phtml", "-t", "15"],
                "desc": "Common paths + PHP extensions"
            }
        ],
        "subdomain_enum": [
            {
                "name": "Subdomain Scan",
                "args": ["dns", "-d", "<target>", "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "-t", "50"],
                "desc": "Top 5000 subdomains (fast)"
            }
        ],
        "vhost_discovery": [
            {
                "name": "Virtual Hosts",
                "args": ["vhost", "-u", "<target>", "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "-t", "50"],
                "desc": "Virtual host discovery (top 5000)"
            }
        ]
    },
    "presets": [
        # Flattened list for backward compatibility
        {"name": "Quick Scan", "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "10"], "desc": "Common wordlist (4600 entries)"},
        {"name": "Standard Scan", "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/big.txt", "-t", "20"], "desc": "Big wordlist (20,000 entries)"},
        {"name": "PHP Extensions", "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/common.txt", "-x", "php,phps,php3,php4,php5,phtml", "-t", "15"], "desc": "Common paths + PHP extensions"},
        {"name": "Subdomain Scan", "args": ["dns", "-d", "<target>", "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "-t", "50"], "desc": "Top 5000 subdomains (fast)"},
        {"name": "Virtual Hosts", "args": ["vhost", "-u", "<target>", "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "-t", "50"], "desc": "Virtual host discovery (top 5000)"}
    ]
}


class GobusterPlugin(PluginBase):
    name = "Gobuster"
    tool = "gobuster"
    category = "web"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """Execute gobuster scan and write output to log_path."""
        args = args or []
        
        processed_args = [arg.replace("<target>", target) for arg in args]
        cmd = ["gobuster"] + processed_args
        
        if not log_path:
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=300, check=False)
                return proc.returncode
            except Exception:
                return 1
        
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


plugin = GobusterPlugin()
