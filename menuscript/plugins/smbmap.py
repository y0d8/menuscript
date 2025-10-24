#!/usr/bin/env python3
"""
menuscript.plugins.smbmap - SMB share enumeration and permission mapping
"""
import subprocess
import time
from typing import List

from .plugin_base import PluginBase

HELP = {
    "name": "SMBMap — SMB Share Enumerator",
    "description": (
        "Want a quick way to see what's readable, writable, or locked down on SMB shares?\n\n"
        "SMBMap enumerates SMB shares and checks permissions (READ, WRITE, etc.). Unlike other SMB tools, it excels at showing what you "
        "can actually do with each share — read files, write files, or no access. Perfect for quickly identifying writable shares that "
        "could be security risks. Works great with legacy SMB/Samba versions where other tools fail.\n\n"
        "Use it for reconnaissance: find open shares, test credentials, and map out file-level access before diving into manual enumeration "
        "or exploitation. Results are captured in the job log so you can convert interesting shares into Findings or follow-up tasks.\n\n"
        "Play nice: authenticated scans that list or read files can be noisy and may trigger alerts. Always run with authorization. 🔒\n\n"
        "Quick tips:\n"
        "- Start with anonymous scans to find publicly accessible shares, then move to authenticated scans if you have credentials.\n"
        "- Use the recursive flag (-R) carefully — it can generate lots of traffic and take time on large shares.\n"
        "- Writable shares are high-risk — flag them as Findings for remediation or exploitation (with permission).\n"
        "- Combine SMBMap output with enum4linux, smbclient, or Bloodhound for a complete SMB assessment.\n"
        "- Capture share names, permissions, and file listings to the job log for reporting and follow-up analysis.\n"
    ),
    "usage": "menuscript jobs enqueue smbmap <target>",
    "examples": [
        "menuscript jobs enqueue smbmap 10.0.0.82",
        "menuscript jobs enqueue smbmap 10.0.0.82 --args \"-u admin -p password\"",
        "menuscript jobs enqueue smbmap 10.0.0.82 --args \"-u admin -p password -R\"",
        "menuscript jobs enqueue smbmap 10.0.0.82 --args \"--depth 3\"",
    ],
    "preset_categories": {
        "unauthenticated": [
            {
                "name": "Anonymous Scan",
                "args": [],
                "desc": "Basic share enumeration (no credentials)"
            },
            {
                "name": "List Share Contents",
                "args": ["-R"],
                "desc": "Recursively list all accessible files"
            }
        ],
        "authenticated": [
            {
                "name": "With Credentials",
                "args": ["-u", "<username>", "-p", "<password>"],
                "desc": "Authenticated scan (replace username/password)"
            },
            {
                "name": "Domain Credentials",
                "args": ["-u", "<username>", "-p", "<password>", "-d", "<domain>"],
                "desc": "Domain authentication"
            }
        ],
        "advanced": [
            {
                "name": "Deep Recursive Scan",
                "args": ["-R", "--depth", "5"],
                "desc": "Recursively list files (5 levels deep)"
            },
            {
                "name": "Download Interesting Files",
                "args": ["-A", "password", "-R"],
                "desc": "Auto-download files matching pattern"
            },
            {
                "name": "Execute Command",
                "args": ["-u", "<username>", "-p", "<password>", "-x", "whoami"],
                "desc": "Execute command on target (requires admin)"
            }
        ]
    },
    "presets": [
        {"name": "Anonymous Scan", "args": [], "desc": "Basic share enumeration (no credentials)"},
        {"name": "List Share Contents", "args": ["-R"], "desc": "Recursively list all accessible files"},
        {"name": "With Credentials", "args": ["-u", "<username>", "-p", "<password>"], "desc": "Authenticated scan (replace username/password)"},
        {"name": "Domain Credentials", "args": ["-u", "<username>", "-p", "<password>", "-d", "<domain>"], "desc": "Domain authentication"},
        {"name": "Deep Recursive Scan", "args": ["-R", "--depth", "5"], "desc": "Recursively list files (5 levels deep)"},
        {"name": "Download Interesting Files", "args": ["-A", "password", "-R"], "desc": "Auto-download files matching pattern"},
        {"name": "Execute Command", "args": ["-u", "<username>", "-p", "<password>", "-x", "whoami"], "desc": "Execute command on target (requires admin)"}
    ],
    "common_options": {
        "-H": "Target host (automatically set)",
        "-u": "Username",
        "-p": "Password",
        "-d": "Domain",
        "-R": "Recursively list files in shares",
        "--depth": "Max recursion depth (default: 5)",
        "-A": "Auto-download files matching pattern",
        "-x": "Execute command",
        "--download": "Download file path",
        "-q": "Quiet mode"
    }
}


class SmbmapPlugin(PluginBase):
    name = "SMBMap"
    tool = "smbmap"
    category = "windows"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """Execute smbmap scan and write output to log_path."""
        args = args or []

        # Build smbmap command
        # smbmap uses -H for host
        cmd = ["smbmap", "-H", target] + args

        if not log_path:
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=120, check=False)
                return proc.returncode
            except Exception:
                return 1

        try:
            with open(log_path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(f"=== SMBMap Scan ===\n")
                fh.write(f"Target: {target}\n")
                fh.write(f"Command: {' '.join(cmd)}\n")
                fh.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
                fh.flush()

                proc = subprocess.run(
                    cmd,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    timeout=120,
                    check=False
                )

                fh.write(f"\n\nCompleted: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
                fh.write(f"Exit Code: {proc.returncode}\n")

                return proc.returncode

        except subprocess.TimeoutExpired:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: smbmap timed out after 120 seconds\n")
            return 124

        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: smbmap not found in PATH\n")
                fh.write("Install with: sudo apt install smbmap\n")
            return 127

        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1


plugin = SmbmapPlugin()
