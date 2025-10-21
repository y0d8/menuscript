#!/usr/bin/env python3
"""
menuscript.plugins.enum4linux

Enum4linux SMB enumeration plugin with unified interface.
"""
import subprocess
import time
from typing import List, Optional

from .plugin_base import PluginBase

HELP = {
    "name": "enum4linux (SMB)",
    "description": "Enum4linux - SMB/CIFS share enumeration tool for Windows/Samba systems",
    "usage": "menuscript jobs enqueue enum4linux <target> --args \"-a\"",
    "examples": [
        "menuscript jobs enqueue enum4linux 10.0.0.5 --args \"-a\"",
        "menuscript jobs enqueue enum4linux 10.0.0.5 --args \"-U -S\"",
    ],
    "flags": [
        ["-U", "Get userlist"],
        ["-S", "Get sharelist"],
        ["-G", "Get group/member list"],
        ["-P", "Get password policy"],
        ["-a", "All simple enumeration"],
    ],
    "presets": [
        {
            "name": "Full Enum",
            "args": ["-a"],
            "desc": "All enumeration (users, shares, groups, etc.)"
        },
        {
            "name": "Shares Only",
            "args": ["-S"],
            "desc": "Enumerate shares only"
        },
        {
            "name": "Users & Shares",
            "args": ["-U", "-S"],
            "desc": "Enumerate users and shares"
        },
    ]
}


class Enum4linuxPlugin(PluginBase):
    name = "enum4linux (SMB)"
    tool = "enum4linux"
    category = "network"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """
        Execute enum4linux scan and write output to log_path.
        
        Args:
            target: Target IP address or hostname
            args: Enum4linux arguments (e.g. ["-a"])
            label: Optional label for this scan
            log_path: Path to write output (required for background jobs)
        
        Returns:
            int: Exit code (0=success, non-zero=error)
        """
        args = args or []
        
        # Build enum4linux command
        cmd = ["enum4linux"] + args + [target]
        
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
                fh.write("\nERROR: enum4linux timed out after 300 seconds\n")
            return 124
            
        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: enum4linux not found in PATH\n")
            return 127
            
        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1


# Export plugin instance
plugin = Enum4linuxPlugin()
