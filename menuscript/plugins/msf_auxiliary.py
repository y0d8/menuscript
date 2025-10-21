#!/usr/bin/env python3
"""
menuscript.plugins.msf_auxiliary - Metasploit Framework auxiliary scanner wrapper
"""
from typing import List
import subprocess
import os
import time

from .plugin_base import PluginBase

HELP = {
    "name": "MSF Auxiliary (Metasploit)",
    "description": "Metasploit Framework auxiliary scanners (non-interactive)",
    "usage": "menuscript jobs enqueue msf_auxiliary <target> --args \"<module_path>\"",
    "examples": [
        "menuscript jobs enqueue msf_auxiliary 10.0.0.82 --args \"auxiliary/scanner/smb/smb_version\"",
        "menuscript jobs enqueue msf_auxiliary 10.0.0.82 --args \"auxiliary/scanner/ssh/ssh_version\"",
        "menuscript jobs enqueue msf_auxiliary 10.0.0.0/24 --args \"auxiliary/scanner/portscan/tcp\"",
    ],
    "presets": [
        {
            "name": "SMB Version",
            "args": ["auxiliary/scanner/smb/smb_version"],
            "desc": "Detect SMB version and OS info"
        },
        {
            "name": "SMB Shares",
            "args": ["auxiliary/scanner/smb/smb_enumshares"],
            "desc": "Enumerate SMB shares"
        },
        {
            "name": "SSH Version",
            "args": ["auxiliary/scanner/ssh/ssh_version"],
            "desc": "Detect SSH server version"
        },
        {
            "name": "FTP Version",
            "args": ["auxiliary/scanner/ftp/ftp_version"],
            "desc": "Detect FTP server version"
        },
        {
            "name": "HTTP Version",
            "args": ["auxiliary/scanner/http/http_version"],
            "desc": "Detect web server version"
        },
        {
            "name": "Port Scan",
            "args": ["auxiliary/scanner/portscan/tcp"],
            "desc": "Fast TCP port scanner"
        },
        {
            "name": "MySQL Version",
            "args": ["auxiliary/scanner/mysql/mysql_version"],
            "desc": "Detect MySQL version"
        },
        {
            "name": "PostgreSQL Version",
            "args": ["auxiliary/scanner/postgres/postgres_version"],
            "desc": "Detect PostgreSQL version"
        },
        {
            "name": "MSSQL Ping",
            "args": ["auxiliary/scanner/mssql/mssql_ping"],
            "desc": "Discover MSSQL instances"
        },
        {
            "name": "VNC None Auth",
            "args": ["auxiliary/scanner/vnc/vnc_none_auth"],
            "desc": "Detect VNC servers with no auth"
        }
    ],
    "notes": [
        "Requires Metasploit Framework installed (msfconsole)",
        "Runs modules non-interactively (-q -x flags)",
        "Only works with auxiliary scanner modules",
        "Cannot maintain sessions or run exploits"
    ]
}


class MsfAuxiliaryPlugin(PluginBase):
    name = "MSF Auxiliary"
    tool = "msf_auxiliary"
    category = "metasploit"
    HELP = HELP

    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """Execute MSF auxiliary module non-interactively."""
        args = args or []

        # First arg should be the module path
        if not args:
            if log_path:
                with open(log_path, "w") as f:
                    f.write("ERROR: No module specified. Example: auxiliary/scanner/smb/smb_version\n")
            return 1

        module_path = args[0]

        # Additional module options (RPORT, etc.)
        extra_opts = args[1:] if len(args) > 1 else []

        if log_path:
            return self._run_with_logpath(module_path, target, extra_opts, log_path)

        return self._run_legacy(module_path, target, extra_opts)

    def _run_with_logpath(self, module_path: str, target: str, extra_opts: List[str], log_path: str) -> int:
        """Run MSF module and write output to log_path."""
        try:
            # Build msfconsole command
            # Use -q (quiet), -x (execute commands), -n (no database)
            msf_commands = [
                f"use {module_path}",
                f"set RHOSTS {target}",
            ]

            # Add any extra options (e.g., "RPORT=445", "USERNAME=postgres PASSWORD=password")
            for opt in extra_opts:
                # Handle KEY=VALUE format - split and use "set KEY VALUE"
                if '=' in opt:
                    key, value = opt.split('=', 1)
                    msf_commands.append(f"set {key} {value}")
                else:
                    # Plain option, just append as-is
                    msf_commands.append(opt)

            # Add run and exit
            msf_commands.append("run")
            msf_commands.append("exit")

            # Join commands with semicolons
            command_string = "; ".join(msf_commands)

            # Build full command
            cmd = [
                "msfconsole",
                "-q",           # Quiet mode (no banner)
                "-n",           # No database
                "-x",           # Execute commands
                command_string
            ]

            with open(log_path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(f"=== Metasploit Auxiliary Module ===\n")
                fh.write(f"Module: {module_path}\n")
                fh.write(f"Target: {target}\n")
                fh.write(f"Options: {', '.join(extra_opts) if extra_opts else 'None'}\n")
                fh.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
                fh.write(f"Command: {' '.join(cmd)}\n\n")
                fh.flush()

                # Run msfconsole
                proc = subprocess.run(
                    cmd,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    timeout=600,  # 10 min timeout
                    check=False
                )

                fh.write(f"\n\nCompleted: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
                fh.write(f"Exit Code: {proc.returncode}\n")

                return proc.returncode

        except subprocess.TimeoutExpired:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: MSF module timed out after 600 seconds\n")
            return 124

        except FileNotFoundError:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write("\nERROR: msfconsole not found in PATH\n")
                fh.write("Please install Metasploit Framework\n")
            return 127

        except Exception as e:
            with open(log_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\nERROR: {type(e).__name__}: {e}\n")
            return 1

    def _run_legacy(self, module_path: str, target: str, extra_opts: List[str]):
        """Legacy execution without log_path."""
        msf_commands = [
            f"use {module_path}",
            f"set RHOSTS {target}",
        ]

        for opt in extra_opts:
            # Handle KEY=VALUE format
            if '=' in opt:
                key, value = opt.split('=', 1)
                msf_commands.append(f"set {key} {value}")
            else:
                msf_commands.append(opt)

        msf_commands.append("run")
        msf_commands.append("exit")

        command_string = "; ".join(msf_commands)

        cmd = ["msfconsole", "-q", "-n", "-x", command_string]

        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=600, check=False)
            return proc.returncode
        except Exception:
            return 1


plugin = MsfAuxiliaryPlugin()
