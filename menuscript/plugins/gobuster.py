#!/usr/bin/env python3
"""
menuscript.plugins.gobuster

Plugin for Gobuster directory / vhost discovery.
Non-destructive defaults; returns a ScanResult dict.
"""
from __future__ import annotations
from pathlib import Path
import subprocess, time, json
from typing import Dict, Any, List, Optional

from ..engine.base import ScannerPlugin, ScanResult

DEFAULT_TIMEOUT = 300

def _now_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class Plugin(ScannerPlugin):
    name = "gobuster"

    def prepare(self, target: str, args: List[str], label: Optional[str]=None) -> Dict[str, Any]:
        outdir = Path.home() / ".menuscript" / "artifacts" / f"gobuster_{int(time.time())}"
        outdir.mkdir(parents=True, exist_ok=True)
        return {"target": target, "args": args or [], "label": label, "outdir": str(outdir)}

    def _build_cmd(self, prepared: Dict[str, Any]) -> List[str]:
        args = list(prepared.get("args") or [])
        cmd = ["gobuster"] + args
        return cmd

    def _parse_output(self, raw: str) -> Dict[str, Any]:
        summary = {"found": []}
        per_host = []
        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("{") and "status" in s:
                try:
                    obj = json.loads(s)
                    path = obj.get("path") or obj.get("word")
                    status = obj.get("status")
                    summary["found"].append({"path": path, "status": status})
                    per_host.append({"path": path, "status": status})
                    continue
                except Exception:
                    pass
            if s.startswith("/"):
                parts = s.split()
                path = parts[0]
                status = None
                if "Status:" in s:
                    try:
                        status = int(s.split("Status:")[1].split(")")[0].strip())
                    except Exception:
                        status = None
                summary["found"].append({"path": path, "status": status})
                per_host.append({"path": path, "status": status})
        summary["count"] = len(summary["found"])
        return {"summary": summary, "per_host": per_host}

    def run(self, prepared: Dict[str, Any]) -> ScanResult:
        target = prepared.get("target")
        args = prepared.get("args") or []
        label = prepared.get("label") or ""
        outdir = Path(prepared.get("outdir"))
        cmd = self._build_cmd(prepared)
        raw_path = outdir / "gobuster.txt"

        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=DEFAULT_TIMEOUT)
            raw = p.stdout or ""
            raw_path.write_text(raw)
            parsed = self._parse_output(raw)
            summary = parsed.get("summary", {})
            per_host = parsed.get("per_host", [])
            return {
                "ts": _now_ts(),
                "tool": self.name,
                "target": target,
                "label": label,
                "args": args,
                "log": str(raw_path),
                "xml": None,
                "summary": summary,
                "per_host": per_host,
                "status": "done" if p.returncode == 0 else "done",
                "rc": int(p.returncode)
            }
        except FileNotFoundError:
            return {
                "ts": _now_ts(),
                "tool": self.name,
                "target": target,
                "label": label,
                "args": args,
                "log": None,
                "xml": None,
                "summary": {"error": "gobuster not found on PATH"},
                "per_host": [],
                "status": "failed",
                "rc": -1
            }
        except subprocess.TimeoutExpired:
            return {
                "ts": _now_ts(),
                "tool": self.name,
                "target": target,
                "label": label,
                "args": args,
                "log": str(raw_path) if raw_path.exists() else None,
                "xml": None,
                "summary": {"error": "timeout"},
                "per_host": [],
                "status": "failed",
                "rc": -2
            }
        except Exception as e:
            return {
                "ts": _now_ts(),
                "tool": self.name,
                "target": target,
                "label": label,
                "args": args,
                "log": str(raw_path) if raw_path.exists() else None,
                "xml": None,
                "summary": {"error": str(e)},
                "per_host": [],
                "status": "failed",
                "rc": -3
            }


# auto-added plugin shim (fallback)
from .plugin_base import Plugin
try:
    from ..scanner import run_nmap
except Exception:
    run_nmap = None

class GobusterPlugin(Plugin):
    name = "gobuster"
    tool = "gobuster"
    category = "network"

    def run(self, target, args, label=None, save_xml=False):
        if run_nmap is None:
            raise RuntimeError("no runner helper available for gobuster")
        logpath, rc, xmlpath, summary = run_nmap(target, args, label, save_xml=save_xml)
        return rc, logpath

try:
    plugin = GobusterPlugin()
except Exception:
    plugin = None


# HELP metadata (H2 style) appended by helper
HELP = {
    "name": "Gobuster",
    "description": "Gobuster: directory/file and DNS/vhost brute force tool. Use with permission and appropriate wordlists.",
    "usage": "menuscript jobs enqueue gobuster <target> --args \"dir -u <url> -w <wordlist> -t <threads>\"",
    "examples": ["menuscript jobs enqueue gobuster http://example.com --args \"dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -t 10\""],
    "flags": [
        ["dir","Dir mode"],
        ["dns","DNS mode"],
        ["-w <wordlist>","Wordlist path"],
        ["-t <threads>","Threads"],
    ],
    "presets": [
        {
            "name": "Dir Quick",
            "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "10"],
            "desc": "Common wordlist quick"
        },
        {
            "name": "Dir Deep",
            "args": ["dir", "-u", "<target>", "-w", "/usr/share/wordlists/raft-large-directories.txt", "-t", "20"],
            "desc": "Large wordlist deep scan"
        },
    ]
}
