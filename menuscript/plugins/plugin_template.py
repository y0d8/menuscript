#!/usr/bin/env python3
"""
Plugin template — copy/adapt this file to add new tools.

Guidance:
- prepare(): no heavy work; create artifact dir and return a prepared dict
- run(prepared): execute tool, write raw output to prepared['outdir'], then return ScanResult dict
- Keep run side-effectful (it actually invokes tools); keep prepare lightweight.
"""
from pathlib import Path
import subprocess
import time
from typing import Dict, Any, List, Optional

from ..engine.base import ScannerPlugin, ScanResult

def _now_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class Plugin(ScannerPlugin):
    name = "template"

    def prepare(self, target: str, args: List[str], label: Optional[str]=None) -> Dict[str, Any]:
        outdir = Path.home() / ".menuscript" / "artifacts" / f"{self.name}_{int(time.time())}"
        outdir.mkdir(parents=True, exist_ok=True)
        return {"target": target, "args": args, "label": label, "outdir": str(outdir)}

    def run(self, prepared: Dict[str, Any]) -> ScanResult:
        # Example minimal command (safe)
        cmd = ["echo", "placeholder", str(prepared.get("target"))] + (prepared.get("args") or [])
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        rawfile = Path(prepared["outdir"]) / f"{self.name}.txt"
        rawfile.write_text(p.stdout or "")
        return {
            "ts": _now_ts(),
            "tool": self.name,
            "target": prepared.get("target"),
            "label": prepared.get("label"),
            "args": prepared.get("args"),
            "log": str(rawfile),
            "xml": None,
            "summary": {"note": "template run"},
            "per_host": [],
            "status": "done",
            "rc": p.returncode
        }
