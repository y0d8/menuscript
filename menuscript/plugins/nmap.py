#!/usr/bin/env python3
"""
menuscript.plugins.nmap

Plugin wrapper for existing run_nmap function.

Design notes:
- Keeps a thin layer over menuscript.scanner.run_nmap to adapt to the Plugin interface.
- Returns a ScanResult dict with the canonical keys used by the DB writer.
- Non-destructive defaults are respected by whatever args you pass; the plugin does not force risky flags.
"""
from pathlib import Path
import time
from typing import Dict, Any, List, Optional

from ..engine.base import ScannerPlugin, ScanResult

# Import the existing nmap runner (the function you already have)
# It should have signature: run_nmap(target, args, label, save_xml=False) -> (logpath, rc, xmlpath, summary)
from .. import scanner

def _now_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

class Plugin(ScannerPlugin):
    name = "nmap"

    def prepare(self, target: str, args: List[str], label: Optional[str]=None) -> Dict[str, Any]:
        """
        Prepare minimal execution context: create artifact dir and return prepared dict.
        Keep side effects minimal: only ensure artifact folder exists.
        """
        outdir = Path.home() / ".menuscript" / "artifacts" / f"nmap_{int(time.time())}"
        outdir.mkdir(parents=True, exist_ok=True)
        return {"target": target, "args": args, "label": label, "outdir": str(outdir)}

    def run(self, prepared: Dict[str, Any]) -> ScanResult:
        """
        Run nmap using existing scanner.run_nmap(). Return a ScanResult dict.
        This function is intentionally simple and delegates parsing to your existing scanner.
        """
        target = prepared.get("target")
        args = prepared.get("args") or []
        label = prepared.get("label") or ""
        # Ask whether to save XML is a UI concern; here plugin does not interactively prompt.
        # Keep non-destructive default: do not save XML unless caller requested it via args (caller can set save_xml=True in manager).
        save_xml = False
        # Call into existing scanner.run_nmap
        try:
            logpath, rc, xmlpath, summary = scanner.run_nmap(target, args, label, save_xml=save_xml)
        except Exception as e:
            # Return failed result and include error message in summary
            return {
                "ts": _now_ts(),
                "tool": self.name,
                "target": target,
                "label": label,
                "args": args,
                "log": None,
                "xml": None,
                "summary": {"error": str(e)},
                "per_host": [],
                "status": "failed",
                "rc": -1
            }

        return {
            "ts": _now_ts(),
            "tool": self.name,
            "target": target,
            "label": label,
            "args": args,
            "log": str(logpath) if logpath else None,
            "xml": str(xmlpath) if xmlpath else None,
            "summary": summary or {},
            "per_host": (summary.get("per_host") if isinstance(summary, dict) else []) or [],
            "status": "done" if (rc == 0) else "done",
            "rc": int(rc) if rc is not None else 0
        }
