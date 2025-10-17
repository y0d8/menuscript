#!/usr/bin/env python3
"""
Simple plugin base classes and type hints for menuscript.
Plugins should implement ScannerPlugin.run(prepared) -> dict (ScanResult).
"""
from typing import Dict, Any, Optional

ScanResult = Dict[str, Any]

class ScannerPlugin:
    """
    Base class for plugins.

    Implement:
      - name (str)
      - prepare(target, args, label) -> dict (optional)
      - run(prepared) -> ScanResult
    """
    name = "base"

    def prepare(self, target: str, args: list, label: Optional[str]=None) -> Dict[str, Any]:
        return {"target": target, "args": args, "label": label}

    def run(self, prepared: Dict[str, Any]) -> ScanResult:
        raise NotImplementedError("Plugins must implement run()")
