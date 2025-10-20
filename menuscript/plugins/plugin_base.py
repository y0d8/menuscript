#!/usr/bin/env python3
"""
PluginBase v2 — minimal, explicit plugin API for menuscript.

Plugins should expose:
 - plugin: an instance of a subclass of PluginBase
 - HELP: optional module-level help dict (kept for M1 compatibility)
"""

from typing import Optional, List, Dict, Any

class PluginBase:
    """Minimal plugin base class. Plugins should subclass this and implement run() or enqueue()."""

    name: str = "unnamed"
    tool: str = "unnamed"
    category: str = "misc"
    HELP: Optional[Dict[str, Any]] = None

    def __init__(self):
        # ensure instance attributes exist
        self.name = getattr(self, "name", self.__class__.__name__)
        self.tool = getattr(self, "tool", self.name).lower()
        self.category = getattr(self, "category", "misc")

    def run(self, target: str, args: List[str] = None, label: str = "") -> int:
        """
        Execute the plugin action synchronously (optional).
        Should be overridden by plugins that support sync-run.
        Return 0 on success, non-zero on error.
        """
        raise NotImplementedError("run() not implemented for this plugin")

    def enqueue(self, target: str, args: List[str] = None, label: str = "") -> int:
        """
        Enqueue the plugin action for background processing (optional).
        Plugins that support background jobs should implement this.
        """
        raise NotImplementedError("enqueue() not implemented for this plugin")


# --- Compatibility alias ---
# Some older plugins import `Plugin` from plugin_base.
# Keep that working by aliasing Plugin -> PluginBase.
try:
    Plugin = PluginBase
except Exception:
    # best-effort (should never fail)
    pass
