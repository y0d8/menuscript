#!/usr/bin/env python3
"""
PluginBase v2.1 — standardized plugin API for menuscript background jobs
"""
from typing import Optional, List, Dict, Any

class PluginBase:
    """Minimal plugin base class for menuscript."""
    
    name: str = "unnamed"
    tool: str = "unnamed"
    category: str = "misc"
    HELP: Optional[Dict[str, Any]] = None
    
    def __init__(self):
        self.name = getattr(self, "name", self.__class__.__name__)
        self.tool = getattr(self, "tool", self.name).lower()
        self.category = getattr(self, "category", "misc")
    
    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """Execute the plugin action synchronously."""
        raise NotImplementedError(f"{self.__class__.__name__}.run() not implemented")
    
    def enqueue(self, target: str, args: List[str] = None, label: str = "") -> int:
        """Enqueue the plugin action for background processing."""
        try:
            from ..engine.background import enqueue_job
            job_id = enqueue_job(
                tool=self.tool,
                target=target,
                args=args or [],
                label=label or ""
            )
            return job_id
        except ImportError:
            raise NotImplementedError("enqueue() requires background job system")

Plugin = PluginBase
