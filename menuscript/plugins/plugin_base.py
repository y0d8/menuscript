#!/usr/bin/env python3
"""
PluginBase v2.1 — standardized plugin API for menuscript background jobs

Standard plugin.run() signature for background jobs:
  run(target: str, args: List[str], label: str, log_path: str) -> int
  
  - target: IP, domain, or URL to scan
  - args: list of tool-specific arguments
  - label: optional user label for this job
  - log_path: absolute path where plugin should write output
  - Returns: exit code (0=success, non-zero=error)

Plugins should:
  1. Write all output (stdout/stderr) to log_path
  2. Handle errors gracefully and log them
  3. Return 0 on success, non-zero on failure
"""
from typing import Optional, List, Dict, Any

class PluginBase:
    """Minimal plugin base class for menuscript."""
    
    name: str = "unnamed"
    tool: str = "unnamed"
    category: str = "misc"
    HELP: Optional[Dict[str, Any]] = None
    
    def __init__(self):
        # Ensure instance attributes exist
        self.name = getattr(self, "name", self.__class__.__name__)
        self.tool = getattr(self, "tool", self.name).lower()
        self.category = getattr(self, "category", "misc")
    
    def run(self, target: str, args: List[str] = None, label: str = "", log_path: str = None) -> int:
        """
        Execute the plugin action synchronously.
        
        Args:
            target: Target IP/domain/URL
            args: Tool-specific arguments (default: [])
            label: User label for this scan (default: "")
            log_path: Path to write output logs (required for background jobs)
        
        Returns:
            int: Exit code (0=success, non-zero=error)
        
        Must be implemented by subclasses.
        """
        raise NotImplementedError(f"{self.__class__.__name__}.run() not implemented")
    
    def enqueue(self, target: str, args: List[str] = None, label: str = "") -> int:
        """
        Enqueue the plugin action for background processing (optional).
        
        Default implementation uses the background job system.
        Override if you need custom enqueue behavior.
        """
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

# Compatibility alias for older plugins
Plugin = PluginBase
