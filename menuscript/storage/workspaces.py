#!/usr/bin/env python3
"""
menuscript.storage.workspaces - Workspace management
"""
from typing import List, Dict, Any, Optional
from .database import get_db
from pathlib import Path
import json

WORKSPACE_FILE = Path.home() / ".menuscript" / "current_workspace"


class WorkspaceManager:
    def __init__(self):
        self.db = get_db()
    
    def create(self, name: str, description: str = "") -> int:
        """Create new workspace."""
        return self.db.insert("workspaces", {
            "name": name,
            "description": description
        })
    
    def list(self) -> List[Dict[str, Any]]:
        """List all workspaces."""
        return self.db.execute("SELECT * FROM workspaces ORDER BY created_at DESC")
    
    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """Get workspace by name."""
        return self.db.execute_one("SELECT * FROM workspaces WHERE name = ?", (name,))
    
    def get_by_id(self, workspace_id: int) -> Optional[Dict[str, Any]]:
        """Get workspace by ID."""
        return self.db.execute_one("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
    
    def set_current(self, name: str) -> bool:
        """Set current workspace."""
        ws = self.get(name)
        if not ws:
            return False
        
        WORKSPACE_FILE.parent.mkdir(parents=True, exist_ok=True)
        WORKSPACE_FILE.write_text(str(ws['id']))
        return True
    
    def get_current(self) -> Optional[Dict[str, Any]]:
        """Get current workspace."""
        if not WORKSPACE_FILE.exists():
            # Create default workspace
            default_id = self.create("default", "Default workspace")
            self.set_current("default")
            return self.get_by_id(default_id)
        
        workspace_id = int(WORKSPACE_FILE.read_text().strip())
        return self.get_by_id(workspace_id)
    
    def delete(self, name: str) -> bool:
        """Delete workspace and all associated data."""
        ws = self.get(name)
        if not ws:
            return False
        
        # Delete associated data
        self.db.execute("DELETE FROM findings WHERE workspace_id = ?", (ws['id'],))
        self.db.execute("DELETE FROM osint_data WHERE workspace_id = ?", (ws['id'],))
        self.db.execute("DELETE FROM services WHERE host_id IN (SELECT id FROM hosts WHERE workspace_id = ?)", (ws['id'],))
        self.db.execute("DELETE FROM hosts WHERE workspace_id = ?", (ws['id'],))
        self.db.execute("DELETE FROM workspaces WHERE id = ?", (ws['id'],))
        
        return True
    
    def stats(self, workspace_id: int) -> Dict[str, int]:
        """Get workspace statistics."""
        hosts = self.db.execute_one("SELECT COUNT(*) as count FROM hosts WHERE workspace_id = ?", (workspace_id,))
        services = self.db.execute_one(
            "SELECT COUNT(*) as count FROM services WHERE host_id IN (SELECT id FROM hosts WHERE workspace_id = ?)",
            (workspace_id,)
        )
        findings = self.db.execute_one("SELECT COUNT(*) as count FROM findings WHERE workspace_id = ?", (workspace_id,))
        
        return {
            "hosts": hosts['count'] if hosts else 0,
            "services": services['count'] if services else 0,
            "findings": findings['count'] if findings else 0,
        }
