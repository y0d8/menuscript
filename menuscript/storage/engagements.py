#!/usr/bin/env python3
"""
menuscript.storage.engagements - Engagement management
"""
from typing import List, Dict, Any, Optional
from .database import get_db
from pathlib import Path
import json

ENGAGEMENT_FILE = Path.home() / ".menuscript" / "current_engagement"


class EngagementManager:
    def __init__(self):
        self.db = get_db()

    def create(self, name: str, description: str = "") -> int:
        """Create new engagement."""
        return self.db.insert("engagements", {
            "name": name,
            "description": description
        })

    def list(self) -> List[Dict[str, Any]]:
        """List all engagements."""
        return self.db.execute("SELECT * FROM engagements ORDER BY created_at DESC")

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """Get engagement by name."""
        return self.db.execute_one("SELECT * FROM engagements WHERE name = ?", (name,))

    def get_by_id(self, engagement_id: int) -> Optional[Dict[str, Any]]:
        """Get engagement by ID."""
        return self.db.execute_one("SELECT * FROM engagements WHERE id = ?", (engagement_id,))

    def set_current(self, name: str) -> bool:
        """Set current engagement."""
        eng = self.get(name)
        if not eng:
            return False

        ENGAGEMENT_FILE.parent.mkdir(parents=True, exist_ok=True)
        ENGAGEMENT_FILE.write_text(str(eng['id']))
        return True

    def get_current(self) -> Optional[Dict[str, Any]]:
        """Get current engagement."""
        if not ENGAGEMENT_FILE.exists():
            # Create default engagement
            default_id = self.create("default", "Default engagement")
            self.set_current("default")
            return self.get_by_id(default_id)

        engagement_id = int(ENGAGEMENT_FILE.read_text().strip())
        return self.get_by_id(engagement_id)

    def delete(self, name: str) -> bool:
        """Delete engagement and all associated data."""
        eng = self.get(name)
        if not eng:
            return False

        # Delete associated data
        self.db.execute("DELETE FROM findings WHERE engagement_id = ?", (eng['id'],))
        self.db.execute("DELETE FROM osint_data WHERE engagement_id = ?", (eng['id'],))
        self.db.execute("DELETE FROM services WHERE host_id IN (SELECT id FROM hosts WHERE engagement_id = ?)", (eng['id'],))
        self.db.execute("DELETE FROM hosts WHERE engagement_id = ?", (eng['id'],))
        self.db.execute("DELETE FROM engagements WHERE id = ?", (eng['id'],))

        return True

    def stats(self, engagement_id: int) -> Dict[str, int]:
        """Get engagement statistics (live hosts only)."""
        # Only count live hosts (status='up')
        hosts = self.db.execute_one(
            "SELECT COUNT(*) as count FROM hosts WHERE engagement_id = ? AND status = 'up'",
            (engagement_id,)
        )
        # Only count services on live hosts
        services = self.db.execute_one(
            "SELECT COUNT(*) as count FROM services WHERE host_id IN (SELECT id FROM hosts WHERE engagement_id = ? AND status = 'up')",
            (engagement_id,)
        )
        findings = self.db.execute_one("SELECT COUNT(*) as count FROM findings WHERE engagement_id = ?", (engagement_id,))

        return {
            "hosts": hosts['count'] if hosts else 0,
            "services": services['count'] if services else 0,
            "findings": findings['count'] if findings else 0,
        }
