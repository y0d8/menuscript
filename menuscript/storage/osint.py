#!/usr/bin/env python3
"""
menuscript.storage.osint - OSINT data management
"""
from typing import List, Dict, Any, Optional
from .database import get_db


class OsintManager:
    """Manages OSINT data (emails, subdomains, URLs, etc.) in the database."""

    def __init__(self):
        self.db = get_db()

    def add_osint_data(
        self,
        workspace_id: int,
        data_type: str,
        value: str,
        source: str = None
    ) -> int:
        """
        Add OSINT data to the database.

        Args:
            workspace_id: Workspace ID
            data_type: Type of data (email, host, ip, url, asn, etc.)
            value: The actual data value
            source: Source tool/method (e.g., 'theHarvester')

        Returns:
            OSINT data ID
        """
        # Check if this exact entry already exists
        existing = self.db.execute_one(
            "SELECT id FROM osint_data WHERE workspace_id = ? AND data_type = ? AND value = ?",
            (workspace_id, data_type, value)
        )

        if existing:
            # Update source if provided and different
            if source:
                self.db.execute(
                    "UPDATE osint_data SET source = ? WHERE id = ?",
                    (source, existing['id'])
                )
            return existing['id']

        # Insert new data
        data = {
            'workspace_id': workspace_id,
            'data_type': data_type,
            'value': value
        }

        if source:
            data['source'] = source

        return self.db.insert('osint_data', data)

    def bulk_add_osint_data(
        self,
        workspace_id: int,
        data_type: str,
        values: List[str],
        source: str = None
    ) -> int:
        """
        Add multiple OSINT data entries of the same type.

        Args:
            workspace_id: Workspace ID
            data_type: Type of data
            values: List of values to add
            source: Source tool/method

        Returns:
            Number of new entries added
        """
        count = 0
        for value in values:
            # Check if exists
            existing = self.db.execute_one(
                "SELECT id FROM osint_data WHERE workspace_id = ? AND data_type = ? AND value = ?",
                (workspace_id, data_type, value)
            )
            if not existing:
                self.add_osint_data(workspace_id, data_type, value, source)
                count += 1
        return count

    def get_osint_data(self, osint_id: int) -> Optional[Dict[str, Any]]:
        """Get OSINT data by ID."""
        query = "SELECT * FROM osint_data WHERE id = ?"
        return self.db.execute_one(query, (osint_id,))

    def list_osint_data(
        self,
        workspace_id: int,
        data_type: str = None,
        source: str = None
    ) -> List[Dict[str, Any]]:
        """
        List OSINT data with optional filters.

        Args:
            workspace_id: Workspace ID
            data_type: Filter by data type (optional)
            source: Filter by source (optional)

        Returns:
            List of OSINT data dicts
        """
        query = "SELECT * FROM osint_data WHERE workspace_id = ?"
        params = [workspace_id]

        if data_type:
            query += " AND data_type = ?"
            params.append(data_type)

        if source:
            query += " AND source = ?"
            params.append(source)

        query += " ORDER BY created_at DESC"

        return self.db.execute(query, tuple(params))

    def get_osint_summary(self, workspace_id: int) -> Dict[str, int]:
        """
        Get summary of OSINT data by type.

        Returns:
            Dict with counts: {'email': 10, 'host': 25, ...}
        """
        query = """
            SELECT data_type, COUNT(*) as count
            FROM osint_data
            WHERE workspace_id = ?
            GROUP BY data_type
        """
        results = self.db.execute(query, (workspace_id,))

        summary = {}
        for row in results:
            data_type = row.get('data_type', 'unknown')
            count = row.get('count', 0)
            summary[data_type] = count

        return summary

    def delete_osint_data(self, osint_id: int) -> bool:
        """Delete OSINT data entry."""
        try:
            self.db.execute("DELETE FROM osint_data WHERE id = ?", (osint_id,))
            return True
        except Exception:
            return False
