#!/usr/bin/env python3
"""
menuscript.storage.web_paths - Web paths/directories management
"""
from typing import List, Dict, Any, Optional
from .database import get_db


class WebPathsManager:
    """Manages discovered web paths (directories, files, etc.) in the database."""

    def __init__(self):
        self.db = get_db()

    def add_web_path(
        self,
        host_id: int,
        url: str,
        status_code: int = None,
        content_length: int = None
    ) -> int:
        """
        Add a web path to the database.

        Args:
            host_id: Associated host ID
            url: Full URL or path
            status_code: HTTP status code
            content_length: Response size in bytes

        Returns:
            Web path ID
        """
        # Check if this exact path already exists for this host
        existing = self.db.execute_one(
            "SELECT id FROM web_paths WHERE host_id = ? AND url = ?",
            (host_id, url)
        )

        if existing:
            # Update if status or length changed
            if status_code is not None or content_length is not None:
                update_data = {}
                if status_code is not None:
                    update_data['status_code'] = status_code
                if content_length is not None:
                    update_data['content_length'] = content_length

                if update_data:
                    set_clause = ', '.join([f"{k} = ?" for k in update_data.keys()])
                    values = list(update_data.values()) + [existing['id']]
                    self.db.execute(
                        f"UPDATE web_paths SET {set_clause} WHERE id = ?",
                        tuple(values)
                    )
            return existing['id']

        # Insert new path
        data = {
            'host_id': host_id,
            'url': url
        }

        if status_code is not None:
            data['status_code'] = status_code
        if content_length is not None:
            data['content_length'] = content_length

        return self.db.insert('web_paths', data)

    def bulk_add_web_paths(
        self,
        host_id: int,
        paths: List[Dict[str, Any]]
    ) -> int:
        """
        Add multiple web paths for a host.

        Args:
            host_id: Associated host ID
            paths: List of path dicts with url, status_code, content_length

        Returns:
            Number of new paths added
        """
        count = 0
        for path in paths:
            # Check if exists
            existing = self.db.execute_one(
                "SELECT id FROM web_paths WHERE host_id = ? AND url = ?",
                (host_id, path.get('url'))
            )
            if not existing:
                self.add_web_path(
                    host_id,
                    path.get('url'),
                    path.get('status_code'),
                    path.get('size')  # gobuster uses 'size' field
                )
                count += 1
        return count

    def get_web_path(self, path_id: int) -> Optional[Dict[str, Any]]:
        """Get a web path by ID."""
        query = "SELECT * FROM web_paths WHERE id = ?"
        return self.db.execute_one(query, (path_id,))

    def list_web_paths(
        self,
        host_id: int = None,
        workspace_id: int = None,
        status_code: int = None
    ) -> List[Dict[str, Any]]:
        """
        List web paths with optional filters.

        Args:
            host_id: Filter by host ID (optional)
            workspace_id: Filter by workspace ID (optional)
            status_code: Filter by HTTP status code (optional)

        Returns:
            List of web path dicts
        """
        if workspace_id:
            query = """
                SELECT wp.*, h.ip_address, h.hostname
                FROM web_paths wp
                JOIN hosts h ON wp.host_id = h.id
                WHERE h.workspace_id = ?
            """
            params = [workspace_id]
        elif host_id:
            query = """
                SELECT wp.*, h.ip_address, h.hostname
                FROM web_paths wp
                JOIN hosts h ON wp.host_id = h.id
                WHERE wp.host_id = ?
            """
            params = [host_id]
        else:
            query = "SELECT * FROM web_paths WHERE 1=1"
            params = []

        if status_code is not None:
            query += " AND wp.status_code = ?" if workspace_id or host_id else " AND status_code = ?"
            params.append(status_code)

        query += " ORDER BY wp.created_at DESC"

        return self.db.execute(query, tuple(params))

    def get_paths_summary(self, workspace_id: int) -> Dict[str, int]:
        """
        Get summary of web paths by status code.

        Returns:
            Dict with counts: {'200': 10, '301': 5, '403': 2, ...}
        """
        query = """
            SELECT wp.status_code, COUNT(*) as count
            FROM web_paths wp
            JOIN hosts h ON wp.host_id = h.id
            WHERE h.workspace_id = ?
            GROUP BY wp.status_code
        """
        results = self.db.execute(query, (workspace_id,))

        summary = {}
        for row in results:
            status = str(row.get('status_code', 'unknown'))
            count = row.get('count', 0)
            summary[status] = count

        return summary

    def delete_web_path(self, path_id: int) -> bool:
        """Delete a web path."""
        try:
            self.db.execute("DELETE FROM web_paths WHERE id = ?", (path_id,))
            return True
        except Exception:
            return False
