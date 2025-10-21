#!/usr/bin/env python3
"""
menuscript.storage.findings - Findings/vulnerabilities database operations
"""
from typing import List, Dict, Any, Optional
from .database import get_db


class FindingsManager:
    """Manages findings (vulnerabilities, misconfigurations, etc.) in the database."""

    def __init__(self):
        self.db = get_db()

    def add_finding(
        self,
        workspace_id: int,
        title: str,
        finding_type: str,
        severity: str = 'info',
        description: str = None,
        host_id: int = None,
        tool: str = None,
        refs: str = None,
        port: int = None,
        path: str = None
    ) -> int:
        """
        Add a finding to the database.

        Args:
            workspace_id: Workspace ID
            title: Finding title/summary
            finding_type: Type of finding (e.g., 'web_vulnerability', 'misconfiguration', etc.)
            severity: Severity level ('critical', 'high', 'medium', 'low', 'info')
            description: Detailed description
            host_id: Associated host ID (optional)
            tool: Tool that discovered the finding
            refs: Reference URL or CVE
            port: Associated port number
            path: Web path or file path

        Returns:
            Finding ID
        """
        data = {
            'workspace_id': workspace_id,
            'title': title,
            'finding_type': finding_type,
            'severity': severity
        }

        if description:
            data['description'] = description
        if host_id:
            data['host_id'] = host_id
        if tool:
            data['tool'] = tool
        if refs:
            data['refs'] = refs
        if port:
            data['port'] = port
        if path:
            data['path'] = path

        return self.db.insert('findings', data)

    def get_finding(self, finding_id: int) -> Optional[Dict[str, Any]]:
        """Get a finding by ID."""
        query = "SELECT * FROM findings WHERE id = ?"
        return self.db.execute_one(query, (finding_id,))

    def list_findings(
        self,
        workspace_id: int,
        host_id: int = None,
        severity: str = None,
        tool: str = None
    ) -> List[Dict[str, Any]]:
        """
        List findings with optional filters.

        Args:
            workspace_id: Workspace ID
            host_id: Filter by host ID (optional)
            severity: Filter by severity (optional)
            tool: Filter by tool (optional)

        Returns:
            List of finding dicts
        """
        query = """
            SELECT
                f.*,
                h.ip_address,
                h.hostname
            FROM findings f
            LEFT JOIN hosts h ON f.host_id = h.id
            WHERE f.workspace_id = ?
        """
        params = [workspace_id]

        if host_id:
            query += " AND f.host_id = ?"
            params.append(host_id)

        if severity:
            query += " AND f.severity = ?"
            params.append(severity)

        if tool:
            query += " AND f.tool = ?"
            params.append(tool)

        query += " ORDER BY f.created_at DESC"

        return self.db.execute(query, tuple(params))

    def update_finding(self, finding_id: int, **kwargs) -> bool:
        """
        Update finding fields.

        Args:
            finding_id: Finding ID
            **kwargs: Fields to update (severity, description, etc.)

        Returns:
            True if update succeeded
        """
        if not kwargs:
            return False

        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        query = f"UPDATE findings SET {set_clause} WHERE id = ?"
        params = list(kwargs.values()) + [finding_id]

        try:
            self.db.execute(query, tuple(params))
            return True
        except Exception:
            return False

    def delete_finding(self, finding_id: int) -> bool:
        """Delete a finding."""
        try:
            self.db.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            return True
        except Exception:
            return False

    def get_findings_summary(self, workspace_id: int) -> Dict[str, int]:
        """
        Get summary of findings by severity.

        Returns:
            Dict with counts: {'critical': 0, 'high': 5, 'medium': 10, ...}
        """
        query = """
            SELECT severity, COUNT(*) as count
            FROM findings
            WHERE workspace_id = ?
            GROUP BY severity
        """
        results = self.db.execute(query, (workspace_id,))

        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for row in results:
            severity = row.get('severity', 'info')
            count = row.get('count', 0)
            if severity in summary:
                summary[severity] = count

        return summary
