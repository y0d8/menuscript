#!/usr/bin/env python3
"""
menuscript.storage.credentials - Credential storage and management

Similar to MSF's creds command - tracks enumerated usernames and discovered passwords.
"""
from typing import List, Dict, Any, Optional
from .database import get_db


class CredentialsManager:
    def __init__(self):
        self.db = get_db()
        self._ensure_table()

    def _ensure_table(self):
        """Ensure credentials table exists."""
        conn = self.db.get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                host_id INTEGER,
                service TEXT,
                port INTEGER,
                protocol TEXT DEFAULT 'tcp',
                username TEXT,
                password TEXT,
                credential_type TEXT DEFAULT 'user',
                status TEXT DEFAULT 'untested',
                tool TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id),
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        """)

        # Create index for faster lookups
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_credentials_engagement
            ON credentials(engagement_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_credentials_host
            ON credentials(host_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_credentials_status
            ON credentials(status)
        """)

        conn.commit()
        conn.close()

    def add_credential(
        self,
        engagement_id: int,
        host_id: int,
        username: str = None,
        password: str = None,
        service: str = None,
        port: int = None,
        protocol: str = 'tcp',
        credential_type: str = 'user',
        status: str = 'untested',
        tool: str = None
    ) -> int:
        """
        Add a credential to the database.

        Args:
            engagement_id: Engagement ID
            host_id: Host ID
            username: Username (optional for password-only creds)
            password: Password (optional for username enumeration)
            service: Service name (ssh, smb, mysql, etc.)
            port: Service port
            protocol: Protocol (tcp/udp)
            credential_type: Type of credential (user, password, hash, key)
            status: Status (untested, valid, invalid)
            tool: Tool that discovered this credential

        Returns:
            Credential ID
        """
        # Check for duplicates
        existing = self.get_credential(
            engagement_id, host_id, username, password, service, port
        )
        if existing:
            # Update status if this one is more definitive
            if status == 'valid' and existing['status'] != 'valid':
                self._update_status(existing['id'], status, tool)
            return existing['id']

        # Special case: If adding a valid username:password pair, check if we have
        # a username-only entry that should be upgraded instead of creating duplicate
        if username and password and status == 'valid':
            username_only = self.get_credential(
                engagement_id, host_id, username, None, service, port
            )
            if username_only:
                # Upgrade the existing entry with the password
                self._update_credential(username_only['id'], password=password, status=status, tool=tool)
                return username_only['id']

        data = {
            'engagement_id': engagement_id,
            'host_id': host_id,
            'service': service,
            'port': port,
            'protocol': protocol,
            'username': username,
            'password': password,
            'credential_type': credential_type,
            'status': status,
            'tool': tool
        }

        return self.db.insert('credentials', data)

    def get_credential(
        self,
        engagement_id: int,
        host_id: int,
        username: str = None,
        password: str = None,
        service: str = None,
        port: int = None
    ) -> Optional[Dict[str, Any]]:
        """Check if credential already exists."""
        query = """
            SELECT * FROM credentials
            WHERE engagement_id = ? AND host_id = ?
        """
        params = [engagement_id, host_id]

        if username is not None:
            query += " AND username = ?"
            params.append(username)
        else:
            query += " AND username IS NULL"

        if password is not None:
            query += " AND password = ?"
            params.append(password)
        else:
            query += " AND password IS NULL"

        if service is not None:
            query += " AND service = ?"
            params.append(service)

        if port is not None:
            query += " AND port = ?"
            params.append(port)

        query += " LIMIT 1"

        return self.db.execute_one(query, tuple(params))

    def _update_status(self, credential_id: int, status: str, tool: str = None):
        """Update credential status."""
        conn = self.db.get_connection()
        if tool:
            conn.execute(
                "UPDATE credentials SET status = ?, tool = ? WHERE id = ?",
                (status, tool, credential_id)
            )
        else:
            conn.execute(
                "UPDATE credentials SET status = ? WHERE id = ?",
                (status, credential_id)
            )
        conn.commit()
        conn.close()

    def _update_credential(self, credential_id: int, password: str = None, status: str = None, tool: str = None):
        """Update credential with password and/or status."""
        conn = self.db.get_connection()

        updates = []
        params = []

        if password is not None:
            updates.append("password = ?")
            params.append(password)

        if status is not None:
            updates.append("status = ?")
            params.append(status)

        if tool is not None:
            updates.append("tool = ?")
            params.append(tool)

        if updates:
            query = f"UPDATE credentials SET {', '.join(updates)} WHERE id = ?"
            params.append(credential_id)
            conn.execute(query, tuple(params))

        conn.commit()
        conn.close()

    def update_credential_status(self, credential_id: int, status: str):
        """
        Update the status of a credential.

        Args:
            credential_id: Credential ID
            status: New status (valid, invalid, untested, discovered, etc.)
        """
        self._update_credential(credential_id, status=status)

    def list_credentials(
        self,
        engagement_id: int,
        host_id: int = None,
        service: str = None,
        status: str = None
    ) -> List[Dict[str, Any]]:
        """
        List credentials for an engagement.

        Args:
            engagement_id: Engagement ID
            host_id: Filter by host (optional)
            service: Filter by service (optional)
            status: Filter by status (optional)

        Returns:
            List of credentials with host information
        """
        query = """
            SELECT
                c.*,
                h.ip_address,
                h.hostname
            FROM credentials c
            LEFT JOIN hosts h ON c.host_id = h.id
            WHERE c.engagement_id = ?
        """
        params = [engagement_id]

        if host_id:
            query += " AND c.host_id = ?"
            params.append(host_id)

        if service:
            query += " AND c.service = ?"
            params.append(service)

        if status:
            query += " AND c.status = ?"
            params.append(status)

        query += " ORDER BY c.created_at DESC"

        return self.db.execute(query, tuple(params))

    def get_stats(self, engagement_id: int) -> Dict[str, int]:
        """Get credential statistics for an engagement."""
        conn = self.db.get_connection()

        # Total credentials
        total = conn.execute(
            "SELECT COUNT(*) as count FROM credentials WHERE engagement_id = ?",
            (engagement_id,)
        ).fetchone()['count']

        # Valid credentials (confirmed working)
        valid = conn.execute(
            "SELECT COUNT(*) as count FROM credentials WHERE engagement_id = ? AND status = 'valid'",
            (engagement_id,)
        ).fetchone()['count']

        # Username-only (enumerated users)
        users_only = conn.execute(
            "SELECT COUNT(*) as count FROM credentials WHERE engagement_id = ? AND username IS NOT NULL AND password IS NULL",
            (engagement_id,)
        ).fetchone()['count']

        # Password-only
        passwords_only = conn.execute(
            "SELECT COUNT(*) as count FROM credentials WHERE engagement_id = ? AND username IS NULL AND password IS NOT NULL",
            (engagement_id,)
        ).fetchone()['count']

        # Username:password pairs
        pairs = conn.execute(
            "SELECT COUNT(*) as count FROM credentials WHERE engagement_id = ? AND username IS NOT NULL AND password IS NOT NULL",
            (engagement_id,)
        ).fetchone()['count']

        conn.close()

        return {
            'total': total,
            'valid': valid,
            'users_only': users_only,
            'passwords_only': passwords_only,
            'pairs': pairs
        }
