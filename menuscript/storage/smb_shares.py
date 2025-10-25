#!/usr/bin/env python3
"""
menuscript.storage.smb_shares - SMB shares storage and retrieval
"""
from typing import Dict, List, Any, Optional
from .database import get_db


class SMBSharesManager:
    """Manage SMB shares discovered via smbmap."""

    def add_share(self, host_id: int, share_data: Dict[str, Any]) -> int:
        """
        Add or update an SMB share.

        Args:
            host_id: Host ID this share belongs to
            share_data: Dict with keys: name, type, permissions, comment, readable, writable

        Returns:
            Share ID
        """
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()

        # Check if share already exists
        cursor.execute(
            "SELECT id FROM smb_shares WHERE host_id = ? AND share_name = ?",
            (host_id, share_data['name'])
        )
        existing = cursor.fetchone()

        if existing:
            # Update existing
            cursor.execute("""
                UPDATE smb_shares
                SET share_type = ?, permissions = ?, comment = ?,
                    readable = ?, writable = ?
                WHERE id = ?
            """, (
                share_data.get('type', ''),
                share_data.get('permissions', ''),
                share_data.get('comment', ''),
                1 if share_data.get('readable') else 0,
                1 if share_data.get('writable') else 0,
                existing[0]
            ))
            conn.commit()
            conn.close()
            return existing[0]
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO smb_shares (host_id, share_name, share_type, permissions, comment, readable, writable)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                host_id,
                share_data['name'],
                share_data.get('type', ''),
                share_data.get('permissions', ''),
                share_data.get('comment', ''),
                1 if share_data.get('readable') else 0,
                1 if share_data.get('writable') else 0
            ))
            row_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return row_id

    def add_file(self, share_id: int, file_data: Dict[str, Any]) -> int:
        """
        Add a file/directory entry to a share.

        Args:
            share_id: Share ID
            file_data: Dict with keys: path, size, timestamp, is_directory

        Returns:
            File ID
        """
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()

        # Check if file already exists
        cursor.execute(
            "SELECT id FROM smb_files WHERE share_id = ? AND path = ?",
            (share_id, file_data['path'])
        )
        existing = cursor.fetchone()

        if existing:
            # Update existing
            cursor.execute("""
                UPDATE smb_files
                SET size = ?, timestamp = ?, is_directory = ?
                WHERE id = ?
            """, (
                file_data.get('size', 0),
                file_data.get('timestamp', ''),
                1 if file_data.get('is_directory') else 0,
                existing[0]
            ))
            conn.commit()
            conn.close()
            return existing[0]
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO smb_files (share_id, path, size, timestamp, is_directory)
                VALUES (?, ?, ?, ?, ?)
            """, (
                share_id,
                file_data['path'],
                file_data.get('size', 0),
                file_data.get('timestamp', ''),
                1 if file_data.get('is_directory') else 0
            ))
            row_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return row_id

    def list_shares(self, engagement_id: int, host_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        List all SMB shares for an engagement or specific host.

        Args:
            engagement_id: Engagement ID
            host_id: Optional host ID to filter by

        Returns:
            List of share dicts
        """
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()

        if host_id:
            cursor.execute("""
                SELECT s.*, h.ip_address, h.hostname
                FROM smb_shares s
                JOIN hosts h ON s.host_id = h.id
                WHERE h.engagement_id = ? AND s.host_id = ?
                ORDER BY h.ip_address, s.share_name
            """, (engagement_id, host_id))
        else:
            cursor.execute("""
                SELECT s.*, h.ip_address, h.hostname
                FROM smb_shares s
                JOIN hosts h ON s.host_id = h.id
                WHERE h.engagement_id = ?
                ORDER BY h.ip_address, s.share_name
            """, (engagement_id,))

        shares = []
        for row in cursor.fetchall():
            shares.append({
                'id': row[0],
                'host_id': row[1],
                'share_name': row[2],
                'share_type': row[3],
                'permissions': row[4],
                'comment': row[5],
                'readable': bool(row[6]),
                'writable': bool(row[7]),
                'created_at': row[8],
                'ip_address': row[9],
                'hostname': row[10]
            })

        conn.close()
        return shares

    def get_share_files(self, share_id: int) -> List[Dict[str, Any]]:
        """
        Get all files for a specific share.

        Args:
            share_id: Share ID

        Returns:
            List of file dicts
        """
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, share_id, path, size, timestamp, is_directory, created_at
            FROM smb_files
            WHERE share_id = ?
            ORDER BY is_directory DESC, path
        """, (share_id,))

        files = []
        for row in cursor.fetchall():
            files.append({
                'id': row[0],
                'share_id': row[1],
                'path': row[2],
                'size': row[3],
                'timestamp': row[4],
                'is_directory': bool(row[5]),
                'created_at': row[6]
            })

        conn.close()
        return files

    def get_writable_shares(self, engagement_id: int) -> List[Dict[str, Any]]:
        """Get all writable shares (security concern)."""
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT s.*, h.ip_address, h.hostname
            FROM smb_shares s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.engagement_id = ? AND s.writable = 1
            ORDER BY h.ip_address, s.share_name
        """, (engagement_id,))

        shares = []
        for row in cursor.fetchall():
            shares.append({
                'id': row[0],
                'host_id': row[1],
                'share_name': row[2],
                'share_type': row[3],
                'permissions': row[4],
                'comment': row[5],
                'readable': bool(row[6]),
                'writable': bool(row[7]),
                'created_at': row[8],
                'ip_address': row[9],
                'hostname': row[10]
            })

        conn.close()
        return shares

    def get_stats(self, engagement_id: int) -> Dict[str, int]:
        """Get SMB shares statistics."""
        db = get_db()
        conn = db.get_connection()
        cursor = conn.cursor()

        # Count total shares
        cursor.execute("""
            SELECT COUNT(*)
            FROM smb_shares s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.engagement_id = ?
        """, (engagement_id,))
        total = cursor.fetchone()[0]

        # Count writable shares
        cursor.execute("""
            SELECT COUNT(*)
            FROM smb_shares s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.engagement_id = ? AND s.writable = 1
        """, (engagement_id,))
        writable = cursor.fetchone()[0]

        # Count readable shares
        cursor.execute("""
            SELECT COUNT(*)
            FROM smb_shares s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.engagement_id = ? AND s.readable = 1
        """, (engagement_id,))
        readable = cursor.fetchone()[0]

        # Count hosts with SMB
        cursor.execute("""
            SELECT COUNT(DISTINCT s.host_id)
            FROM smb_shares s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.engagement_id = ?
        """, (engagement_id,))
        hosts_with_smb = cursor.fetchone()[0]

        conn.close()
        return {
            'total_shares': total,
            'writable': writable,
            'readable': readable,
            'hosts_with_smb': hosts_with_smb
        }
