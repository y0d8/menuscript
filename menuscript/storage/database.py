#!/usr/bin/env python3
"""
menuscript.storage.database - Core database operations
"""
import sqlite3
import os
from typing import Optional, List, Dict, Any
from pathlib import Path

DB_PATH = Path.home() / ".menuscript" / "menuscript.db"


class Database:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(DB_PATH)
        self._ensure_db()
    
    def _ensure_db(self):
        """Ensure database and schema exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        
        # Load and execute schema from the same directory as this file
        schema_path = Path(__file__).parent / "schema.sql"
        
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
                conn.executescript(schema_sql)
        else:
            # If schema file doesn't exist, create minimal tables inline
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS workspaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace_id INTEGER NOT NULL,
                    ip_address TEXT NOT NULL,
                    hostname TEXT,
                    os_name TEXT,
                    status TEXT DEFAULT 'up',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
                    UNIQUE(workspace_id, ip_address)
                );
                
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    state TEXT DEFAULT 'open',
                    service_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts(id),
                    UNIQUE(host_id, port, protocol)
                );
                
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace_id INTEGER NOT NULL,
                    host_id INTEGER,
                    finding_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    title TEXT NOT NULL,
                    description TEXT,
                    tool TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );
            """)
        
        conn.commit()
        conn.close()
    
    def get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def execute(self, query: str, params: tuple = None) -> List[Dict[str, Any]]:
        """Execute query and return results."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.commit()
        conn.close()
        
        return results
    
    def execute_one(self, query: str, params: tuple = None) -> Optional[Dict[str, Any]]:
        """Execute query and return single result."""
        results = self.execute(query, params)
        return results[0] if results else None
    
    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert row and return ID."""
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?' for _ in data])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, tuple(data.values()))
        row_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return row_id


# Singleton instance
_db = None

def get_db() -> Database:
    """Get database singleton."""
    global _db
    if _db is None:
        _db = Database()
    return _db
