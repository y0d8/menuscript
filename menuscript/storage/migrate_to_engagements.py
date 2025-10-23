#!/usr/bin/env python3
"""
Migration script to rename workspaces to engagements
"""
import sqlite3
from pathlib import Path

DB_PATH = Path.home() / ".menuscript" / "menuscript.db"


def migrate():
    """Migrate database from workspaces to engagements."""
    if not DB_PATH.exists():
        print("No existing database found. Skipping migration.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # Check if workspaces table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='workspaces'")
    if not cursor.fetchone():
        print("Database already migrated or no workspaces table found.")
        conn.close()
        return

    print("Starting migration from workspaces to engagements...")

    try:
        # Begin transaction
        cursor.execute("BEGIN TRANSACTION")

        # Rename workspaces table to engagements
        print("  - Renaming workspaces table to engagements...")
        cursor.execute("ALTER TABLE workspaces RENAME TO engagements")

        # Rename workspace_id to engagement_id in hosts table
        print("  - Updating hosts table...")
        cursor.execute("""
            CREATE TABLE hosts_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                os_name TEXT,
                os_accuracy INTEGER,
                mac_address TEXT,
                status TEXT DEFAULT 'up',
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            INSERT INTO hosts_new
            SELECT id, workspace_id, ip_address, hostname, os_name, os_accuracy,
                   mac_address, status, tags, created_at, updated_at
            FROM hosts
        """)
        cursor.execute("DROP TABLE hosts")
        cursor.execute("ALTER TABLE hosts_new RENAME TO hosts")

        # Rename workspace_id to engagement_id in findings table
        print("  - Updating findings table...")
        cursor.execute("""
            CREATE TABLE findings_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                host_id INTEGER,
                service_id INTEGER,
                finding_type TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                refs TEXT,
                port INTEGER,
                path TEXT,
                tool TEXT,
                scan_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            INSERT INTO findings_new
            SELECT id, workspace_id, host_id, service_id, finding_type, severity,
                   title, description, evidence, refs, port, path, tool, scan_id, created_at
            FROM findings
        """)
        cursor.execute("DROP TABLE findings")
        cursor.execute("ALTER TABLE findings_new RENAME TO findings")

        # Check if osint_data table exists and update it
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='osint_data'")
        if cursor.fetchone():
            print("  - Updating osint_data table...")
            cursor.execute("""
                CREATE TABLE osint_data_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER NOT NULL,
                    data_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                INSERT INTO osint_data_new
                SELECT id, workspace_id, data_type, value, source, created_at
                FROM osint_data
            """)
            cursor.execute("DROP TABLE osint_data")
            cursor.execute("ALTER TABLE osint_data_new RENAME TO osint_data")

        # Recreate indexes with new names
        print("  - Recreating indexes...")
        cursor.execute("DROP INDEX IF EXISTS idx_hosts_workspace")
        cursor.execute("DROP INDEX IF EXISTS idx_findings_workspace")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON hosts(engagement_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")

        # Update current_workspace file to current_engagement
        old_file = Path.home() / ".menuscript" / "current_workspace"
        new_file = Path.home() / ".menuscript" / "current_engagement"
        if old_file.exists() and not new_file.exists():
            print("  - Renaming current_workspace file to current_engagement...")
            old_file.rename(new_file)

        # Commit transaction
        cursor.execute("COMMIT")
        conn.close()

        print("✓ Migration completed successfully!")

    except Exception as e:
        print(f"✗ Migration failed: {e}")
        cursor.execute("ROLLBACK")
        conn.close()
        raise


if __name__ == "__main__":
    migrate()
