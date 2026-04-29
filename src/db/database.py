"""
Intel Pipeline — Database Abstraction Layer
Creates and manages intel.db. All queries routed through this module.
No inline queries anywhere else in the codebase.
"""

import sqlite3
import os
from datetime import datetime, timezone

# --- Path config ---
ROOT_PATH = os.path.join(os.environ["USERPROFILE"], "Desktop", "Intel")
DB_PATH = os.path.join(ROOT_PATH, "Data", "intel.db")


def get_connection():
    """Return a connection to intel.db with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create all tables if they do not exist. Safe to call on every startup."""
    conn = get_connection()
    cursor = conn.cursor()

    # --- Intel entries ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intel_entries (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            type                TEXT NOT NULL,
            value               TEXT NOT NULL,
            evidence_class      TEXT NOT NULL,
            confidence          REAL NOT NULL DEFAULT 0,
            suggested_severity  TEXT NOT NULL DEFAULT 'info',
            approved_severity   TEXT,
            suggested_tlp       TEXT NOT NULL DEFAULT 'TLP:GREEN',
            approved_tlp        TEXT,
            source_list         TEXT NOT NULL DEFAULT '[]',
            source_count        INTEGER NOT NULL DEFAULT 0,
            first_seen          TEXT NOT NULL,
            last_seen           TEXT NOT NULL,
            ttl                 INTEGER,
            expires_at          TEXT,
            lane                TEXT NOT NULL DEFAULT 'automated',
            status              TEXT NOT NULL DEFAULT 'pending',
            approved_at         TEXT,
            approved_by         TEXT,
            last_reviewed       TEXT,
            engine_action       TEXT,
            description         TEXT,
            affected_vendor     TEXT,
            affected_product    TEXT,
            nvd_versions        TEXT,
            UNIQUE(type, value)
        )
    """)

    # --- Analyst notes (append-only, INSERT only — never UPDATE) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyst_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id    INTEGER NOT NULL,
            note        TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            created_by  TEXT,
            FOREIGN KEY (entry_id) REFERENCES intel_entries(id)
        )
    """)

    # --- Feed configuration ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feed_config (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name       TEXT NOT NULL UNIQUE,
            enabled         INTEGER NOT NULL DEFAULT 1,
            pull_frequency  TEXT NOT NULL DEFAULT 'daily',
            base_weight     REAL NOT NULL DEFAULT 70,
            tier            INTEGER NOT NULL DEFAULT 2,
            last_modified   TEXT NOT NULL
        )
    """)

    # --- Export snapshots (last 5 retained) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS export_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            filename        TEXT NOT NULL,
            sha256          TEXT NOT NULL,
            exported_at     TEXT NOT NULL,
            entry_count     INTEGER NOT NULL,
            tlp             TEXT NOT NULL,
            export_type     TEXT NOT NULL DEFAULT 'standard',
            schema_version  TEXT NOT NULL
        )
    """)

    # --- Audit log (immutable — INSERT only, never UPDATE or DELETE) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT NOT NULL,
            entry_id    INTEGER,
            detail      TEXT,
            performed_by TEXT,
            created_at  TEXT NOT NULL
        )
    """)

    # --- Feed health (pull history per feed) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feed_health (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name       TEXT NOT NULL,
            pull_at         TEXT NOT NULL,
            status          TEXT NOT NULL,
            indicators_new  INTEGER NOT NULL DEFAULT 0,
            indicators_updated INTEGER NOT NULL DEFAULT 0,
            error_message   TEXT
        )
    """)

    _run_migrations(conn)
    conn.commit()
    conn.close()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Database initialised at {DB_PATH}")


def seed_feed_config():
    """
    Insert default feed configuration on first run.
    Safe to call repeatedly — uses INSERT OR IGNORE.
    """
    feeds = [
        ("MITRE ATT&CK",    1, "daily", 85, 1),
        ("CISA KEV",         1, "daily", 85, 1),
        ("Spamhaus ASN-DROP",1, "daily", 80, 1),
        ("MalwareBazaar",    1, "daily", 75, 1),
        ("Feodo Tracker",    1, "daily", 75, 1),
        ("ThreatFox",        1, "daily", 70, 2),
        ("URLhaus",          1, "daily", 70, 2),
        ("AlienVault OTX",   1, "daily", 55, 3),
        ("GreyNoise",        1, "enrichment", 65, 2),
    ]

    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    for name, enabled, frequency, weight, tier in feeds:
        cursor.execute("""
            INSERT OR IGNORE INTO feed_config
                (feed_name, enabled, pull_frequency, base_weight, tier, last_modified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, enabled, frequency, weight, tier, now))

    conn.commit()
    conn.close()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Feed configuration seeded.")


def _run_migrations(conn):
    """Add new columns to existing databases. Safe to call on every startup."""
    migrations = [
        "ALTER TABLE intel_entries ADD COLUMN affected_vendor  TEXT",
        "ALTER TABLE intel_entries ADD COLUMN affected_product TEXT",
        "ALTER TABLE intel_entries ADD COLUMN nvd_versions     TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()


# --- Audit log helper ---
def write_audit(event_type, entry_id=None, detail=None, performed_by=None):
    """Write an immutable audit log entry."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO audit_log (event_type, entry_id, detail, performed_by, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (event_type, entry_id, detail, performed_by, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    seed_feed_config()
