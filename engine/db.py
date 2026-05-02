"""
Cerberus — engine/db.py

Single source of truth for all database operations.
Every other engine module imports from here.
No other file should open its own database connection.

Database: SQLite (single file, no server needed)
Location: data/recon.db
"""

import sqlite3
import os
from datetime import datetime


BASE_DIR = os.path.expanduser("~/Documents/cerberus")
DB_PATH  = os.path.join(BASE_DIR, "data", "recon.db")


# =============================================================================
# CONNECTION
# =============================================================================

def get_db() -> sqlite3.Connection:
    """
    Open and return a connection to recon.db.

    sqlite3.Row allows columns to be accessed by name:
        row["port"]  instead of  row[2]
    This makes downstream code much more readable and less fragile.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =============================================================================
# SCHEMA
# =============================================================================

def init_db() -> None:
    """
    Create all tables and indexes if they do not exist yet.
    Safe to call on every run — CREATE IF NOT EXISTS is idempotent.

    Tables:
        port_observations    — one row per open port per nmap scan
        connection_snapshots — one row per connection per ss snapshot
        parsed_files         — registry of already-ingested files
    """
    conn   = get_db()
    cursor = conn.cursor()

    # ------------------------------------------------------------------
    # port_observations
    # Primary data source for the baseline engine and ML detector.
    # Each row represents one port seen as open in one nmap scan.
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_observations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            port        INTEGER NOT NULL,
            protocol    TEXT,
            state       TEXT,
            service     TEXT,
            version     TEXT,
            parsed_at   TEXT    NOT NULL
        )
    """)

    # ------------------------------------------------------------------
    # connection_snapshots
    # One row per active or listening connection captured by ss.
    # Used to enrich port behaviour profiles in the baseline engine.
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            local_address   TEXT,
            local_port      INTEGER,
            remote_address  TEXT,
            remote_port     INTEGER,
            state           TEXT,
            process         TEXT,
            parsed_at       TEXT    NOT NULL
        )
    """)

    # ------------------------------------------------------------------
    # parsed_files
    # Tracks every file already ingested by parser.py.
    # Prevents the same scan file from being counted twice
    # if main.py is run multiple times.
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS parsed_files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT    UNIQUE NOT NULL,
            parsed_at   TEXT    NOT NULL
        )
    """)

    # ------------------------------------------------------------------
    # Indexes
    # These make per-port queries significantly faster once
    # thousands of rows have accumulated.
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_port_obs_port
        ON port_observations(port)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_port_obs_timestamp
        ON port_observations(timestamp)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_conn_local_port
        ON connection_snapshots(local_port)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_conn_timestamp
        ON connection_snapshots(timestamp)
    """)

    conn.commit()
    conn.close()
    print(f"[+] Database initialised → {DB_PATH}")


# =============================================================================
# HELPERS
# =============================================================================

def already_parsed(filename: str) -> bool:
    """
    Return True if this filename exists in parsed_files.
    Called by parser.py before processing each file.
    """
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM parsed_files WHERE filename = ?",
        (filename,)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


def mark_parsed(filename: str) -> None:
    """
    Insert filename into parsed_files after successful ingestion.
    INSERT OR IGNORE means this is safe to call even if the file
    somehow already exists — no duplicate, no crash.
    """
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO parsed_files (filename, parsed_at) VALUES (?, ?)",
        (filename, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


# =============================================================================
# STATS
# =============================================================================

def get_stats() -> dict:
    """
    Return a summary of what is currently in the database.
    Printed by main.py at the end of each run.
    """
    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM port_observations")
    port_rows = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM connection_snapshots")
    conn_rows = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM parsed_files")
    files_parsed = cursor.fetchone()[0]

    cursor.execute("""
        SELECT timestamp FROM port_observations
        ORDER BY timestamp DESC
        LIMIT 1
    """)
    latest      = cursor.fetchone()
    latest_scan = latest[0] if latest else "none yet"

    cursor.execute("""
        SELECT port, COUNT(*) AS seen
        FROM port_observations
        WHERE state = 'open'
        GROUP BY port
        ORDER BY seen DESC
        LIMIT 5
    """)
    top_ports = [
        {"port": r["port"], "seen": r["seen"]}
        for r in cursor.fetchall()
    ]

    conn.close()

    return {
        "port_observation_rows":    port_rows,
        "connection_snapshot_rows": conn_rows,
        "files_parsed":             files_parsed,
        "latest_scan":              latest_scan,
        "top_5_open_ports":         top_ports,
    }


# =============================================================================
# ENTRY POINT — run directly to initialise the database
# =============================================================================

if __name__ == "__main__":
    print("=== Cerberus — Database Setup ===\n")
    init_db()

    print("\n--- Current stats ---")
    stats = get_stats()
    for key, val in stats.items():
        print(f"  {key}: {val}")
