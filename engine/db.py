import sqlite3
import os
from datetime import datetime


BASE_DIR = os.path.expanduser("~/Documents/cerberus")
DB_PATH  = os.path.join(BASE_DIR, "data", "recon.db")


# ─── CONNECTION ───────────────────────────────────────────────────────────────

def get_db():
    """Return a connection to the SQLite database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # access columns by name, not index
    return conn


# ─── SCHEMA ───────────────────────────────────────────────────────────────────

def init_db():
    """Create all tables and indexes if they don't exist yet."""
    conn   = get_db()
    cursor = conn.cursor()

    # One row per open port per nmap scan
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_observations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            ip          TEXT NOT NULL,
            port        INTEGER NOT NULL,
            protocol    TEXT,
            state       TEXT,
            service     TEXT,
            version     TEXT,
            parsed_at   TEXT NOT NULL
        )
    """)

    # One row per active/listening connection captured by ss
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            local_address   TEXT,
            local_port      INTEGER,
            remote_address  TEXT,
            remote_port     INTEGER,
            state           TEXT,
            process         TEXT,
            parsed_at       TEXT NOT NULL
        )
    """)

    # Tracks which raw files have already been ingested
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS parsed_files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT UNIQUE NOT NULL,
            parsed_at   TEXT NOT NULL
        )
    """)

    # Indexes so baseline and ML queries run fast on large datasets
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
    print(f"[+] Database initialised at: {DB_PATH}")


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def already_parsed(filename):
    """Return True if this file has already been ingested."""
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM parsed_files WHERE filename = ?", (filename,)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


def mark_parsed(filename):
    """Record a file as ingested so it is never processed again."""
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO parsed_files (filename, parsed_at) VALUES (?, ?)",
        (filename, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


# ─── STATS ────────────────────────────────────────────────────────────────────

def get_stats():
    """Return a quick summary of what is currently in the database."""
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
        ORDER BY timestamp DESC LIMIT 1
    """)
    latest     = cursor.fetchone()
    latest_scan = latest[0] if latest else "none yet"

    cursor.execute("""
        SELECT port, COUNT(*) as seen
        FROM port_observations
        WHERE state = 'open'
        GROUP BY port
        ORDER BY seen DESC
        LIMIT 5
    """)
    top_ports = cursor.fetchall()

    conn.close()

    return {
        "port_observation_rows":    port_rows,
        "connection_snapshot_rows": conn_rows,
        "files_parsed":             files_parsed,
        "latest_scan":              latest_scan,
        "top_5_open_ports":         [(r["port"], r["seen"]) for r in top_ports]
    }


# ─── ENTRY POINT (run directly to initialise) ─────────────────────────────────

if __name__ == "__main__":
    print("=== Cerberus — Database Setup ===")
    init_db()
    print("\n--- Current stats ---")
    stats = get_stats()
    for key, val in stats.items():
        print(f"  {key}: {val}")