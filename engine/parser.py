import xml.etree.ElementTree as ET
import pandas as pd
import sqlite3
import os
import glob
from datetime import datetime


BASE_DIR  = os.path.expanduser("~/Documents/cerberus")
DB_PATH   = os.path.join(BASE_DIR, "data", "recon.db")
SCANS_DIR = os.path.join(BASE_DIR, "data", "scans")
CONNS_DIR = os.path.join(BASE_DIR, "data", "connections")


# ─── DATABASE ─────────────────────────────────────────────────────────────────

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    """Create tables if they don't exist yet."""
    conn = get_db()
    cursor = conn.cursor()

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS parsed_files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT UNIQUE NOT NULL,
            parsed_at   TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialised.")


def already_parsed(filename):
    """Check if a file has already been ingested — prevents double counting."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM parsed_files WHERE filename = ?", (filename,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def mark_parsed(filename):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO parsed_files (filename, parsed_at) VALUES (?, ?)",
        (filename, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


# ─── NMAP XML PARSER ──────────────────────────────────────────────────────────

def extract_timestamp_from_filename(filename):
    """Pull timestamp out of scan_20260429_080000.xml → ISO datetime string."""
    base = os.path.basename(filename)
    try:
        parts = base.replace(".xml", "").split("_")
        dt = datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S")
        return dt.isoformat()
    except Exception:
        return datetime.now().isoformat()


def parse_nmap_xml(filepath):
    """Parse one nmap XML file → list of row dicts."""
    timestamp = extract_timestamp_from_filename(filepath)
    rows = []

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] Failed to parse {filepath}: {e}")
        return []

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "unknown")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            port_id  = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")

            state_el   = port_el.find("state")
            service_el = port_el.find("service")

            state   = state_el.get("state", "unknown")  if state_el   is not None else "unknown"
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            version = service_el.get("product", "")     if service_el is not None else ""
            if version and service_el is not None and service_el.get("version"):
                version += f" {service_el.get('version')}"

            rows.append({
                "timestamp": timestamp,
                "ip":        ip,
                "port":      port_id,
                "protocol":  protocol,
                "state":     state,
                "service":   service,
                "version":   version,
                "parsed_at": datetime.now().isoformat()
            })

    return rows


def ingest_nmap_scans():
    """Find all unparsed XML scan files and load them into SQLite."""
    files     = sorted(glob.glob(os.path.join(SCANS_DIR, "scan_*.xml")))
    new_files = [f for f in files if not already_parsed(os.path.basename(f))]

    if not new_files:
        print("[*] No new scan files to parse.")
        return 0

    conn  = get_db()
    total = 0

    for filepath in new_files:
        rows = parse_nmap_xml(filepath)
        if rows:
            df = pd.DataFrame(rows)
            df.to_sql("port_observations", conn, if_exists="append", index=False)
            mark_parsed(os.path.basename(filepath))
            total += len(rows)
            print(f"[+] {os.path.basename(filepath)} → {len(rows)} rows inserted")
        else:
            print(f"[!] {os.path.basename(filepath)} → empty or failed, skipping")

    conn.close()
    print(f"[+] Nmap total: {total} rows")
    return total


# ─── SS CONNECTION LOG PARSER ─────────────────────────────────────────────────

def split_addr_port(addr_str):
    """Split '192.168.1.1:443' or '[::1]:80' into (addr, port)."""
    if addr_str.startswith("["):
        # IPv6: [::1]:port
        addr, port = addr_str.rsplit(":", 1)
    elif addr_str.count(":") == 1:
        addr, port = addr_str.rsplit(":", 1)
    else:
        return addr_str, 0
    try:
        return addr, int(port)
    except ValueError:
        return addr, 0


def parse_conn_log(filepath):
    """Parse one ss connection snapshot → list of row dicts."""
    timestamp = None
    rows      = []

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] Could not read {filepath}: {e}")
        return []

    for line in lines:
        line = line.strip()

        # Extract timestamp from the header line written by conn_monitor.sh
        if line.startswith("=== TIMESTAMP:"):
            ts_str = line.replace("=== TIMESTAMP:", "").replace("===", "").strip()
            try:
                dt        = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                timestamp = dt.isoformat()
            except Exception:
                timestamp = datetime.now().isoformat()
            continue

        # Skip section headers and empty lines
        if not line or line.startswith("---") or line.startswith("Netid"):
            continue

        # ss output: State Recv-Q Send-Q Local:Port Peer:Port [Process]
        parts = line.split()
        if len(parts) < 5:
            continue

        state       = parts[0]
        local_full  = parts[3]
        remote_full = parts[4]
        process     = parts[5] if len(parts) > 5 else ""

        local_addr,  local_port  = split_addr_port(local_full)
        remote_addr, remote_port = split_addr_port(remote_full)

        rows.append({
            "timestamp":      timestamp or datetime.now().isoformat(),
            "local_address":  local_addr,
            "local_port":     local_port,
            "remote_address": remote_addr,
            "remote_port":    remote_port,
            "state":          state,
            "process":        process,
            "parsed_at":      datetime.now().isoformat()
        })

    return rows


def ingest_conn_logs():
    """Find all unparsed connection logs and load them into SQLite."""
    files     = sorted(glob.glob(os.path.join(CONNS_DIR, "conn_*.log")))
    new_files = [f for f in files if not already_parsed(os.path.basename(f))]

    if not new_files:
        print("[*] No new connection logs to parse.")
        return 0

    conn  = get_db()
    total = 0

    for filepath in new_files:
        rows = parse_conn_log(filepath)
        if rows:
            df = pd.DataFrame(rows)
            df.to_sql("connection_snapshots", conn, if_exists="append", index=False)
            mark_parsed(os.path.basename(filepath))
            total += len(rows)
            print(f"[+] {os.path.basename(filepath)} → {len(rows)} rows inserted")
        else:
            print(f"[!] {os.path.basename(filepath)} → empty or failed, skipping")

    conn.close()
    print(f"[+] Connections total: {total} rows")
    return total


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Cerberus — Parser ===")
    init_db()
    ingest_nmap_scans()
    ingest_conn_logs()
