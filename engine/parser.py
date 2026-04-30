import xml.etree.ElementTree as ET
import pandas as pd
import os
import glob
from datetime import datetime

from engine.db import get_db, already_parsed, mark_parsed, BASE_DIR


SCANS_DIR = os.path.join(BASE_DIR, "data", "scans")
CONNS_DIR = os.path.join(BASE_DIR, "data", "connections")


# ─── UTILITIES ────────────────────────────────────────────────────────────────

def extract_timestamp_from_filename(filename):
    """
    Pull the datetime out of a filename.
    scan_20260429_080000.xml  →  '2026-04-29T08:00:00'
    conn_20260429_080000.log  →  '2026-04-29T08:00:00'
    Falls back to now() if parsing fails.
    """
    base = os.path.basename(filename)
    try:
        parts = base.replace(".xml", "").replace(".log", "").split("_")
        dt    = datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S")
        return dt.isoformat()
    except Exception:
        return datetime.now().isoformat()


def split_addr_port(addr_str):
    """
    Split an address:port string into (address, port).
    Handles IPv4 '192.168.1.1:443' and IPv6 '[::1]:80'.
    Returns port as int, or 0 if unparseable.
    """
    if addr_str.startswith("["):
        # IPv6 format: [::1]:port
        addr, port = addr_str.rsplit(":", 1)
    elif addr_str.count(":") == 1:
        addr, port = addr_str.rsplit(":", 1)
    else:
        return addr_str, 0
    try:
        return addr, int(port)
    except ValueError:
        return addr, 0


# ─── NMAP XML PARSER ──────────────────────────────────────────────────────────

def parse_nmap_xml(filepath):
    """
    Parse one nmap XML output file.
    Returns a list of dicts, one per open port found.
    Returns [] if the file is empty, malformed, or has no open ports.
    """
    timestamp = extract_timestamp_from_filename(filepath)
    rows      = []

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] XML parse error in {os.path.basename(filepath)}: {e}")
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

            # Build version string: product + version number if available
            version = ""
            if service_el is not None:
                product = service_el.get("product", "")
                ver     = service_el.get("version", "")
                version = f"{product} {ver}".strip()

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
    """
    Find every scan_*.xml in data/scans/ that has not been parsed yet.
    Parse each one and insert rows into port_observations.
    Marks each file as parsed so it is never processed twice.
    """
    files     = sorted(glob.glob(os.path.join(SCANS_DIR, "scan_*.xml")))
    new_files = [f for f in files if not already_parsed(os.path.basename(f))]

    if not new_files:
        print("[*] No new nmap scan files to parse.")
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
            print(f"[+] {os.path.basename(filepath)} → {len(rows)} rows")
        else:
            print(f"[!] {os.path.basename(filepath)} → no data, skipping")

    conn.close()
    print(f"[+] Nmap ingestion complete: {total} rows total")
    return total


# ─── SS CONNECTION LOG PARSER ─────────────────────────────────────────────────

def parse_conn_log(filepath):
    """
    Parse one ss connection snapshot written by conn_monitor.sh.
    Returns a list of dicts, one per connection line.
    Returns [] if the file cannot be read or contains no valid lines.
    """
    timestamp = None
    rows      = []

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] Could not read {os.path.basename(filepath)}: {e}")
        return []

    for line in lines:
        line = line.strip()

        # Header written by conn_monitor.sh: "=== TIMESTAMP: 20260429_080000 ==="
        if line.startswith("=== TIMESTAMP:"):
            ts_str = line.replace("=== TIMESTAMP:", "").replace("===", "").strip()
            try:
                dt        = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                timestamp = dt.isoformat()
            except Exception:
                timestamp = datetime.now().isoformat()
            continue

        # Skip section labels and empty lines
        if not line or line.startswith("---") or line.startswith("Netid"):
            continue

        # ss line format:
        # State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  [Process]
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
    """
    Find every conn_*.log in data/connections/ that has not been parsed yet.
    Parse each one and insert rows into connection_snapshots.
    Marks each file as parsed so it is never processed twice.
    """
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
            print(f"[+] {os.path.basename(filepath)} → {len(rows)} rows")
        else:
            print(f"[!] {os.path.basename(filepath)} → no data, skipping")

    conn.close()
    print(f"[+] Connection ingestion complete: {total} rows total")
    return total


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Cerberus — Parser ===")
    ingest_nmap_scans()
    ingest_conn_logs()