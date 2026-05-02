"""
Cerberus — engine/parser.py

Reads raw files produced by Phase 1 Bash scripts and inserts
structured rows into SQLite via engine/db.py.

Two parsers:
    ingest_nmap_scans()  — reads scan_*.xml  → port_observations
    ingest_conn_logs()   — reads conn_*.log  → connection_snapshots

Both are idempotent: files already in parsed_files are skipped.
"""

import xml.etree.ElementTree as ET
import pandas as pd
import os
import sys
import glob
from datetime import datetime

# Ensure project root is on the path regardless of how this file is invoked
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.db import (
    BASE_DIR,
    get_db,
    already_parsed,
    mark_parsed,
)


SCANS_DIR = os.path.join(BASE_DIR, "data", "scans")
CONNS_DIR = os.path.join(BASE_DIR, "data", "connections")


# =============================================================================
# UTILITIES
# =============================================================================

def _timestamp_from_filename(filename: str) -> str:
    """
    Extract a datetime from a Cerberus filename.

    scan_20260429_080000.xml  →  '2026-04-29T08:00:00'
    conn_20260429_080000.log  →  '2026-04-29T08:00:00'

    Falls back to now() if the filename doesn't match the expected pattern.
    This ensures every row always has a timestamp, even in edge cases.
    """
    base = os.path.basename(filename)
    try:
        # Strip extension, split on underscore
        # ['scan', '20260429', '080000']
        parts = base.rsplit(".", 1)[0].split("_")
        dt    = datetime.strptime(f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S")
        return dt.isoformat()
    except (IndexError, ValueError):
        return datetime.now().isoformat()


def _split_addr_port(addr_str: str) -> tuple:
    """
    Split a combined address:port string into (address, port).

    Handles:
        IPv4  →  '192.168.1.1:443'     →  ('192.168.1.1', 443)
        IPv6  →  '[::1]:80'            →  ('[::1]', 80)
        No port found                  →  (addr_str, 0)

    Returns port as int. Returns 0 if port cannot be parsed.
    """
    try:
        if addr_str.startswith("["):
            # IPv6: the port comes after the closing bracket
            addr, port = addr_str.rsplit(":", 1)
        elif addr_str.count(":") == 1:
            addr, port = addr_str.rsplit(":", 1)
        else:
            return addr_str, 0
        return addr, int(port)
    except ValueError:
        return addr_str, 0


# =============================================================================
# NMAP XML PARSER
# =============================================================================

def _parse_nmap_xml(filepath: str) -> list:
    """
    Parse one nmap XML file and return a list of row dicts.

    nmap's XML structure:
        <nmaprun>
            <host>
                <address addr="127.0.0.1"/>
                <ports>
                    <port portid="80" protocol="tcp">
                        <state state="open"/>
                        <service name="http" product="Apache" version="2.4"/>
                    </port>
                </ports>
            </host>
        </nmaprun>

    We walk this tree and extract one dict per open port per host.
    Returns [] if the file is malformed or contains no open ports.
    """
    timestamp = _timestamp_from_filename(filepath)
    rows      = []

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as exc:
        print(f"  [!] XML parse error in {os.path.basename(filepath)}: {exc}")
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

            # Combine product and version into one readable string
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
                "parsed_at": datetime.now().isoformat(),
            })

    return rows


def ingest_nmap_scans() -> int:
    """
    Find all scan_*.xml files not yet in parsed_files.
    Parse each and insert rows into port_observations.
    Mark each file as parsed when done.

    Returns total number of rows inserted.
    """
    files     = sorted(glob.glob(os.path.join(SCANS_DIR, "scan_*.xml")))
    new_files = [f for f in files if not already_parsed(os.path.basename(f))]

    if not new_files:
        print("[*] No new nmap scan files to parse.")
        return 0

    conn  = get_db()
    total = 0

    for filepath in new_files:
        rows = _parse_nmap_xml(filepath)
        if rows:
            df = pd.DataFrame(rows)
            df.to_sql("port_observations", conn, if_exists="append", index=False)
            mark_parsed(os.path.basename(filepath))
            total += len(rows)
            print(f"  [+] {os.path.basename(filepath)} → {len(rows)} rows")
        else:
            print(f"  [!] {os.path.basename(filepath)} → empty or failed, skipped")

    conn.close()
    print(f"[+] Nmap ingestion complete: {total} rows inserted")
    return total


# =============================================================================
# SS CONNECTION LOG PARSER
# =============================================================================

def _parse_conn_log(filepath: str) -> list:
    """
    Parse one ss connection snapshot written by conn_monitor.sh.

    Expected file format:
        === TIMESTAMP: 20260429_080000 ===

        --- LISTENING PORTS ---
        Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
        tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*

        --- ACTIVE CONNECTIONS ---
        ...

    We extract the timestamp from the header line, then parse
    each ss output line into address, port, state, and process fields.
    Returns [] if the file cannot be read or contains no valid lines.
    """
    timestamp = None
    rows      = []

    try:
        with open(filepath, "r") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"  [!] Cannot read {os.path.basename(filepath)}: {exc}")
        return []

    for line in lines:
        line = line.strip()

        # Timestamp header written by conn_monitor.sh
        if line.startswith("=== TIMESTAMP:"):
            ts_str = line.replace("=== TIMESTAMP:", "").replace("===", "").strip()
            try:
                dt        = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                timestamp = dt.isoformat()
            except ValueError:
                timestamp = datetime.now().isoformat()
            continue

        # Skip section labels, column headers, and blank lines
        if not line or line.startswith("---") or line.startswith("Netid"):
            continue

        # ss output line:
        # State  Recv-Q  Send-Q  Local:Port  Peer:Port  [Process]
        parts = line.split()
        if len(parts) < 5:
            continue

        state       = parts[0]
        local_full  = parts[3]
        remote_full = parts[4]
        process     = parts[5] if len(parts) > 5 else ""

        local_addr,  local_port  = _split_addr_port(local_full)
        remote_addr, remote_port = _split_addr_port(remote_full)

        rows.append({
            "timestamp":      timestamp or datetime.now().isoformat(),
            "local_address":  local_addr,
            "local_port":     local_port,
            "remote_address": remote_addr,
            "remote_port":    remote_port,
            "state":          state,
            "process":        process,
            "parsed_at":      datetime.now().isoformat(),
        })

    return rows


def ingest_conn_logs() -> int:
    """
    Find all conn_*.log files not yet in parsed_files.
    Parse each and insert rows into connection_snapshots.
    Mark each file as parsed when done.

    Returns total number of rows inserted.
    """
    files     = sorted(glob.glob(os.path.join(CONNS_DIR, "conn_*.log")))
    new_files = [f for f in files if not already_parsed(os.path.basename(f))]

    if not new_files:
        print("[*] No new connection log files to parse.")
        return 0

    conn  = get_db()
    total = 0

    for filepath in new_files:
        rows = _parse_conn_log(filepath)
        if rows:
            df = pd.DataFrame(rows)
            df.to_sql("connection_snapshots", conn, if_exists="append", index=False)
            mark_parsed(os.path.basename(filepath))
            total += len(rows)
            print(f"  [+] {os.path.basename(filepath)} → {len(rows)} rows")
        else:
            print(f"  [!] {os.path.basename(filepath)} → no data, skipped")

    conn.close()
    print(f"[+] Connection ingestion complete: {total} rows inserted")
    return total


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=== Cerberus — Parser ===\n")
    ingest_nmap_scans()
    print()
    ingest_conn_logs()