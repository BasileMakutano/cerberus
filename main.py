"""
Cerberus — main entry point
Runs the full pipeline: parse → baseline → detect → alert
"""

from engine.parser import init_db, ingest_nmap_scans, ingest_conn_logs

print("=" * 40)
print("  Cerberus — Network Threat Detector")
print("=" * 40)

# Phase 2 — Parse raw scan files into SQLite
print("\n[*] Phase 2 — Parsing scan data...")
init_db()
ingest_nmap_scans()
ingest_conn_logs()

# Phase 3, 4, 5 will be added here as we build them
print("\n[+] Done.")
