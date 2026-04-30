"""
Cerberus — Network Threat Detector
Entry point. Runs the full pipeline in sequence.

Usage:
    ~/Documents/cerberus/venv/bin/python3 main.py
"""

from engine.db     import init_db, get_stats
from engine.parser import ingest_nmap_scans, ingest_conn_logs


def main():
    print("=" * 45)
    print("   Cerberus — Network Threat Detector")
    print("=" * 45)

    # ── Phase 2: initialise DB and parse raw files ──
    print("\n[Phase 2] Initialising database...")
    init_db()

    print("\n[Phase 2] Parsing scan data...")
    ingest_nmap_scans()
    ingest_conn_logs()

    # ── Phases 3, 4, 5 will slot in here ────────────
    # from engine.baseline import build_all_baselines
    # from engine.detector import run_detection
    # from engine.alerter  import generate_alerts

    # ── Summary ──────────────────────────────────────
    print("\n--- Database summary ---")
    stats = get_stats()
    for key, val in stats.items():
        print(f"  {key}: {val}")

    print("\n[+] Done.\n")


if __name__ == "__main__":
    main()