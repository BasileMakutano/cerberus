"""
Cerberus — main.py
Entry point. Runs the full pipeline in sequence.

Phases implemented:
    Phase 1 — Bash scripts (run via cron automatically)
    Phase 2 — Database init + live scan parser
    Phase 3 — Dataset cleaner (comment out after first run)
    Phase 4 — Per-port baseline engine (three-source combined)

Phases to be added:
    Phase 5 — Per-port Isolation Forest ML models
    Phase 6 — Correlation engine (baseline + ML)
    Phase 7 — Alerting + dashboard

Usage:
    ~/Documents/cerberus/venv/bin/python3 main.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.db       import init_db, get_stats
from engine.parser   import ingest_nmap_scans, ingest_conn_logs
from engine.baseline import build_all_baselines


def main() -> None:
    print("=" * 55)
    print("   Cerberus — Network Threat Detector")
    print("=" * 55)

    # ── Phase 2: Database + live scan parsing ─────────────────────────────
    print("\n[Phase 2] Initialising database...")
    init_db()

    print("\n[Phase 2] Parsing live scan data...")
    ingest_nmap_scans()
    print()
    ingest_conn_logs()

    # ── Phase 3: Dataset cleaning ──────────────────────────────────────────
    # Ran successfully — clean.csv and normal_only.csv exist.
    # Uncomment ONLY if you need to re-clean from scratch.
    #
    # from engine.cleaner import clean
    # print("\n[Phase 3] Cleaning Kaggle dataset...")
    # clean()

    # ── Phase 4: Baseline engine ───────────────────────────────────────────
    # Merges Kaggle + SQLite + synthetic → combined_normal.csv
    # Builds baselines.json (one entry per port)
    # Comment out after first successful run if you don't want
    # it to rebuild baselines on every execution.
    print("\n[Phase 4] Building per-port baselines...")
    build_all_baselines()

    # ── Phase 5: ML detection ──────────────────────────────────────────────
    # from engine.detector import train_all
    # print("\n[Phase 5] Training per-port Isolation Forest models...")
    # train_all()

    # ── Phase 6: Correlation ───────────────────────────────────────────────
    # from engine.correlator import correlate
    # print("\n[Phase 6] Running correlation engine...")
    # correlate()

    # ── Phase 7: Alerting ──────────────────────────────────────────────────
    # from engine.alerter import generate_alerts
    # print("\n[Phase 7] Generating alerts...")
    # generate_alerts()

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "─" * 55)
    print("Database summary")
    print("─" * 55)
    stats = get_stats()
    for key, val in stats.items():
        print(f"  {key}: {val}")

    print("\n[+] Done.\n")


if __name__ == "__main__":
    main()