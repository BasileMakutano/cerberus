"""
Cerberus — main.py
Entry point. Runs the full pipeline in sequence.

Current phases implemented:
    Phase 1 — Bash scripts (run separately via cron)
    Phase 2 — Database init + live scan parser
    Phase 3 — Dataset cleaner (run once, then comment out)

Phases to be added:
    Phase 4 — Per-port baseline engine
    Phase 5 — Per-port Isolation Forest ML models
    Phase 6 — Correlation engine (baseline + ML)
    Phase 7 — Alerting + dashboard

Usage:
    ~/Documents/cerberus/venv/bin/python3 main.py
"""

import sys
import os

# Ensure project root is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.db      import init_db, get_stats
from engine.parser  import ingest_nmap_scans, ingest_conn_logs


def main() -> None:
    print("=" * 50)
    print("   Cerberus — Network Threat Detector")
    print("=" * 50)

    # ── Phase 2: Database + live scan parsing ─────────────────────────────
    print("\n[Phase 2] Initialising database...")
    init_db()

    print("\n[Phase 2] Parsing live scan data...")
    ingest_nmap_scans()
    print()
    ingest_conn_logs()

    # ── Phase 3: Dataset cleaning ──────────────────────────────────────────
    # Phase 3 has already run successfully — clean.csv and
    # normal_only.csv exist in data/dataset/.
    # Uncomment ONLY if you need to re-clean from scratch.
    #
    # from engine.cleaner import clean
    # print("\n[Phase 3] Cleaning Kaggle dataset...")
    # clean()

    # ── Phase 4: Baseline engine ───────────────────────────────────────────
    # from engine.baseline import build_all_baselines
    # print("\n[Phase 4] Building per-port baselines...")
    # build_all_baselines()

    # ── Phase 5: ML detection ──────────────────────────────────────────────
    # from engine.detector import train_all, run_detection
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
    print("\n" + "─" * 50)
    print("Database summary")
    print("─" * 50)
    stats = get_stats()
    for key, val in stats.items():
        print(f"  {key}: {val}")

    print("\n[+] Done.\n")


if __name__ == "__main__":
    main()