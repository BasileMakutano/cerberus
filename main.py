import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.db        import init_db, get_stats
from engine.parser    import ingest_nmap_scans, ingest_conn_logs
from engine.profiler  import build_all_profiles
from engine.baseline  import build_all_baselines
from engine.detector   import train_all
from engine.correlator import correlate_recent
from engine.alerter    import write_alerts, get_alert_summary


def _banner():
    print("=" * 55)
    print("   Cerberus — Network Threat Detector v1.0")
    print("=" * 55)


def run_alert_only() -> None:
    _banner()
    print("\n[Mode] Alert-only — parsing new files, correlating last 10 minutes\n")

    print("[Phase 2] Parsing new scan/connection files...")
    nmap_rows = ingest_nmap_scans()
    conn_rows = ingest_conn_logs()
    print(f"  nmap  : {nmap_rows} new rows")
    print(f"  conn  : {conn_rows} new rows\n")

    events = correlate_recent(since_minutes=10)
    new    = write_alerts(events, confirmed_only=False)

    summary = get_alert_summary()
    _print_alert_summary(summary, new)


def run_full(skip_train: bool = False) -> None:
    _banner()

    # ── Phase 2: Database init + parse new scan files ──────────────────────
    print("\n[Phase 2] Initialising database...")
    init_db()

    print("\n[Phase 2] Parsing live scan data...")
    nmap_rows = ingest_nmap_scans()
    conn_rows = ingest_conn_logs()
    print(f"  nmap  : {nmap_rows} new rows")
    print(f"  conn  : {conn_rows} new rows")

    # ── Phase 3: Dataset cleaning ──────────────────────────────────────────
    # Runs automatically only if clean.csv doesn't exist yet.
    # To force a re-clean: delete data/dataset/clean.csv and rerun.
    clean_path = os.path.join(os.path.dirname(__file__), "data", "dataset", "clean.csv")
    if not os.path.exists(clean_path):
        print("\n[Phase 3] clean.csv not found — running Kaggle dataset cleaner...")
        from engine.cleaner import clean
        clean()
    else:
        print("\n[Phase 3] clean.csv exists — skipping cleaner.")

    # ── Phase 4a: Behavioural profiler ────────────────────────────────────
    print("\n[Phase 4a] Building behavioural profiles...")
    build_all_profiles()

    # ── Phase 4b: Statistical baseline engine ─────────────────────────────
    print("\n[Phase 4b] Building statistical baselines...")
    build_all_baselines()

    # ── Phase 5: Isolation Forest training ────────────────────────────────
    if skip_train:
        print("\n[Phase 5] Skipping ML training (--no-train flag set).")
        models_dir = os.path.join(os.path.dirname(__file__), "models", "ports")
        pkl_count  = len([f for f in os.listdir(models_dir) if f.endswith(".pkl") and "port_" in f]) // 2 \
                     if os.path.exists(models_dir) else 0
        print(f"  Using {pkl_count} existing port models.")
    else:
        print("\n[Phase 5] Training per-port Isolation Forest models...")
        train_all()

    # ── Phase 6: Correlation engine ───────────────────────────────────────
    print("\n[Phase 6] Running correlation engine (last 60 min)...")
    events    = correlate_recent(since_minutes=60)
    confirmed = [e for e in events if e.get("confirmed")]
    low_conf  = [e for e in events if not e.get("confirmed")]
    print(f"  Flagged  : {len(events)} events")
    print(f"  Confirmed: {len(confirmed)}")
    print(f"  Low-conf : {len(low_conf)}")

    # ── Phase 7: Alerter ──────────────────────────────────────────────────
    print("\n[Phase 7] Writing alerts...")
    new_alerts = write_alerts(events, confirmed_only=False)

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "─" * 55)
    print("  Database summary")
    print("─" * 55)
    stats = get_stats()
    for key, val in stats.items():
        print(f"  {key:<30}: {val}")

    summary = get_alert_summary()
    _print_alert_summary(summary, new_alerts)

    print("\n[+] Pipeline complete.\n")
    print("    Open the dashboard at http://127.0.0.1:5000 to view alerts.")
    print(f"    Alerts file: {os.path.join(os.path.dirname(__file__), 'logs', 'alerts.json')}\n")


def _print_alert_summary(summary: dict, new_alerts: list) -> None:
    print("\n" + "─" * 55)
    print("  Alert store summary")
    print("─" * 55)
    print(f"  Total alerts     : {summary.get('total', 0)}")
    print(f"  Confirmed threats: {summary.get('confirmed', 0)}")
    print(f"  HIGH             : {summary.get('high', 0)}")
    print(f"  MEDIUM           : {summary.get('medium', 0)}")
    print(f"  LOW              : {summary.get('low', 0)}")
    print(f"  Unacknowledged   : {summary.get('unacknowledged', 0)}")
    if new_alerts:
        print(f"\n  [+] {len(new_alerts)} new alert(s) written this run.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cerberus — Network Threat Detection Pipeline"
    )
    parser.add_argument(
        "--no-train",
        action="store_true",
        help="Skip Phase 5 ML training (use existing models)"
    )
    parser.add_argument(
        "--alert-only",
        action="store_true",
        help="Only run Phase 2 (parse) + Phase 6+7 (correlate + alert). Fast mode for cron."
    )
    args = parser.parse_args()

    if args.alert_only:
        run_alert_only()
    else:
        run_full(skip_train=args.no_train)
