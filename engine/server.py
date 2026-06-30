"""
Cerberus — engine/server.py
Local control server. Serves the dashboard and exposes the detection
pipeline as HTTP endpoints so the operator never needs to type a
terminal command.

Architecture:
    Browser (dashboard) → fetch() → Flask routes → Python pipeline functions
                                                  → subprocess (nmap only)

Why subprocess only for nmap:
    nmap requires root for SYN scans. A sudoers rule grants the
    `blessing` user passwordless execution of ONLY nmap_scan.sh
    (see /etc/sudoers.d/cerberus). All other phases run in-process
    as plain Python function calls — no subprocess, no shell,
    direct access to exceptions and return values.

Endpoints:
    GET  /                       → dashboard index.html
    GET  /<path>                 → static dashboard assets (style.css, app.js)
    GET  /api/status             → engine + DB health check
    POST /api/run/scan           → triggers nmap_scan.sh via sudo subprocess
    POST /api/run/parser         → ingest_nmap_scans() + ingest_conn_logs()
    POST /api/run/profiler       → build_all_profiles()
    POST /api/run/baseline       → build_all_baselines()
    POST /api/run/detector       → train_all() (Phase 5 — slow, rarely needed)
    POST /api/run/correlator     → correlate_recent()
    POST /api/run/alerter        → run_alert_cycle()
    POST /api/run/full-cycle     → scan → parse → correlate → alert, in sequence
    GET  /api/alerts             → raw contents of logs/alerts.json
    GET  /logs/alerts.json       → direct alias so the existing dashboard
                                    fetch('../logs/alerts.json') keeps working

Every POST endpoint returns:
    {
        "success": bool,
        "phase":   str,
        "output":  str    captured stdout/log lines
        "error":   str | null
        "duration_sec": float
    }

This lets the dashboard show a live console of what actually happened,
rather than a silent pass/fail.

Run:
    /home/blessing/Documents/cerberus/venv/bin/python3 engine/server.py

Then open:
    http://127.0.0.1:5000
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import io
import json
import time
import subprocess
import contextlib
import traceback
from datetime import datetime, timezone

from flask import Flask, jsonify, send_from_directory, request

from engine.db import BASE_DIR, get_db, get_stats


# =============================================================================
# PATHS
# =============================================================================

DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")
LOGS_DIR      = os.path.join(BASE_DIR, "logs")
ALERTS_PATH   = os.path.join(LOGS_DIR, "alerts.json")
SCAN_SCRIPT   = os.path.join(BASE_DIR, "scripts", "nmap_scan.sh")

app = Flask(__name__, static_folder=None)


# =============================================================================
# HELPERS
# =============================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _capture_run(label: str, fn, *args, **kwargs) -> dict:
    """
    Run a pipeline function, capturing stdout (the engine modules print
    their own progress) and any exception, and time the execution.

    This lets the dashboard show real engine output in a console panel
    instead of a generic spinner.
    """
    start = time.time()
    buf = io.StringIO()
    error = None
    result = None

    try:
        with contextlib.redirect_stdout(buf):
            result = fn(*args, **kwargs)
    except Exception:
        error = traceback.format_exc()

    duration = round(time.time() - start, 2)

    return {
        "success":       error is None,
        "phase":         label,
        "output":        buf.getvalue(),
        "error":         error,
        "duration_sec":  duration,
        "timestamp":     _now_iso(),
        "result_preview": _safe_preview(result),
    }


def _safe_preview(result) -> str:
    """Truncate large return values (e.g. full evaluation dicts) for the UI."""
    if result is None:
        return ""
    try:
        s = json.dumps(result, default=str)
    except Exception:
        s = str(result)
    return s[:500] + ("…" if len(s) > 500 else "")


def _run_scan_script() -> dict:
    """
    Run nmap_scan.sh via the passwordless sudoers rule.
    This is the ONLY phase that uses subprocess — nmap needs root for
    SYN scans, and the sudoers rule at /etc/sudoers.d/cerberus scopes
    passwordless execution to this exact script only.
    """
    start = time.time()
    try:
        proc = subprocess.run(
            ["sudo", "-n", "bash", SCAN_SCRIPT],
            capture_output=True,
            text=True,
            timeout=120,
        )
        duration = round(time.time() - start, 2)
        success  = proc.returncode == 0

        return {
            "success":      success,
            "phase":        "scan",
            "output":       proc.stdout or "(no stdout — see logs/recon.log)",
            "error":        proc.stderr if not success else None,
            "duration_sec": duration,
            "timestamp":    _now_iso(),
            "result_preview": "",
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False, "phase": "scan",
            "output": "", "error": "Scan timed out after 120s.",
            "duration_sec": 120.0, "timestamp": _now_iso(),
            "result_preview": "",
        }
    except FileNotFoundError:
        return {
            "success": False, "phase": "scan",
            "output": "", "error": "sudo or nmap_scan.sh not found on PATH.",
            "duration_sec": 0.0, "timestamp": _now_iso(),
            "result_preview": "",
        }


# =============================================================================
# STATIC SERVING — dashboard
# =============================================================================

@app.route("/")
def serve_dashboard():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    """Serves style.css, app.js, and any other dashboard asset."""
    return send_from_directory(DASHBOARD_DIR, filename)


@app.route("/logs/alerts.json")
def serve_alerts_alias():
    """
    Alias so the dashboard's existing fetch('../logs/alerts.json') call
    keeps working unmodified when served through this Flask app instead
    of opened as a raw file:// path.
    """
    if not os.path.exists(ALERTS_PATH):
        return jsonify([])
    return send_from_directory(LOGS_DIR, "alerts.json")


# =============================================================================
# API — STATUS
# =============================================================================

@app.route("/api/status")
def api_status():
    try:
        stats = get_stats()
        db_ok = True
    except Exception as exc:
        stats = {}
        db_ok = False

    return jsonify({
        "engine_running": True,
        "db_connected":   db_ok,
        "db_stats":       stats,
        "timestamp":      _now_iso(),
    })


@app.route("/api/alerts")
def api_alerts():
    if not os.path.exists(ALERTS_PATH):
        return jsonify([])
    with open(ALERTS_PATH) as f:
        return jsonify(json.load(f))


# =============================================================================
# API — INDIVIDUAL PHASE TRIGGERS
# =============================================================================

@app.route("/api/run/scan", methods=["POST"])
def api_run_scan():
    return jsonify(_run_scan_script())


@app.route("/api/run/parser", methods=["POST"])
def api_run_parser():
    from engine.parser import ingest_nmap_scans, ingest_conn_logs

    def _run():
        n1 = ingest_nmap_scans()
        n2 = ingest_conn_logs()
        return {"nmap_rows": n1, "conn_rows": n2}

    return jsonify(_capture_run("parser", _run))


@app.route("/api/run/profiler", methods=["POST"])
def api_run_profiler():
    from engine.profiler import build_all_profiles
    return jsonify(_capture_run("profiler", build_all_profiles))


@app.route("/api/run/baseline", methods=["POST"])
def api_run_baseline():
    from engine.baseline import build_all_baselines
    return jsonify(_capture_run("baseline", build_all_baselines))


@app.route("/api/run/detector", methods=["POST"])
def api_run_detector():
    """
    Phase 5 — retrains all 26 Isolation Forest models.
    This is slow (rebuilds combined_normal.csv dependent models) and
    rarely needs to run outside of initial setup or after baseline
    data changes substantially. Exposed for completeness but the
    dashboard should warn the operator before triggering it.
    """
    from engine.detector import train_all
    return jsonify(_capture_run("detector", train_all))


@app.route("/api/run/correlator", methods=["POST"])
def api_run_correlator():
    from engine.correlator import correlate_recent
    since = request.json.get("since_minutes", 60) if request.is_json else 60
    return jsonify(_capture_run("correlator", correlate_recent, since_minutes=since))


@app.route("/api/run/alerter", methods=["POST"])
def api_run_alerter():
    from engine.alerter import run_alert_cycle
    since = request.json.get("since_minutes", 60) if request.is_json else 60
    return jsonify(_capture_run("alerter", run_alert_cycle, since_minutes=since))


# =============================================================================
# API — FULL CYCLE (the single button the operator actually uses)
# =============================================================================

@app.route("/api/run/full-cycle", methods=["POST"])
def api_run_full_cycle():
    """
    Runs the entire live pipeline in sequence:
        scan → parse → correlate + alert

    Returns a list of per-phase results so the dashboard console can
    show exactly what happened at each step, and stops early if a
    phase fails so the operator isn't left guessing which step broke.
    """
    steps = []

    # 1. Scan
    scan_result = _run_scan_script()
    steps.append(scan_result)
    if not scan_result["success"]:
        return jsonify({"steps": steps, "stopped_at": "scan"})

    # 2. Parse
    from engine.parser import ingest_nmap_scans, ingest_conn_logs

    def _parse():
        n1 = ingest_nmap_scans()
        n2 = ingest_conn_logs()
        return {"nmap_rows": n1, "conn_rows": n2}

    parse_result = _capture_run("parser", _parse)
    steps.append(parse_result)
    if not parse_result["success"]:
        return jsonify({"steps": steps, "stopped_at": "parser"})

    # 3. Alert cycle (correlator runs internally inside run_alert_cycle)
    from engine.alerter import run_alert_cycle
    alert_result = _capture_run("alerter", run_alert_cycle, since_minutes=15)
    steps.append(alert_result)

    return jsonify({
        "steps": steps,
        "stopped_at": None,
        "completed": True,
        "timestamp": _now_iso(),
    })


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=== Cerberus Control Server ===")
    print(f"[*] Dashboard root : {DASHBOARD_DIR}")
    print(f"[*] Database       : {os.path.join(BASE_DIR, 'data', 'recon.db')}")
    print(f"[*] Scan script    : {SCAN_SCRIPT}")
    print(f"[*] Listening on   : http://127.0.0.1:5000")
    print()
    app.run(host="127.0.0.1", port=5000, debug=False)