"""
Cerberus — engine/server.py
Local control server. Serves the dashboard and exposes the full
detection pipeline as HTTP endpoints so the operator never needs
a terminal.

Endpoints:
    GET  /                       → dashboard/index.html
    GET  /<path>                 → dashboard static assets
    GET  /api/status             → engine + DB health
    GET  /api/alerts             → logs/alerts.json contents
    GET  /api/settings           → current settings (target IP, interval)
    POST /api/settings           → save settings (writes target IP to nmap_scan.sh)
    GET  /api/baselines          → models/baselines.json
    GET  /api/profiles           → models/port_profiles.json
    GET  /api/evaluation         → models/evaluation.json
    GET  /api/db/ports           → port_observations summary from SQLite
    GET  /api/db/stats           → SQLite table counts
    GET  /api/logs/recon         → last 100 lines of logs/recon.log
    GET  /api/logs/correlation   → last 100 lines of logs/correlation.log
    POST /api/run/scan           → sudo bash scripts/nmap_scan.sh
    POST /api/run/parser         → ingest_nmap_scans() + ingest_conn_logs()
    POST /api/run/profiler       → build_all_profiles()
    POST /api/run/baseline       → build_all_baselines()
    POST /api/run/detector       → train_all() (slow — rebuilds all 26 models)
    POST /api/run/correlator     → correlate_recent(since_minutes)
    POST /api/run/alerter        → run_alert_cycle(since_minutes)
    POST /api/run/full-cycle     → scan → parse → correlate → alert in sequence
    DELETE /api/alerts           → wipe logs/alerts.json (reset dashboard)

Run:
    venv/bin/python3 engine/server.py
    Then open: http://127.0.0.1:5000
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import io
import ipaddress
import json
import re
import time
import subprocess
import contextlib
import traceback
from datetime import datetime, timezone

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

from engine.config import (
    ALERTS_PATH,
    BASELINES_PATH,
    CORR_LOG,
    DASHBOARD_DIR,
    DB_PATH,
    EVAL_PATH,
    LOGS_DIR,
    MODELS_DIR,
    PROFILES_PATH,
    RECON_LOG,
    SCAN_SCRIPT,
    SCRIPTS_DIR,
    SETTINGS_PATH,
)
from engine.db import BASE_DIR, get_db, get_stats
from engine.alerter import acknowledge_alert

# =============================================================================
# PATHS
# =============================================================================

DASHBOARD_DIR = str(DASHBOARD_DIR)
LOGS_DIR = str(LOGS_DIR)
MODELS_DIR = str(MODELS_DIR)
SCRIPTS_DIR = str(SCRIPTS_DIR)
ALERTS_PATH = str(ALERTS_PATH)
RECON_LOG = str(RECON_LOG)
CORR_LOG = str(CORR_LOG)
BASELINES_PATH = str(BASELINES_PATH)
PROFILES_PATH = str(PROFILES_PATH)
EVAL_PATH = str(EVAL_PATH)
SCAN_SCRIPT = str(SCAN_SCRIPT)
SETTINGS_PATH = str(SETTINGS_PATH)
DB_PATH = str(DB_PATH)

app = Flask(__name__, static_folder=None)
CORS(app, resources={
    r"/api/*": {"origins": ["http://127.0.0.1:5000", "http://localhost:5000"]}
})


# =============================================================================
# SETTINGS — persist target IP and scan interval
# =============================================================================

DEFAULT_SETTINGS = {
    "target_ip":       "192.168.100.100",
    "scan_interval":   5,
    "confirmed_only":  False,
    "lookback_minutes": 60,
}


def load_settings() -> dict:
    if not os.path.exists(SETTINGS_PATH):
        return DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_PATH) as f:
            saved = json.load(f)
        s = DEFAULT_SETTINGS.copy()
        s.update(saved)
        return s
    except Exception:
        return DEFAULT_SETTINGS.copy()


def save_settings(new: dict) -> dict:
    current = load_settings()
    current.update(new)
    with open(SETTINGS_PATH, "w") as f:
        json.dump(current, f, indent=2)
    return current


def validate_settings(data: dict) -> tuple[dict, dict]:
    cleaned = {}
    errors = {}

    if "target_ip" in data:
        target = str(data["target_ip"]).strip()
        try:
            cleaned["target_ip"] = str(ipaddress.ip_address(target))
        except ValueError:
            errors["target_ip"] = "Target IP must be a valid IPv4 or IPv6 address."

    if "scan_interval" in data:
        try:
            interval = int(data["scan_interval"])
            if not 1 <= interval <= 60:
                raise ValueError
            cleaned["scan_interval"] = interval
        except (TypeError, ValueError):
            errors["scan_interval"] = "Scan interval must be between 1 and 60 minutes."

    if "lookback_minutes" in data:
        try:
            lookback = int(data["lookback_minutes"])
            if not 5 <= lookback <= 1440:
                raise ValueError
            cleaned["lookback_minutes"] = lookback
        except (TypeError, ValueError):
            errors["lookback_minutes"] = "Look-back window must be between 5 and 1440 minutes."

    if "confirmed_only" in data:
        cleaned["confirmed_only"] = bool(data["confirmed_only"])

    allowed = set(DEFAULT_SETTINGS)
    for key in data:
        if key not in allowed:
            errors[key] = "Unknown setting."

    return cleaned, errors


def write_target_ip_to_script(ip: str) -> bool:
    """
    Permanently update TARGET= in scripts/nmap_scan.sh.
    Replaces the line regardless of current value.
    """
    if not os.path.exists(SCAN_SCRIPT):
        return False
    try:
        with open(SCAN_SCRIPT) as f:
            content = f.read()
        updated = re.sub(
            r'^TARGET=.*$', f'TARGET="{ip}"',
            content, flags=re.MULTILINE
        )
        with open(SCAN_SCRIPT, "w") as f:
            f.write(updated)
        return True
    except Exception:
        return False


# =============================================================================
# HELPERS
# =============================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _capture_run(label: str, fn, *args, **kwargs) -> dict:
    start  = time.time()
    buf    = io.StringIO()
    error  = None
    result = None
    try:
        with contextlib.redirect_stdout(buf):
            result = fn(*args, **kwargs)
    except Exception:
        error = traceback.format_exc()

    duration = round(time.time() - start, 2)
    return {
        "success":        error is None,
        "phase":          label,
        "output":         buf.getvalue(),
        "error":          error,
        "duration_sec":   duration,
        "timestamp":      _now_iso(),
        "result_preview": _safe_preview(result),
    }


def _safe_preview(result) -> str:
    if result is None:
        return ""
    try:
        s = json.dumps(result, default=str)
    except Exception:
        s = str(result)
    return s[:500] + ("…" if len(s) > 500 else "")


def _tail_log(path: str, lines: int = 100) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path) as f:
            all_lines = f.readlines()
        return "".join(all_lines[-lines:])
    except Exception:
        return ""


def _load_json_file(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None

def _run_scan() -> dict:
    """Run nmap_scan.sh via passwordless sudoers rule."""
    start = time.time()
    try:
        proc = subprocess.run(
            ["sudo", "-n", "bash", SCAN_SCRIPT],
            capture_output=True, text=True, timeout=120,
        )
        duration = round(time.time() - start, 2)
        success  = proc.returncode == 0
        return {
            "success":        success,
            "phase":          "scan",
            "output":         proc.stdout or "(see logs/recon.log for nmap output)",
            "error":          proc.stderr if not success else None,
            "duration_sec":   duration,
            "timestamp":      _now_iso(),
            "result_preview": "",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "phase": "scan", "output": "",
                "error": "Scan timed out after 120s.", "duration_sec": 120.0,
                "timestamp": _now_iso(), "result_preview": ""}
    except FileNotFoundError:
        return {"success": False, "phase": "scan", "output": "",
                "error": "sudo or nmap_scan.sh not found.", "duration_sec": 0.0,
                "timestamp": _now_iso(), "result_preview": ""}


# =============================================================================
# STATIC — dashboard
# =============================================================================

@app.route("/")
def serve_index():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(DASHBOARD_DIR, filename)


@app.route("/logs/alerts.json")
def serve_alerts_file():
    if not os.path.exists(ALERTS_PATH):
        return jsonify([])
    return send_from_directory(LOGS_DIR, "alerts.json")


# =============================================================================
# API — STATUS + SETTINGS
# =============================================================================

@app.route("/api/status")
def api_status():
    try:
        stats = get_stats()
        db_ok = True
    except Exception:
        stats = {}
        db_ok = False

    settings = load_settings()

    return jsonify({
        "engine_running": True,
        "db_connected":   db_ok,
        "db_stats":       stats,
        "settings":       settings,
        "timestamp":      _now_iso(),
        "models_trained": len([
            f for f in os.listdir(os.path.join(MODELS_DIR, "ports"))
            if f.startswith("port_") and f.endswith(".pkl")
        ]) if os.path.exists(os.path.join(MODELS_DIR, "ports")) else 0,
        "alerts_count": len(_load_json_file(ALERTS_PATH) or []),
    })


@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    return jsonify(load_settings())


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    cleaned, errors = validate_settings(data)
    if errors:
        return jsonify({"success": False, "error": "Invalid settings", "fields": errors}), 400

    updated = save_settings(cleaned)

    # If target IP was updated, write it permanently to nmap_scan.sh
    script_updated = False
    if "target_ip" in cleaned:
        script_updated = write_target_ip_to_script(cleaned["target_ip"])

    return jsonify({
        "success":        True,
        "settings":       updated,
        "script_updated": script_updated,
    })


# =============================================================================
# API — DATA READS
# =============================================================================

@app.route("/api/alerts")
def api_alerts():
    data = _load_json_file(ALERTS_PATH)
    return jsonify(data or [])


@app.route("/api/alerts/<alert_id>/ack", methods=["PATCH"])
def api_ack_alert(alert_id):
    data = request.get_json(silent=True) or {}
    acknowledged = data.get("acknowledged", True)
    result = acknowledge_alert(alert_id, acknowledged=bool(acknowledged))
    status = 200 if result.get("success") else 404
    return jsonify(result), status


@app.route("/api/baselines")
def api_baselines():
    data = _load_json_file(BASELINES_PATH)
    if not data:
        return jsonify({"error": "baselines.json not found. Run Phase 4b."}), 404
    return jsonify(data)


@app.route("/api/profiles")
def api_profiles():
    data = _load_json_file(PROFILES_PATH)
    if not data:
        return jsonify({"error": "port_profiles.json not found. Run Phase 4a."}), 404
    return jsonify(data)


@app.route("/api/evaluation")
def api_evaluation():
    data = _load_json_file(EVAL_PATH)
    if not data:
        return jsonify({"error": "evaluation.json not found. Run Phase 5."}), 404
    return jsonify(data)


@app.route("/api/db/stats")
def api_db_stats():
    try:
        return jsonify(get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/db/ports")
def api_db_ports():
    try:
        conn = get_db()
        c    = conn.cursor()
        c.execute("""
            SELECT port, service, protocol,
                   COUNT(*) as observations,
                   MAX(timestamp) as last_seen,
                   COUNT(DISTINCT ip) as unique_ips
            FROM port_observations
            GROUP BY port
            ORDER BY observations DESC
        """)
        rows = [
            dict(zip([col[0] for col in c.description], row))
            for row in c.fetchall()
        ]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs/recon")
def api_log_recon():
    return jsonify({"log": _tail_log(RECON_LOG, 100)})


@app.route("/api/logs/correlation")
def api_log_correlation():
    return jsonify({"log": _tail_log(CORR_LOG, 100)})


# =============================================================================
# API — PIPELINE TRIGGERS
# =============================================================================

@app.route("/api/run/scan", methods=["POST"])
def api_run_scan():
    return jsonify(_run_scan())


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
    from engine.detector import train_all
    return jsonify(_capture_run("detector", train_all))


@app.route("/api/run/correlator", methods=["POST"])
def api_run_correlator():
    from engine.correlator import correlate_recent
    data  = request.get_json() or {}
    since = data.get("since_minutes", load_settings().get("lookback_minutes", 60))
    return jsonify(_capture_run("correlator", correlate_recent, since_minutes=since))


@app.route("/api/run/alerter", methods=["POST"])
def api_run_alerter():
    from engine.alerter import run_alert_cycle
    data  = request.get_json() or {}
    since = data.get("since_minutes", load_settings().get("lookback_minutes", 60))
    confirmed_only = data.get("confirmed_only", load_settings().get("confirmed_only", False))
    return jsonify(_capture_run("alerter", run_alert_cycle,
                                since_minutes=since, confirmed_only=confirmed_only))


@app.route("/api/run/full-cycle", methods=["POST"])
def api_run_full_cycle():
    """
    Full pipeline: scan → parse → correlate+alert.
    Stops and reports at the first failure so the operator
    knows exactly which step broke.
    """
    steps    = []
    settings = load_settings()

    # 1. Scan
    scan_result = _run_scan()
    steps.append(scan_result)
    if not scan_result["success"]:
        return jsonify({"steps": steps, "stopped_at": "scan", "completed": False})

    # 2. Parse
    from engine.parser import ingest_nmap_scans, ingest_conn_logs
    def _parse():
        n1 = ingest_nmap_scans()
        n2 = ingest_conn_logs()
        return {"nmap_rows": n1, "conn_rows": n2}
    parse_result = _capture_run("parser", _parse)
    steps.append(parse_result)
    if not parse_result["success"]:
        return jsonify({"steps": steps, "stopped_at": "parser", "completed": False})

    # 3. Correlate + Alert
    from engine.alerter import run_alert_cycle
    alert_result = _capture_run(
        "alerter", run_alert_cycle,
        since_minutes=settings.get("lookback_minutes", 60),
        confirmed_only=settings.get("confirmed_only", False),
    )
    steps.append(alert_result)

    return jsonify({
        "steps":      steps,
        "stopped_at": None if alert_result["success"] else "alerter",
        "completed":  alert_result["success"],
        "timestamp":  _now_iso(),
    })


@app.route("/api/alerts", methods=["DELETE"])
def api_clear_alerts():
    try:
        with open(ALERTS_PATH, "w") as f:
            json.dump([], f)
        return jsonify({"success": True, "message": "Alert store cleared."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=" * 50)
    print("   Cerberus Control Server")
    print("=" * 50)
    print(f"  Dashboard : http://127.0.0.1:5000")
    print(f"  Root      : {BASE_DIR}")
    print(f"  DB        : {DB_PATH}")
    print(f"  Target IP : {load_settings()['target_ip']}")
    print("=" * 50)
    print()
    app.run(host="127.0.0.1", port=5000, debug=False)
