"""
Cerberus — engine/alerter.py
Phase 7: Alert Writer.

Pipeline position:
    correlator.py → alerter.py → logs/alerts.json → dashboard/

Alert structure:
    {
        "alert_id"          : str   UUID4
        "fingerprint"       : str   SHA256[:16] of port+ip+trigger+service
        "timestamp"         : str   ISO 8601 UTC (write time)
        "observed_at"       : str   timestamp of the original scan row
        "severity"          : str   HIGH / MEDIUM / LOW
        "confirmed"         : bool  True = both Layer 1 and Layer 2 agree
        "port"              : int
        "ip"                : str
        "service"           : str
        "layer1_trigger"    : str   e.g. UNKNOWN_IP, WRONG_SERVICE
        "layer1_details"    : dict  triggers list + confidence
        "layer2_score"      : float Isolation Forest anomaly score
        "layer2_confidence" : str   HIGH / MEDIUM / LOW / NO_MODEL
        "recommendation"    : str   plain-English operator guidance
        "acknowledged"      : bool  False by default
    }
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import uuid
import hashlib
import numpy as np
from datetime import datetime, timezone

from engine.db         import BASE_DIR
from engine.correlator import correlate_recent


# =============================================================================
# PATHS
# =============================================================================

ALERTS_PATH = os.path.join(BASE_DIR, "logs", "alerts.json")


# =============================================================================
# JSON SERIALIZATION — numpy-safe
# =============================================================================

def _clean_for_json(obj):
    """
    Recursively cast numpy scalar types to native Python so json.dump
    never raises TypeError regardless of what the profiler or detector
    returns. Called on every alert before writing.
    """
    if isinstance(obj, dict):
        return {k: _clean_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_for_json(i) for i in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.bool_):
        return bool(obj)
    return obj


class _SafeEncoder(json.JSONEncoder):
    """Fallback encoder — catches any numpy type that slips through _clean_for_json."""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)


# =============================================================================
# RECOMMENDATIONS
# =============================================================================

RECOMMENDATIONS = {
    ("UNKNOWN_PORT", "HIGH"):      "An unrecognised port is active on this host. Investigate immediately — this port is not part of the expected service profile and may indicate malware, a backdoor, or an unauthorised service installation.",
    ("UNKNOWN_PORT", "MEDIUM"):    "An unrecognised port was detected. Verify whether a new legitimate service has been deployed. If not expected, treat as suspicious.",
    ("WRONG_SERVICE", "HIGH"):     "A known port is running an unexpected service. This is a strong indicator of service spoofing or port hijacking. Inspect the process bound to this port immediately using: ss -tlnp | grep :<port>",
    ("WRONG_SERVICE", "MEDIUM"):   "Service on this port does not match the expected profile. Verify the service configuration and check for recent changes.",
    ("UNKNOWN_IP", "HIGH"):        "Connection from an unrecognised IP address confirmed as anomalous. Check firewall rules and review whether this IP should have access. Consider blocking if source is external and unexpected.",
    ("UNKNOWN_IP", "MEDIUM"):      "Connection from an IP not in the known address list. Verify whether this is a new legitimate host. Log the source for correlation.",
    ("UNKNOWN_IP", "LOW"):         "New IP observed on this port. Monitor for recurrence. May be a legitimate new device joining the network.",
    ("FREQUENCY_SPIKE", "HIGH"):   "Connection frequency is far above baseline — consistent with active port scanning or brute-force activity. Review recent connection logs for the source IP and consider rate limiting.",
    ("FREQUENCY_SPIKE", "MEDIUM"): "Unusual spike in connection frequency detected. May indicate automated scanning. Monitor the source IP for continued activity.",
    ("FREQUENCY_SPIKE", "LOW"):    "Slightly elevated connection frequency. Within tolerable range but worth noting if it continues.",
    ("WRONG_PROTOCOL", "HIGH"):    "Unexpected protocol detected on this port. Legitimate services use fixed protocols — a mismatch may indicate protocol tunnelling or evasion techniques.",
    ("WRONG_PROTOCOL", "MEDIUM"):  "Protocol does not match the expected profile for this port. Verify service configuration.",
    ("NEW_VERSION", "LOW"):        "A new service version was detected on this port. Verify this is an authorised upgrade. New versions can introduce vulnerabilities.",
}

DEFAULT_RECOMMENDATION = (
    "Anomalous activity detected. Review the port, IP, and trigger details "
    "above and compare against expected network behaviour."
)


def _get_recommendation(trigger: str, severity: str) -> str:
    return RECOMMENDATIONS.get(
        (trigger, severity),
        RECOMMENDATIONS.get((trigger, "LOW"), DEFAULT_RECOMMENDATION)
    )


# =============================================================================
# FINGERPRINT — deduplication key
# =============================================================================

def _event_fingerprint(event: dict) -> str:
    """
    Fingerprint on port + ip + trigger + service + UTC date bucket.

    The date bucket (YYYY-MM-DD) means the same anomaly is deduplicated
    within a single day but will re-alert the next day if the threat
    persists. This prevents the alert store going permanently quiet
    after the first detection of a recurring threat, while still
    suppressing the duplicate-per-scan-cycle noise within any given day.
    """
    ts  = event.get("timestamp") or event.get("observed_at") or ""
    day = str(ts)[:10]  # "YYYY-MM-DD" — UTC date bucket
    key = {
        "port":    event.get("port"),
        "ip":      event.get("ip"),
        "trigger": event.get("layer1_trigger"),
        "service": event.get("service"),
        "day":     day,
    }
    raw = json.dumps(key, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# =============================================================================
# ALERT FORMATTING
# =============================================================================

def _format_alert(event: dict) -> dict:
    """
    Convert a correlator threat event into a structured alert record.

    All values are explicitly cast to native Python types before storage.
    _clean_for_json() recursively handles nested dicts (layer1_details)
    which may contain numpy types from the profiler output.
    """
    trigger  = str(event.get("layer1_trigger", "UNKNOWN"))
    severity = str(event.get("severity", "LOW"))

    port  = int(event["port"])              if event.get("port")         is not None else None
    score = float(event["layer2_score"])    if event.get("layer2_score") is not None else None
    confirmed = bool(event.get("confirmed", False))

    alert = {
        "alert_id":          str(uuid.uuid4()),
        "fingerprint":       _event_fingerprint(event),
        "timestamp":         str(event.get("timestamp", datetime.now(timezone.utc).isoformat())),
        "observed_at":       str(event.get("observed_at", "")),
        "severity":          severity,
        "confirmed":         confirmed,
        "port":              port,
        "ip":                str(event.get("ip", "")),
        "service":           str(event.get("service", "")),
        "layer1_trigger":    trigger,
        "layer1_details":    _clean_for_json(event.get("layer1_details", {})),
        "layer2_score":      score,
        "layer2_confidence": str(event.get("layer2_confidence", "")),
        "recommendation":    _get_recommendation(trigger, severity),
        "acknowledged":      False,
    }

    return _clean_for_json(alert)


# =============================================================================
# ALERT STORAGE
# =============================================================================

def _load_alerts() -> list:
    """Load existing alerts from alerts.json, or return empty list."""
    os.makedirs(os.path.dirname(ALERTS_PATH), exist_ok=True)
    if not os.path.exists(ALERTS_PATH):
        return []
    try:
        with open(ALERTS_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        print("  [!] alerts.json unreadable — starting fresh.")
        return []


def _save_alerts(alerts: list) -> None:
    """
    Write the full alerts list back to alerts.json.
    Uses _SafeEncoder as a double-safety net after _clean_for_json
    has already converted all known numpy types.
    """
    os.makedirs(os.path.dirname(ALERTS_PATH), exist_ok=True)
    with open(ALERTS_PATH, "w") as f:
        json.dump(alerts, f, indent=2, cls=_SafeEncoder)


def acknowledge_alert(alert_id: str, acknowledged: bool = True) -> dict:
    alerts = _load_alerts()
    for alert in alerts:
        if alert.get("alert_id") == alert_id:
            alert["acknowledged"] = acknowledged
            _save_alerts(alerts)
            return {"success": True, "alert": alert}
    return {"success": False, "error": "Alert not found"}


# =============================================================================
# PUBLIC API
# =============================================================================

def write_alerts(events: list, confirmed_only: bool = False) -> list:
    """
    Format and persist a list of correlator events as alerts.

    Deduplication: events whose fingerprint (port+ip+trigger+service)
    already exists in alerts.json are silently skipped. This prevents
    repeated scans of the same anomalous condition from flooding the
    alert store.
    """
    if confirmed_only:
        events = [e for e in events if e.get("confirmed")]

    if not events:
        return []

    existing = _load_alerts()
    existing_fingerprints = {
        a.get("fingerprint")
        for a in existing
        if a.get("fingerprint")
    }

    new_alerts = []
    for event in events:
        alert = _format_alert(event)
        if alert["fingerprint"] in existing_fingerprints:
            continue
        existing_fingerprints.add(alert["fingerprint"])
        new_alerts.append(alert)

    if not new_alerts:
        print("[*] No new alerts written — all flagged events already recorded.")
        return []

    _save_alerts(existing + new_alerts)

    print(f"[+] {len(new_alerts)} alert(s) written → {ALERTS_PATH}")
    for a in new_alerts:
        status = "CONFIRMED" if a["confirmed"] else "LOW-CONF"
        print(
            f"    [{a['severity']}] [{status}] "
            f"port={a['port']} ip={a['ip']} "
            f"trigger={a['layer1_trigger']}"
        )

    return new_alerts


def run_alert_cycle(since_minutes: int = 10, confirmed_only: bool = False) -> list:
    """
    Full pipeline run: correlate recent observations → write alerts.
    Called by the Flask server on each dashboard-triggered cycle.
    """
    print(f"[*] Running alert cycle (last {since_minutes} min)...")
    events = correlate_recent(since_minutes=since_minutes)

    if not events:
        print("[*] No flagged events in this window.")
        return []

    return write_alerts(events, confirmed_only=confirmed_only)


def get_alert_summary() -> dict:
    alerts = _load_alerts()
    if not alerts:
        return {"total": 0, "confirmed": 0, "high": 0, "medium": 0, "low": 0, "unacknowledged": 0}
    return {
        "total":          len(alerts),
        "confirmed":      sum(1 for a in alerts if a.get("confirmed")),
        "high":           sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "medium":         sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "low":            sum(1 for a in alerts if a.get("severity") == "LOW"),
        "unacknowledged": sum(1 for a in alerts if not a.get("acknowledged")),
    }


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=== Cerberus — Alerter (Phase 7) ===\n")
    new     = run_alert_cycle(since_minutes=60, confirmed_only=False)
    summary = get_alert_summary()
    print(f"\n--- Alert Store Summary ---")
    print(f"  Total alerts     : {summary['total']}")
    print(f"  Confirmed threats: {summary['confirmed']}")
    print(f"  HIGH             : {summary['high']}")
    print(f"  MEDIUM           : {summary['medium']}")
    print(f"  LOW              : {summary['low']}")
    print(f"  Unacknowledged   : {summary['unacknowledged']}")
    print(f"\n[+] Dashboard data → {ALERTS_PATH}")