"""
Cerberus — engine/alerter.py
Phase 7: Alert Writer.

This module sits at the end of the detection pipeline. It receives
confirmed and low-confidence threat events from the correlator,
formats them into structured alert records, and appends them to
logs/alerts.json for consumption by the dashboard.

Pipeline position:
    correlator.py → alerter.py → logs/alerts.json → dashboard/index.html

Alert structure (one record per event):
    {
        "alert_id"       : str   UUID4 — unique per alert
        "timestamp"      : str   ISO 8601 UTC
        "severity"       : str   HIGH / MEDIUM / LOW
        "confirmed"      : bool  True = both layers flagged
        "port"           : int
        "ip"             : str
        "service"        : str
        "layer1_trigger" : str   e.g. UNKNOWN_IP, WRONG_SERVICE
        "layer1_details" : dict  triggers list + confidence
        "layer2_score"   : float Isolation Forest anomaly score
        "layer2_confidence": str HIGH / MEDIUM / LOW / NO_MODEL
        "recommendation" : str   human-readable action guidance
        "acknowledged"   : bool  False by default (for dashboard)
    }

Recommendations are generated from trigger type + severity to give
the operator actionable guidance without specialist knowledge. This
directly addresses the interpretability requirement from the proposal
(Section 1.3.2) and Rudin (2019)'s argument that security tools must
produce outputs that practitioners can understand and act on.

logs/alerts.json format:
    A JSON array. Each run appends new alerts to the array.
    The dashboard reads this file via fetch() and renders it.
    If the file doesn't exist it is created with an empty array.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import uuid
import hashlib
from datetime import datetime, timezone

from engine.db         import BASE_DIR
from engine.correlator import correlate_recent


# =============================================================================
# PATHS
# =============================================================================

ALERTS_PATH = os.path.join(BASE_DIR, "logs", "alerts.json")


# =============================================================================
# RECOMMENDATIONS
# =============================================================================

# Maps Layer 1 trigger + severity to actionable guidance for the operator.
# Written in plain language per the interpretability design principle.
RECOMMENDATIONS = {
    ("UNKNOWN_PORT", "HIGH"):    (
        "An unrecognised port is active on this host. Investigate immediately — "
        "this port is not part of the expected service profile and may indicate "
        "malware, a backdoor, or an unauthorised service installation."
    ),
    ("UNKNOWN_PORT", "MEDIUM"):  (
        "An unrecognised port was detected. Verify whether a new legitimate "
        "service has been deployed. If not expected, treat as suspicious."
    ),
    ("WRONG_SERVICE", "HIGH"):   (
        "A known port is running an unexpected service. This is a strong "
        "indicator of service spoofing or port hijacking. Inspect the process "
        "bound to this port immediately using: ss -tlnp | grep :<port>"
    ),
    ("WRONG_SERVICE", "MEDIUM"): (
        "Service on this port does not match the expected profile. Verify "
        "the service configuration and check for recent changes."
    ),
    ("UNKNOWN_IP", "HIGH"):      (
        "Connection from an unrecognised IP address confirmed as anomalous. "
        "Check firewall rules and review whether this IP should have access. "
        "Consider blocking if source is external and unexpected."
    ),
    ("UNKNOWN_IP", "MEDIUM"):    (
        "Connection from an IP not in the known address list. Verify whether "
        "this is a new legitimate host. Log the source for correlation."
    ),
    ("UNKNOWN_IP", "LOW"):       (
        "New IP observed on this port. Monitor for recurrence. May be a "
        "legitimate new device joining the network."
    ),
    ("FREQUENCY_SPIKE", "HIGH"): (
        "Connection frequency is far above baseline — consistent with active "
        "port scanning or brute-force activity. Review recent connection logs "
        "for the source IP and consider rate limiting."
    ),
    ("FREQUENCY_SPIKE", "MEDIUM"): (
        "Unusual spike in connection frequency detected. May indicate automated "
        "scanning. Monitor the source IP for continued activity."
    ),
    ("FREQUENCY_SPIKE", "LOW"):  (
        "Slightly elevated connection frequency. Within tolerable range but "
        "worth noting if it continues."
    ),
    ("WRONG_PROTOCOL", "HIGH"):  (
        "Unexpected protocol detected on this port. Legitimate services use "
        "fixed protocols — a mismatch may indicate protocol tunnelling or "
        "evasion techniques."
    ),
    ("WRONG_PROTOCOL", "MEDIUM"): (
        "Protocol does not match the expected profile for this port. "
        "Verify service configuration."
    ),
    ("NEW_VERSION", "LOW"):      (
        "A new service version was detected on this port. Verify this is "
        "an authorised upgrade. New versions can introduce vulnerabilities."
    ),
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


def _event_fingerprint(event: dict) -> str:
    key = {
        "observed_at": event.get("observed_at") or event.get("timestamp"),
        "port": event.get("port"),
        "ip": event.get("ip"),
        "trigger": event.get("layer1_trigger"),
        "service": event.get("service"),
    }
    raw = json.dumps(key, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# =============================================================================
# ALERT FORMATTING
# =============================================================================

def _format_alert(event: dict) -> dict:
    """
    Convert a correlator threat event into a structured alert record.
    Adds alert_id, recommendation, and acknowledged fields.
    """
    trigger  = event.get("layer1_trigger", "UNKNOWN")
    severity = event.get("severity", "LOW")

    return {
        "alert_id":          str(uuid.uuid4()),
        "fingerprint":       _event_fingerprint(event),
        "timestamp":         event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "observed_at":       event.get("observed_at"),
        "severity":          severity,
        "confirmed":         event.get("confirmed", False),
        "port":              event.get("port"),
        "ip":                event.get("ip"),
        "service":           event.get("service"),
        "layer1_trigger":    trigger,
        "layer1_details":    event.get("layer1_details", {}),
        "layer2_score":      event.get("layer2_score"),
        "layer2_confidence": event.get("layer2_confidence"),
        "recommendation":    _get_recommendation(trigger, severity),
        "acknowledged":      False,
    }


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
        print(f"  [!] alerts.json unreadable — starting fresh.")
        return []


def _save_alerts(alerts: list) -> None:
    """Write the full alerts list back to alerts.json."""
    os.makedirs(os.path.dirname(ALERTS_PATH), exist_ok=True)
    with open(ALERTS_PATH, "w") as f:
        json.dump(alerts, f, indent=2)


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

    Parameters:
        events         : list of threat event dicts from correlator
        confirmed_only : if True, only write confirmed=True events
                         if False, write all flagged events (default)

    Returns:
        List of newly written alert dicts.

    The dashboard shows all alerts by default. The operator can filter
    by confirmed=True to see only dual-layer confirmed threats.
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
        print("[*] No new alerts written; all flagged events were already recorded.")
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

    This is the function called by cron or main.py on each cycle.

    Parameters:
        since_minutes  : look-back window passed to correlator (default 10)
        confirmed_only : only alert on dual-layer confirmed events

    Returns:
        List of newly written alert dicts.
    """
    print(f"[*] Running alert cycle (last {since_minutes} min)...")
    events = correlate_recent(since_minutes=since_minutes)

    if not events:
        print("[*] No flagged events in this window.")
        return []

    return write_alerts(events, confirmed_only=confirmed_only)


def get_alert_summary() -> dict:
    """
    Return a summary of all alerts in alerts.json.
    Used by the dashboard on load to populate the stats panel.
    """
    alerts = _load_alerts()
    if not alerts:
        return {"total": 0, "confirmed": 0, "high": 0, "medium": 0, "low": 0}

    return {
        "total":     len(alerts),
        "confirmed": sum(1 for a in alerts if a.get("confirmed")),
        "high":      sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "medium":    sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "low":       sum(1 for a in alerts if a.get("severity") == "LOW"),
        "unacknowledged": sum(1 for a in alerts if not a.get("acknowledged")),
    }


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=== Cerberus — Alerter (Phase 7) ===\n")

    new = run_alert_cycle(since_minutes=60, confirmed_only=False)
    summary = get_alert_summary()

    print(f"\n--- Alert Store Summary ---")
    print(f"  Total alerts     : {summary['total']}")
    print(f"  Confirmed threats: {summary['confirmed']}")
    print(f"  HIGH             : {summary['high']}")
    print(f"  MEDIUM           : {summary['medium']}")
    print(f"  LOW              : {summary['low']}")
    print(f"  Unacknowledged   : {summary['unacknowledged']}")
    print(f"\n[+] Dashboard data → {ALERTS_PATH}")
