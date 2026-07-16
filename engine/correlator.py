

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import sqlite3
from datetime import datetime, timezone

from engine.db       import BASE_DIR, DB_PATH, get_db
from engine.profiler import (
    load_profiles,
    check_observation,
    check_frequency,
    detect_port_scan,
)
  # Layer 1
from engine.detector import score_observation                                   # Layer 2


# =============================================================================
# PATHS
# =============================================================================

BASELINES_PATH    = os.path.join(BASE_DIR, "models", "baselines.json")
PORT_PROFILES_PATH = os.path.join(BASE_DIR, "models", "port_profiles.json")
CORR_LOG_PATH     = os.path.join(BASE_DIR, "logs", "correlation.log")

# =============================================================================
# CONSTANTS
# =============================================================================


SCORE_HIGH_MARGIN   = 0.05   # score ≤ threshold - 0.05 → HIGH confidence
SCORE_MEDIUM_MARGIN = 0.01   # score ≤ threshold - 0.01 → MEDIUM confidence


TRIGGER_SEVERITY = {
    "UNKNOWN_PORT": "HIGH",
    "WRONG_SERVICE": "HIGH",
    "SCAN_DETECTED": "HIGH",
    "UNKNOWN_IP": "MEDIUM",
    "UNKNOWN_REMOTE_IP": "MEDIUM",
    "FREQUENCY_SPIKE": "MEDIUM",
    "WRONG_PROTOCOL": "MEDIUM",
    "NEW_VERSION": "LOW",
}
TRIGGER_ALIASES = {
    "UNKNOWN_REMOTE_IP": "UNKNOWN_IP"
}


# =============================================================================
# HELPERS
# =============================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _connection_frequency(ip: str, port: int) -> int:
    conn = get_db()

    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM connection_snapshots
        WHERE remote_address = ?
        AND local_port = ?
        AND datetime(timestamp)
            >= datetime('now','-60 minutes')
    """,(ip, port))

    count = cur.fetchone()[0]

    conn.close()

    return count

def _load_baselines() -> dict:
    if not os.path.exists(BASELINES_PATH):
        print(f"[!] baselines.json not found at {BASELINES_PATH}. Run Phase 4b first.")
        sys.exit(1)
    with open(BASELINES_PATH) as f:
        raw = json.load(f)
    # baselines.json is keyed by string port numbers — normalise to int keys
    return {int(k): v for k, v in raw.items()}


def _log(msg: str) -> None:
    """Append a timestamped line to logs/correlation.log."""
    os.makedirs(os.path.dirname(CORR_LOG_PATH), exist_ok=True)
    line = f"[{_now_iso()}] {msg}\n"
    with open(CORR_LOG_PATH, "a") as f:
        f.write(line)
    print(line, end="")


def _load_recent_connections(since_minutes: int) -> list:
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, local_port, remote_address, state
        FROM connection_snapshots
        WHERE datetime(timestamp) >= datetime('now', ?)
        ORDER BY timestamp ASC
    """, (f"-{since_minutes} minutes",))
    rows = [
        dict(zip([c[0] for c in cursor.description], r))
        for r in cursor.fetchall()
    ]
    conn.close()
    return rows


# =============================================================================
# LAYER 2 CONFIDENCE + SEVERITY DERIVATION
# =============================================================================

def _layer2_confidence(score: float, threshold: float) -> str:
    
    if score is None:
        return "NO_MODEL"
    if score <= threshold - SCORE_HIGH_MARGIN:
        return "HIGH"
    if score <= threshold - SCORE_MEDIUM_MARGIN:
        return "MEDIUM"
    return "LOW"


def _derive_severity(trigger: str, l2_confidence: str) -> str:
    trigger = TRIGGER_ALIASES.get(trigger, trigger)

    l1_sev = TRIGGER_SEVERITY.get(trigger, "LOW")

    tier = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

    if l2_confidence == "NO_MODEL":
        return l1_sev

    l1_score = tier.get(l1_sev, 1)
    l2_score = tier.get(l2_confidence, 1)

    combined = (l1_score + l2_score) // 2

    if l1_score == 3 and l2_score == 3:
        combined = 3

    return {3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(combined, "LOW")


# =============================================================================
# OBSERVATION BUILDER
# =============================================================================
def _get_recent_source_port(ip: str, port: int) -> int:
    conn = get_db()

    cur = conn.cursor()

    cur.execute("""
        SELECT remote_port
        FROM connection_snapshots
        WHERE remote_address = ?
        AND local_port = ?
        AND remote_port > 0
        ORDER BY timestamp DESC
        LIMIT 1
    """, (ip, port))

    row = cur.fetchone()

    conn.close()

    if row:
        return int(row[0])

    return 49152

def _build_observation(row: dict, baselines: dict) -> dict:
    protocol_map = {
        "ICMP": 0, "TCP": 1, "UDP": 2,
        "ARP":  3, "TLS": 4,
    }
    port     = int(row.get("port", -1))
    protocol = str(row.get("protocol", "TCP")).upper()
    proto_enc = protocol_map.get(protocol, 5)

    # Use baseline mean length as proxy where live packet length is unavailable
    baseline  = baselines.get(port, {})
    length_info = baseline.get("length", {})
    mean_length = length_info.get("mean", 0.0) if length_info.get("available") else 0.0

    source_port = _get_recent_source_port(
    str(row.get("ip", "")),
    port
)

    return {
    "port": port,
    "ip": str(row.get("ip", "")),
    "service": str(row.get("service", "")),
    "protocol": str(row.get("protocol", "")),
    "version": str(row.get("version", "")),

    "length": mean_length,
    "source_port": source_port,
    "dest_port": port,
    "protocol_enc": proto_enc,
}



# =============================================================================
# CORE CORRELATION LOGIC — per-port (Layer 1 + Layer 2)
# =============================================================================

def correlate_observation(row: dict, baselines: dict, port_profiles: dict) -> dict | None:
    port = int(row.get("port", -1))
    ip   = str(row.get("ip", "unknown"))

    l1_result = check_observation(row, port_profiles)

    if not l1_result:
        return None

    freq_result = {"flagged": False, "triggers": []}

    if "current_hour_count" in row:
        row["current_hour_count"] = _connection_frequency(
    ip,
    port
)
    freq_result = check_frequency(
    port,
    row["current_hour_count"],
    port_profiles,
)

    if freq_result is None:
        freq_result = {
        "flagged": False,
        "triggers": [],
        "severity": "LOW", 
        "confidence": "LOW"
    }

    triggers = []

    if l1_result.get("flagged", False):
        triggers.extend(l1_result.get("triggers", []))

    if freq_result and freq_result.get("flagged", False):
        triggers.extend(freq_result.get("triggers", []))

    if not triggers:
        return None

    primary = triggers[0]

    if isinstance(primary, dict):
        trigger = primary.get("type", "UNKNOWN")
    else:
        trigger = str(primary)

    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    l1_severity = l1_result.get("severity", "LOW")
    freq_severity = freq_result.get("severity", "LOW")

    layer1_severity = max(
        [l1_severity, freq_severity],
        key=lambda x: severity_rank.get(x, 1)
    )

    l1_details = {
        "triggers": triggers,
        "severity": layer1_severity,
        "confidence": l1_result.get("confidence", "UNKNOWN")
    }

    observation = _build_observation(row, baselines)
    l2_result = score_observation(observation, port)

    l2_score = l2_result.get("score")
    l2_threshold = l2_result.get("threshold")
    l2_anomaly = l2_result.get("anomaly", False)
    model_status = l2_result.get("model_status", "no_model")

    l2_confidence = (
        _layer2_confidence(l2_score, l2_threshold)
        if l2_score is not None and l2_threshold is not None
        else "NO_MODEL"
    )

    confirmed = l2_anomaly if model_status == "ok" else False

    severity = _derive_severity(trigger, l2_confidence)

    event = {
        "timestamp": _now_iso(),
        "port": port,
        "ip": ip,
        "service": str(row.get("service", "unknown")),
        "layer1_trigger": trigger,
        "layer1_details": l1_details,
        "layer2_score": round(l2_score, 6) if l2_score is not None else None,
        "layer2_confidence": l2_confidence,
        "severity": severity,
        "confirmed": confirmed
    }

    status = "CONFIRMED" if confirmed else "LOW-CONFIDENCE"

    _log(
        f"{status} | port={port} ip={ip} "
        f"trigger={trigger} l2={l2_confidence} severity={severity}"
    )

    return event

# =============================================================================
# CROSS-PORT PATTERN — vertical scan detection
# =============================================================================

def _correlate_scan_events(since_minutes: int) -> list[dict]:
    conn_rows = _load_recent_connections(since_minutes)
    if not conn_rows:
        return []
    
    print("\nCONN ROWS:", len(conn_rows))

    for r in conn_rows[-10:]:
            print(r)
    scan_hits = detect_port_scan(
    conn_rows,
    monitored_ports={
        21,22,23,25,53,80,110,
        135,139,143,443,445,
        1433,1521,3306,3389,
        5432,5900,6379,8080,
        8443,8888,9200,27017,
        2181
    }
)
    events = []

    for hit in scan_hits:
        event = {
            "timestamp":         _now_iso(),
            "port":              None,
            "ip":                hit["ip"],
            "service":           "multiple",
            "layer1_trigger":    "SCAN_DETECTED",
            "layer1_details": {
                "triggers": [{
                    "type":   "SCAN_DETECTED",
                    "detail": hit["detail"],
                    "ports":  hit["ports"],
                }],
                "severity":   "HIGH",
                "confidence": "HIGH",
            },
            "layer2_score":      None,
            "layer2_confidence": "NO_MODEL",
            "severity":          "HIGH",
            "confirmed":         True,
        }
        events.append(event)
        _log(
            f"CONFIRMED | SCAN_DETECTED | ip={hit['ip']} "
            f"ports={hit['ports']} severity=HIGH"
        )

    return events


# =============================================================================
# BATCH MODE — scan all recent observations from SQLite
# =============================================================================

def correlate_recent(since_minutes: int = 10) -> list[dict]:
    baselines     = _load_baselines()
    port_profiles = load_profiles()

    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        timestamp,
        ip,
        port,
        protocol,
        state,
        service,
        version,
        COUNT(*) OVER (
            PARTITION BY port, ip
        ) AS current_hour_count
    FROM port_observations
    WHERE datetime(timestamp) >= datetime('now', ?)
    ORDER BY timestamp ASC
""", (f"-{since_minutes} minutes",))


    rows = [
        dict(zip([c[0] for c in cursor.description], r))
        for r in cursor.fetchall()
    ]
    conn.close()

    events = []

    if not rows:
        _log(f"No port observations in the last {since_minutes} minutes.")
    else:
        _log(f"Correlating {len(rows)} observations from the last {since_minutes} min...")
        for row in rows:
            event = correlate_observation(row, baselines, port_profiles)
            if event is not None:
                events.append(event)

    # ── Cross-port pattern: vertical port-scan detection ───────────────────
    # Runs independently of the per-port loop above — a scan signature is
    # about one IP touching many ports, not any single observation.
    scan_events = _correlate_scan_events(since_minutes)
    events.extend(scan_events)

    confirmed = [e for e in events if e["confirmed"]]
    low_conf  = [e for e in events if not e["confirmed"]]

    _log(
        f"Done. {len(rows)} port observations + {len(scan_events)} scan-pattern "
        f"check(s) → {len(confirmed)} confirmed threats, "
        f"{len(low_conf)} low-confidence events."
    )

    return events


# =============================================================================
# SINGLE OBSERVATION MODE — called by alerter or tests
# =============================================================================

def correlate_one(row: dict) -> dict | None:
    baselines     = _load_baselines()
    port_profiles = load_profiles()
    return correlate_observation(row, baselines, port_profiles)


# =============================================================================
# ENTRY POINT — standalone test run
# =============================================================================

if __name__ == "__main__":
    print("=== Cerberus — Correlator (Phase 6) ===\n")

    events = correlate_recent(since_minutes=60)

    confirmed = [e for e in events if e["confirmed"]]
    low_conf  = [e for e in events if not e["confirmed"]]

    print(f"\n--- Results ---")
    print(f"  Total flagged    : {len(events)}")
    print(f"  Confirmed threats: {len(confirmed)}")
    print(f"  Low-confidence   : {len(low_conf)}")

    if confirmed:
        print("\n--- Confirmed Threats ---")
        for e in confirmed:
            print(json.dumps(e, indent=2))

    if low_conf:
        print("\n--- Low-Confidence Events ---")
        for e in low_conf:
            print(
                f"  [{e['severity']}] port={e['port']} ip={e['ip']} "
                f"trigger={e['layer1_trigger']} l2={e['layer2_confidence']}"
            )