"""
Cerberus — engine/correlator.py
Phase 6: Correlation Engine.

This module is the intelligence layer of Cerberus. It connects the two
detection layers into a single, coherent decision pipeline and produces
confirmed threat events for the alerter.

Architecture:
    New observation (live SQLite row)
            ↓
    Layer 1 — profiler.py
        Checks: unknown port, unknown IP, wrong service, wrong protocol,
                frequency spike. Flags if any rule fires.
            ↓ flagged?
    Layer 2 — detector.py → score_observation()
        Confirms: is this statistically anomalous vs learned normal
                  behaviour for this specific port?
            ↓ confirmed?
    Threat event dict → alerter.py

Decision logic:
    Both layers flag  → confirmed=True,  alert sent
    Layer 1 only      → confirmed=False, logged as low-confidence
    Neither flags     → logged as normal, discarded

Why require both layers?
    Layer 1 (behavioural) has high recall but can produce false positives
    when a new legitimate service appears on the network. Layer 2 (ML)
    acts as a statistical gatekeeper — it only confirms events that are
    also anomalous in the feature space learned from normal traffic.
    Requiring both layers reduces false positives without sacrificing
    recall on genuine reconnaissance activity.

    This dual-confirmation design is directly motivated by Bhuyan,
    Bhattacharyya and Kalita (2014), who demonstrated that hybrid
    approaches combining statistical and rule-based methods outperform
    either approach in isolation on real-world network data.

Severity derivation:
    Severity is derived from the Layer 1 trigger type and the Layer 2
    anomaly score together:

        HIGH   — Layer 2 score ≤ threshold - 0.05  (deep into anomaly region)
                 OR trigger is UNKNOWN_PORT / NEW_PORT_EXPOSURE
        MEDIUM — Layer 2 score between threshold and threshold - 0.05
                 OR trigger is WRONG_SERVICE / WRONG_PROTOCOL
        LOW    — Layer 2 score near threshold (borderline)
                 OR trigger is FREQUENCY_SPIKE / UNKNOWN_IP

    This graduated scheme ensures that a port scanner hitting an
    unexpected service is treated more seriously than a simple frequency
    spike, which may have innocent explanations.

Layer 2 confidence:
    HIGH   — score ≤ threshold - 0.05
    MEDIUM — score between threshold - 0.05 and threshold
    LOW    — score within 0.01 of threshold (borderline case)

Output format (per confirmed or low-confidence event):
    {
        "timestamp":         str   ISO 8601
        "port":              int
        "ip":                str
        "service":           str
        "layer1_trigger":    str   e.g. "UNKNOWN_IP", "WRONG_SERVICE"
        "layer1_details":    dict  raw profiler output for this observation
        "layer2_score":      float anomaly score from Isolation Forest
        "layer2_confidence": str   HIGH / MEDIUM / LOW / NO_MODEL
        "severity":          str   HIGH / MEDIUM / LOW
        "confirmed":         bool  True = both layers agree
    }
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import sqlite3
from datetime import datetime, timezone

from engine.db       import BASE_DIR, DB_PATH, get_db
from engine.profiler import load_profiles, check_observation  # Layer 1
from engine.detector import score_observation                  # Layer 2


# =============================================================================
# PATHS
# =============================================================================

BASELINES_PATH    = os.path.join(BASE_DIR, "models", "baselines.json")
PORT_PROFILES_PATH = os.path.join(BASE_DIR, "models", "port_profiles.json")
CORR_LOG_PATH     = os.path.join(BASE_DIR, "logs", "correlation.log")

# =============================================================================
# CONSTANTS
# =============================================================================

# Layer 2 score margin below model.offset_ that determines confidence tier.
# Isolation Forest score_samples() → more negative = more anomalous.
# offset_ is the decision boundary set by contamination=0.05.
SCORE_HIGH_MARGIN   = 0.05   # score ≤ threshold - 0.05 → HIGH confidence
SCORE_MEDIUM_MARGIN = 0.01   # score ≤ threshold - 0.01 → MEDIUM confidence

# Layer 1 trigger severity weights.
# Triggers closer to confirmed reconnaissance are weighted higher.
TRIGGER_SEVERITY = {
    "NEW_PORT_EXPOSURE":  "HIGH",
    "UNKNOWN_PORT":       "HIGH",
    "WRONG_SERVICE":      "MEDIUM",
    "WRONG_PROTOCOL":     "MEDIUM",
    "UNKNOWN_IP":         "LOW",
    "FREQUENCY_SPIKE":    "LOW",
    "NEW_VERSION":        "LOW",
}


# =============================================================================
# HELPERS
# =============================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


# =============================================================================
# LAYER 2 CONFIDENCE + SEVERITY DERIVATION
# =============================================================================

def _layer2_confidence(score: float, threshold: float) -> str:
    """
    Translate a raw Isolation Forest score into a human-readable
    confidence tier.

    The threshold (model.offset_) is the decision boundary set by
    contamination=0.05. Points below it are anomalies.

        score ≤ threshold - SCORE_HIGH_MARGIN   → HIGH
        score ≤ threshold - SCORE_MEDIUM_MARGIN → MEDIUM
        score < threshold                        → LOW
        score ≥ threshold                        → (should not reach here,
                                                    Layer 2 would not flag)
    """
    if score is None:
        return "NO_MODEL"
    if score <= threshold - SCORE_HIGH_MARGIN:
        return "HIGH"
    if score <= threshold - SCORE_MEDIUM_MARGIN:
        return "MEDIUM"
    return "LOW"


def _derive_severity(trigger: str, l2_confidence: str) -> str:
    """
    Combine Layer 1 trigger type with Layer 2 confidence to produce
    a final severity rating for the threat event.

    Escalation rules:
        - If Layer 1 trigger is HIGH and Layer 2 is HIGH → HIGH
        - If either is HIGH → MEDIUM minimum
        - If both are LOW → LOW
        - NO_MODEL (no trained model for this port) → use Layer 1 only

    This ensures that a WRONG_SERVICE observation confirmed by a high
    ML anomaly score is treated more seriously than the same trigger
    confirmed at LOW confidence.
    """
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

def _build_observation(row: dict, baselines: dict) -> dict:
    """
    Convert a raw SQLite port_observations row into the feature dict
    expected by Layer 2 (score_observation).

    Protocol encoding:
        0 = ICMP
        1 = TCP
        2 = UDP
        3 = ARP
        4 = TLS
        5 = other

    Length:
        SQLite rows do not carry packet length — this field comes from
        tcpdump / combined_normal.csv training data. For live inference
        we use the baseline mean length for this port as a proxy.
        This is a known limitation: the ML score will be less sensitive
        to length-based anomalies until tcpdump parsing is integrated
        in a future phase.
    """
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

    return {
        "length":       mean_length,
        "source_port":  0,           # not available from nmap/ss rows
        "dest_port":    port,
        "protocol_enc": proto_enc,
    }


# =============================================================================
# CORE CORRELATION LOGIC
# =============================================================================

def correlate_observation(row: dict, baselines: dict, port_profiles: dict) -> dict | None:
    """
    Run one SQLite observation through both detection layers.

    Parameters:
        row           : dict from port_observations table
        baselines     : loaded baselines.json (int-keyed)
        port_profiles : loaded port_profiles.json via profiler.load_profiles()

    Returns:
        Threat event dict if Layer 1 fires, None if observation is clean.
        The 'confirmed' field distinguishes dual-layer vs single-layer flags.
    """
    port = int(row.get("port", -1))
    ip   = str(row.get("ip",   "unknown"))

    # ------------------------------------------------------------------
    # Layer 1 — Behavioural profiler
    # ------------------------------------------------------------------
    l1_result = check_observation(row, port_profiles)

    if not l1_result.get("flagged", False):
        return None

    trigger    = l1_result.get("trigger",  "UNKNOWN")
    l1_details = l1_result.get("details",  {})

    # ------------------------------------------------------------------
    # Layer 2 — Isolation Forest
    # ------------------------------------------------------------------
    observation  = _build_observation(row, baselines)
    l2_result    = score_observation(observation, port)

    l2_score     = l2_result.get("score")
    l2_threshold = l2_result.get("threshold")
    l2_anomaly   = l2_result.get("anomaly", False)
    model_status = l2_result.get("model_status", "no_model")

    l2_confidence = _layer2_confidence(l2_score, l2_threshold) \
                    if (l2_score is not None and l2_threshold is not None) \
                    else "NO_MODEL"

    confirmed = l2_anomaly if model_status == "ok" else False

    severity = _derive_severity(trigger, l2_confidence)

    event = {
        "timestamp":         _now_iso(),
        "port":              port,
        "ip":                ip,
        "service":           str(row.get("service", "unknown")),
        "layer1_trigger":    trigger,
        "layer1_details":    l1_details,
        "layer2_score":      round(l2_score, 6) if l2_score is not None else None,
        "layer2_confidence": l2_confidence,
        "severity":          severity,
        "confirmed":         confirmed,
    }

    status = "CONFIRMED" if confirmed else "LOW-CONFIDENCE"
    _log(
        f"{status} | port={port} ip={ip} "
        f"trigger={trigger} l2={l2_confidence} severity={severity}"
    )

    return event


# =============================================================================
# BATCH MODE — scan all recent observations from SQLite
# =============================================================================

def correlate_recent(since_minutes: int = 10) -> list[dict]:
    """
    Pull all port_observations from the last N minutes and run each
    through the correlation pipeline.

    Parameters:
        since_minutes : look-back window in minutes (default 10)

    Returns:
        List of threat event dicts (confirmed and low-confidence combined).
        Confirmed events have confirmed=True; callers should filter by this
        field when deciding what to send to the alerter.

    Called by:
        - main.py (scheduled loop)
        - alerter.py (when building the alert queue)
    """
    baselines     = _load_baselines()
    port_profiles = load_profiles()

    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, timestamp, ip, port, protocol, state, service, version
        FROM port_observations
        WHERE datetime(timestamp) >= datetime('now', ?)
        ORDER BY timestamp ASC
    """, (f"-{since_minutes} minutes",))

    rows = [
        dict(zip([c[0] for c in cursor.description], r))
        for r in cursor.fetchall()
    ]
    conn.close()

    if not rows:
        _log(f"No observations in the last {since_minutes} minutes.")
        return []

    _log(f"Correlating {len(rows)} observations from the last {since_minutes} min...")

    events = []
    for row in rows:
        event = correlate_observation(row, baselines, port_profiles)
        if event is not None:
            events.append(event)

    confirmed = [e for e in events if e["confirmed"]]
    low_conf  = [e for e in events if not e["confirmed"]]

    _log(
        f"Done. {len(rows)} observations → "
        f"{len(confirmed)} confirmed threats, "
        f"{len(low_conf)} low-confidence events."
    )

    return events


# =============================================================================
# SINGLE OBSERVATION MODE — called by alerter or tests
# =============================================================================

def correlate_one(row: dict) -> dict | None:
    """
    Correlate a single observation dict without hitting SQLite.
    Used by unit tests and direct alerter calls.

    Parameters:
        row : dict with keys matching port_observations schema:
              {ip, port, protocol, state, service, version, timestamp}

    Returns:
        Threat event dict or None if observation is clean.
    """
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