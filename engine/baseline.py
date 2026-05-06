"""
Cerberus — engine/baseline.py
Phase 4: Per-port baseline engine.

Builds statistical behavioural profiles for each of the 25 critical
ports using a three-source combined dataset:

    Source 1: data/dataset/normal_only.csv  — Kaggle real traffic
    Source 2: data/recon.db port_observations — live nmap scan data
    Source 3: engine/synthetic.py — RFC-based synthetic normal traffic

Source priority and weighting:
    Real data (Kaggle + SQLite) is weighted 3x over synthetic data.
    This ensures the model learns primarily from real behaviour, with
    synthetic filling in the shape for ports with no real observations.

    Weighting is achieved by duplicating real rows 3 times before
    merging — a standard technique in imbalanced dataset handling.

Combined dataset is saved to:
    data/dataset/combined_normal.csv

This file is what Phase 5 (Isolation Forest) trains on.

The baseline itself (baselines.json) is Layer 1 of Cerberus's
two-layer detection system — a fast statistical check that runs
before the ML model to filter obvious anomalies efficiently.
"""

import pandas as pd
import numpy as np
import sqlite3
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.db      import BASE_DIR, DB_PATH
from engine.synthetic import generate_port, generate_all, PORT_PROFILES


NORMAL_PATH    = os.path.join(BASE_DIR, "data", "dataset", "normal_only.csv")
COMBINED_PATH  = os.path.join(BASE_DIR, "data", "dataset", "combined_normal.csv")
BASELINES_PATH = os.path.join(BASE_DIR, "models", "baselines.json")

CRITICAL_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888,
    9200, 27017, 2181
]

PROTOCOL_MAP = {
    0:  "ICMP",
    1:  "TCP",
    2:  "UDP",
    3:  "ARP",
    4:  "NBNS",
    5:  "BROWSER",
    99: "OTHER"
}

STD_MULTIPLIER   = 2.0
MIN_OBSERVATIONS = 10
REAL_DATA_WEIGHT = 3   # real rows duplicated this many times


# =============================================================================
# DATA LOADING
# =============================================================================

def _load_kaggle() -> pd.DataFrame:
    """
    Load normal_only.csv — Kaggle normal traffic rows.
    Tags each row with source='kaggle'.
    Returns empty DataFrame if file not found.
    """
    if not os.path.exists(NORMAL_PATH):
        print("  [!] normal_only.csv not found — Kaggle source skipped")
        return pd.DataFrame()

    df = pd.read_csv(NORMAL_PATH)
    df["source"] = "kaggle"
    print(f"  [+] Kaggle   : {len(df):,} rows")
    return df


def _load_sqlite() -> pd.DataFrame:
    """
    Load open port observations from recon.db.
    Maps nmap fields to match the shared column schema:
        port      → dest_port
        protocol  → protocol_enc (tcp=1, udp=2, other=99)
        length    → 0 (nmap does not record packet size)
    Tags each row with source='sqlite'.
    Returns empty DataFrame if DB not found or empty.
    """
    if not os.path.exists(DB_PATH):
        print("  [!] recon.db not found — SQLite source skipped")
        return pd.DataFrame()

    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql("""
            SELECT
                port     AS dest_port,
                protocol AS proto_str,
                0        AS length,
                0        AS source_port
            FROM port_observations
            WHERE state = 'open'
        """, conn)
    except Exception as exc:
        print(f"  [!] SQLite read error: {exc}")
        conn.close()
        return pd.DataFrame()
    conn.close()

    if df.empty:
        print("  [!] SQLite  : no open port observations yet")
        return pd.DataFrame()

    proto_map        = {"tcp": 1, "udp": 2}
    df["protocol_enc"] = df["proto_str"].str.lower().map(proto_map).fillna(99).astype(int)
    df["source"]     = "sqlite"
    df = df.drop(columns=["proto_str"])

    print(f"  [+] SQLite   : {len(df):,} rows")
    return df


def _load_synthetic(ports: list) -> pd.DataFrame:
    """
    Generate synthetic normal traffic for all 25 critical ports.
    Tags each row with source='synthetic'.
    """
    df = generate_all(ports=ports)
    if not df.empty:
        print(f"  [+] Synthetic: {len(df):,} rows")
    return df


# =============================================================================
# MERGING WITH WEIGHTING
# =============================================================================

def _merge_sources(
    kaggle_df:    pd.DataFrame,
    sqlite_df:    pd.DataFrame,
    synthetic_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Merge all three sources into one combined normal traffic dataset.

    Weighting strategy:
        Real rows (Kaggle + SQLite) are duplicated REAL_DATA_WEIGHT times.
        Synthetic rows are kept as-is (weight = 1).

        This ensures the Isolation Forest model learns primarily from
        real observed behaviour. Synthetic data fills the shape for
        ports with no real observations without distorting ports that
        do have real data.

    Example for port 22:
        SQLite:    192 rows × 3 = 576 weighted rows
        Synthetic: 200 rows × 1 = 200 rows
        Total:                    776 rows for training

    Example for port 3306 (MySQL not running on Ubuntu VM):
        Kaggle:    0 rows
        SQLite:    0 rows
        Synthetic: 200 rows × 1 = 200 rows for training

    The 'source' column is preserved so downstream analysis can
    report exactly how much real vs synthetic data each port used.
    """
    frames = []

    # Standardise columns across all sources
    required_cols = ["length", "source_port", "dest_port", "protocol_enc", "source"]

    for df, name in [(kaggle_df, "kaggle"), (sqlite_df, "sqlite")]:
        if df.empty:
            continue
        # Add missing columns with defaults
        if "source" not in df.columns:
            df = df.copy()
            df["source"] = name
        if "source_port" not in df.columns:
            df = df.copy()
            df["source_port"] = 0
        df = df[required_cols]
        # Duplicate real rows to apply weight
        frames.append(pd.concat([df] * REAL_DATA_WEIGHT, ignore_index=True))

    if not synthetic_df.empty:
        df = synthetic_df.copy()
        if "source_port" not in df.columns:
            df["source_port"] = 0
        frames.append(df[required_cols])

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    return combined


# =============================================================================
# BASELINE CALCULATION
# =============================================================================

def _calculate_baseline(port_data: pd.DataFrame, port: int) -> dict:
    """
    Calculate a statistical baseline for one port.

    Computes:
        - Packet length distribution (mean, std, bounds)
        - Protocol distribution (dominant + full breakdown)
        - Data source composition (how much real vs synthetic)
        - Confidence level based on observation count

    Length availability:
        If all length values are 0 (SQLite-only ports where nmap
        does not record packet size), length profiling is marked
        unavailable. The correlator skips the length check for
        those ports and relies solely on protocol checking.

    Confidence thresholds:
        HIGH   >= 100 observations
        MEDIUM >= 10 observations
        LOW    <  10 observations (baseline not used)

    Bounds calculation:
        lower = max(0, mean - STD_MULTIPLIER × std)
        upper = mean + STD_MULTIPLIER × std
        Any packet outside these bounds is flagged by Layer 1.
    """
    n = len(port_data)

    if n < MIN_OBSERVATIONS:
        return {
            "port":               port,
            "status":             "insufficient_data",
            "total_observations": n,
            "confidence":         "LOW",
        }

    # ── Source composition ────────────────────────────────────────────────
    source_counts = port_data["source"].value_counts().to_dict()

    # ── Packet length ─────────────────────────────────────────────────────
    has_length = port_data["length"].sum() > 0

    if has_length:
        mean = port_data["length"].mean()
        std  = port_data["length"].std()
        std  = std if std > 0 else 1.0
        length_profile = {
            "available": True,
            "mean":      round(mean, 4),
            "std":       round(std, 4),
            "min":       round(float(port_data["length"].min()), 4),
            "max":       round(float(port_data["length"].max()), 4),
            "lower":     round(max(0, mean - STD_MULTIPLIER * std), 4),
            "upper":     round(mean + STD_MULTIPLIER * std, 4),
        }
    else:
        length_profile = {"available": False}

    # ── Protocol distribution ─────────────────────────────────────────────
    proto_counts  = port_data["protocol_enc"].value_counts()
    dominant_enc  = int(proto_counts.idxmax())
    dominant_name = PROTOCOL_MAP.get(dominant_enc, "UNKNOWN")

    proto_dist = {
        PROTOCOL_MAP.get(int(k), str(k)): int(v)
        for k, v in proto_counts.items()
    }

    # ── Confidence ────────────────────────────────────────────────────────
    confidence = "HIGH" if n >= 100 else "MEDIUM" if n >= MIN_OBSERVATIONS else "LOW"

    return {
        "port":               port,
        "status":             "ok",
        "total_observations": n,
        "confidence":         confidence,
        "source_composition": source_counts,
        "length":             length_profile,
        "protocol": {
            "dominant":     dominant_name,
            "dominant_enc": dominant_enc,
            "distribution": proto_dist,
        },
    }


# =============================================================================
# BUILD ALL BASELINES
# =============================================================================

def build_all_baselines() -> dict:
    """
    Build baselines for all 25 critical ports + port -1 (ICMP/ARP).

    Steps:
        1. Load all three data sources
        2. Merge with weighting (real 3x, synthetic 1x)
        3. Save combined_normal.csv for Phase 5 training
        4. Calculate per-port baseline statistics
        5. Save baselines.json

    Returns the full baselines dict.
    """
    print("=== Cerberus — Baseline Engine ===\n")
    print("[*] Loading data sources...")

    kaggle_df    = _load_kaggle()
    sqlite_df    = _load_sqlite()
    synthetic_df = _load_synthetic(CRITICAL_PORTS + [-1])

    print(f"\n[*] Merging sources (real weight={REAL_DATA_WEIGHT}x, synthetic weight=1x)...")
    combined = _merge_sources(kaggle_df, sqlite_df, synthetic_df)

    if combined.empty:
        print("[!] No data available from any source. Exiting.")
        sys.exit(1)

    # ── Save combined dataset for Phase 5 ─────────────────────────────────
    os.makedirs(os.path.dirname(COMBINED_PATH), exist_ok=True)
    combined.to_csv(COMBINED_PATH, index=False)
    print(f"[+] Combined normal dataset: {len(combined):,} rows → {COMBINED_PATH}")

    # ── Source composition report ─────────────────────────────────────────
    print(f"\n[*] Combined dataset composition:")
    comp = combined["source"].value_counts()
    for src, count in comp.items():
        pct = count / len(combined) * 100
        print(f"    {src:<10}: {count:>6,} rows ({pct:.1f}%)")

    # ── Build per-port baselines ──────────────────────────────────────────
    print(f"\n[*] Building per-port baselines...")
    print(f"[*] STD_MULTIPLIER={STD_MULTIPLIER} | MIN_OBSERVATIONS={MIN_OBSERVATIONS}\n")

    baselines  = {}
    ok_ports   = []
    skipped    = []

    for port in CRITICAL_PORTS + [-1]:
        port_data = combined[combined["dest_port"] == port]
        baseline  = _calculate_baseline(port_data, port)
        baselines[str(port)] = baseline

        if baseline["status"] == "ok":
            ok_ports.append(port)
            length_info = (
                f"[{baseline['length']['lower']:.0f}–{baseline['length']['upper']:.0f}]"
                if baseline["length"].get("available")
                else "n/a"
            )
            src_summary = ", ".join(
                f"{k}:{v}" for k, v in baseline["source_composition"].items()
            )
            print(
                f"  [+] Port {port:>5} | "
                f"{baseline['total_observations']:>5} obs | "
                f"{baseline['confidence']:<6} | "
                f"length: {length_info:<14} | "
                f"protocol: {baseline['protocol']['dominant']:<8} | "
                f"src: {src_summary}"
            )
        else:
            skipped.append(port)
            print(f"  [!] Port {port:>5} | insufficient data — skipped")

    # ── Save baselines.json ───────────────────────────────────────────────
    os.makedirs(os.path.dirname(BASELINES_PATH), exist_ok=True)
    with open(BASELINES_PATH, "w") as f:
        json.dump(baselines, f, indent=2)

    print(f"\n[+] Baselines saved → {BASELINES_PATH}")
    print(f"\n--- Summary ---")
    print(f"  Ports profiled : {len(ok_ports)}")
    print(f"  Ports skipped  : {len(skipped)}")
    if skipped:
        print(f"  Skipped        : {skipped}")

    return baselines


# =============================================================================
# BASELINE CHECKER  (used by Phase 6 correlator)
# =============================================================================

def load_baselines() -> dict:
    """
    Load baselines.json from disk.
    Returns empty dict if file does not exist.
    """
    if not os.path.exists(BASELINES_PATH):
        print("[!] baselines.json not found. Run Phase 4 first.")
        return {}
    with open(BASELINES_PATH, "r") as f:
        return json.load(f)


def check_packet(packet: dict, baselines: dict) -> dict:
    """
    Layer 1 baseline check for a single packet.

    Parameters:
        packet    : dict with keys — dest_port, length, protocol_enc
        baselines : loaded dict from load_baselines()

    Returns:
        {
            "port"       : int,
            "flagged"    : bool,
            "reasons"    : list[str],
            "confidence" : str,
        }

    Flagging logic:
        A packet is flagged if ANY single condition fails:
        1. Port has no baseline (unseen port is itself suspicious)
        2. Packet length outside [lower, upper] bounds
           (skipped if length data was unavailable for this port)
        3. Protocol does not match dominant protocol for this port

    Why ANY rather than ALL:
        Security detection errs on the side of caution.
        A single deviation is worth passing to Layer 2 for confirmation.
        Requiring multiple failures simultaneously would miss attacks
        that only deviate on one dimension — a common evasion technique.
    """
    port   = int(packet.get("dest_port", -1))
    length = float(packet.get("length", 0))
    proto  = int(packet.get("protocol_enc", 99))

    baseline = baselines.get(str(port))

    if baseline is None or baseline.get("status") != "ok":
        return {
            "port":       port,
            "flagged":    True,
            "reasons":    [f"Port {port} has no established baseline"],
            "confidence": "LOW",
        }

    reasons = []

    # Check 1: packet length
    lp = baseline.get("length", {})
    if lp.get("available") and length > 0:
        if not (lp["lower"] <= length <= lp["upper"]):
            reasons.append(
                f"Length {length:.0f} outside normal range "
                f"[{lp['lower']:.0f}–{lp['upper']:.0f}] for port {port}"
            )

    # Check 2: protocol
    expected_enc  = baseline["protocol"]["dominant_enc"]
    expected_name = PROTOCOL_MAP.get(expected_enc, str(expected_enc))
    actual_name   = PROTOCOL_MAP.get(proto, str(proto))
    if proto != expected_enc:
        reasons.append(
            f"Protocol {actual_name} unexpected on port {port} "
            f"(expected {expected_name})"
        )

    return {
        "port":       port,
        "flagged":    len(reasons) > 0,
        "reasons":    reasons,
        "confidence": baseline["confidence"],
    }


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    baselines = build_all_baselines()

    print("\n--- Sample: port 22 ---")
    print(json.dumps(baselines.get("22", {}), indent=2))

    print("\n--- Sample: port 443 ---")
    print(json.dumps(baselines.get("443", {}), indent=2))