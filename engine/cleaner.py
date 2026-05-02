"""
Cerberus — engine/cleaner.py

Cleans and prepares the Kaggle dataset for use in Phase 4 (baseline)
and Phase 5 (ML detection).

Input:   data/dataset/raw.csv         — original Kaggle CSV
Output:  data/dataset/clean.csv       — cleaned, balanced, numeric
         data/dataset/normal_only.csv — bad_packet=0 rows only (for training)

Why two output files:
    clean.csv        → used for evaluating model performance (has labels)
    normal_only.csv  → used for training Isolation Forest (unsupervised,
                       the model only sees normal traffic and learns what
                       normal looks like — anomalies deviate from this)
"""

import pandas as pd
import numpy as np
import os
import sys

# Ensure project root is on the path regardless of how this file is invoked
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.db import BASE_DIR


DATASET_DIR  = os.path.join(BASE_DIR, "data", "dataset")
RAW_PATH     = os.path.join(DATASET_DIR, "raw.csv")
CLEAN_PATH   = os.path.join(DATASET_DIR, "clean.csv")
NORMAL_PATH  = os.path.join(DATASET_DIR, "normal_only.csv")


# =============================================================================
# CLEANING STEPS
# =============================================================================

def _load_raw(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        print(f"[!] Raw dataset not found at: {path}")
        print(f"    Place your Kaggle CSV at: {path}")
        sys.exit(1)

    print(f"[*] Loading dataset from {path}...")
    df = pd.read_csv(path)
    print(f"[+] Loaded: {df.shape[0]:,} rows × {df.shape[1]} columns")
    return df


def _drop_useless_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Drop columns that carry no useful signal for per-port anomaly detection.

    Time        → relative float from packet capture start, not a real
                  timestamp and not comparable across sessions
    Source      → mix of IPs and MAC addresses (ARP rows show MAC addresses
                  like 'VMware_8a:60:5f' instead of IPs) — inconsistent
                  and not useful for port-level analysis
    Destination → same problem as Source
    """
    cols_to_drop = ["Time", "Source", "Destination"]
    df = df.drop(columns=cols_to_drop)
    print(f"[+] Dropped {cols_to_drop} → {df.shape[1]} columns remaining")
    return df


def _encode_protocol(df: pd.DataFrame) -> pd.DataFrame:
    """
    Encode the Protocol column from string to integer.

    ML models require numeric input — strings must be converted.
    We use a fixed mapping so the encoding is consistent between
    training and inference. Unknown protocols map to 99.

    Mapping:
        ICMP     → 0   (most common in this dataset, mostly bad traffic)
        TCP      → 1   (standard connection-based traffic)
        TLSv1.2  → 2   (encrypted TCP, typically HTTPS)
        ARP      → 3   (link-layer, no ports)
        NBNS     → 4   (NetBIOS name service)
        BROWSER  → 5   (SMB browser protocol)
        other    → 99  (unknown/future protocols)
    """
    protocol_map = {
        "ICMP":    0,
        "TCP":     1,
        "TLSv1.2": 2,
        "ARP":     3,
        "NBNS":    4,
        "BROWSER": 5,
    }
    df["protocol_enc"] = df["Protocol"].map(protocol_map).fillna(99).astype(int)
    df = df.drop(columns=["Protocol"])

    dist = df["protocol_enc"].value_counts().to_dict()
    print(f"[+] Protocol encoded → distribution: {dist}")
    return df


def _fill_null_ports(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fill null Source Port and Destination Port values with -1.

    96% of port values are null because ICMP and ARP packets
    genuinely have no port — they operate below the transport layer.
    Dropping these rows would remove almost the entire dataset.

    We use -1 as a sentinel value meaning 'no port applicable'.
    The baseline and ML engines treat -1 as a distinct port class,
    not as a missing value — this is intentional.
    """
    before = df[["Source Port", "Destination Port"]].isnull().sum()
    df["Source Port"]      = df["Source Port"].fillna(-1).astype(int)
    df["Destination Port"] = df["Destination Port"].fillna(-1).astype(int)
    print(f"[+] Filled null ports with -1 (was: {before['Source Port']:,} nulls)")
    return df


def _cap_packet_length(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cap packet Length at the 99.9th percentile.

    We use 99.9% instead of 99% because 99% of this dataset has
    length exactly 42 (bare ICMP/ARP packets), which means capping
    at 99% would set every packet to length 42 — destroying the
    feature entirely.

    Using 99.9% captures the actual variation in larger TCP/TLS
    packets while still removing extreme outliers.
    """
    cap = df["Length"].quantile(0.999)

    if cap <= 42:
        # Safety check: if even 99.9% is 42, don't cap at all
        # — the feature has no variance worth preserving via capping
        print(f"[!] 99.9th percentile is {cap} — skipping cap, no variance to preserve")
        return df

    before_max = df["Length"].max()
    df["Length"] = df["Length"].clip(upper=cap)
    print(f"[+] Packet length capped at 99.9th percentile: {cap:.0f} (was max: {before_max})")
    return df


def _rename_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Standardise column names to snake_case for consistency."""
    df = df.rename(columns={
        "Source Port":      "source_port",
        "Destination Port": "dest_port",
        "Length":           "length",
    })
    return df


def _balance_classes(df: pd.DataFrame) -> pd.DataFrame:
    """
    Rebalance the dataset to a realistic malicious-to-normal ratio.

    The raw dataset is 94% bad_packet=1. This is not realistic —
    in a real network, malicious traffic is the minority. Training
    or evaluating on a 94% malicious dataset would make any model
    appear highly accurate just by predicting 'malicious' every time.

    Strategy:
        - Keep ALL normal rows (bad_packet=0) — these are scarce
          (only ~4,500 out of 3.2M) so we preserve every one
        - Undersample malicious to 3× normal count for evaluation
        - This gives a 3:1 malicious:normal ratio in clean.csv

    Note: normal_only.csv contains only the ~4,500 normal rows.
    This is enough for Isolation Forest to learn a normal profile,
    but the model will be conservative — flag anything that deviates
    even slightly, since it has limited normal examples to learn from.
    """
    normal    = df[df["bad_packet"] == 0]
    malicious = df[df["bad_packet"] == 1]

    target            = len(normal) * 3
    malicious_sampled = malicious.sample(
        n            = min(target, len(malicious)),
        random_state = 42
    )

    balanced = pd.concat([normal, malicious_sampled]) \
                 .sample(frac=1, random_state=42) \
                 .reset_index(drop=True)

    print(f"[+] Class balance after resampling:")
    print(f"    normal    (0): {len(normal):,}")
    print(f"    malicious (1): {len(malicious_sampled):,}")
    print(f"    total        : {len(balanced):,}")
    return balanced


# =============================================================================
# SAVE OUTPUTS
# =============================================================================

def _save_normal_only(df: pd.DataFrame) -> None:
    """
    Save a version containing only normal traffic (bad_packet=0).

    This is the training input for Isolation Forest in Phase 5.
    The model is trained exclusively on normal traffic so it learns
    what normal looks like. When it later scores new packets, anything
    that deviates significantly from this learned normal gets a high
    anomaly score.

    We drop bad_packet from this file since the model trains
    unsupervised — it must not see the labels during training.
    """
    normal = df[df["bad_packet"] == 0].drop(columns=["bad_packet"]).copy()
    os.makedirs(os.path.dirname(NORMAL_PATH), exist_ok=True)
    normal.to_csv(NORMAL_PATH, index=False)
    print(f"[+] Normal-only dataset saved: {len(normal):,} rows → {NORMAL_PATH}")


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def clean(raw_path: str = RAW_PATH) -> pd.DataFrame:
    """
    Run the full cleaning pipeline and save both output files.

    Steps:
        1. Load raw CSV
        2. Drop Time, Source, Destination
        3. Encode Protocol as integer
        4. Fill null ports with -1
        5. Cap Length outliers at 99.9th percentile
        6. Rename columns to snake_case
        7. Balance classes (keep all normal, 3x malicious for evaluation)
        8. Save clean.csv  (full balanced dataset with labels)
        9. Save normal_only.csv (no labels, for IF training)

    Returns the cleaned DataFrame.
    """
    print("=== Cerberus — Dataset Cleaner ===\n")

    df = _load_raw(raw_path)

    print("\n[Step 1] Dropping useless columns...")
    df = _drop_useless_columns(df)

    print("\n[Step 2] Encoding protocol...")
    df = _encode_protocol(df)

    print("\n[Step 3] Filling null ports...")
    df = _fill_null_ports(df)

    print("\n[Step 4] Capping packet length outliers...")
    df = _cap_packet_length(df)

    print("\n[Step 5] Renaming columns...")
    df = _rename_columns(df)

    print("\n[Step 6] Balancing classes...")
    df = _balance_classes(df)

    print("\n[Step 7] Saving clean dataset...")
    os.makedirs(DATASET_DIR, exist_ok=True)
    df.to_csv(CLEAN_PATH, index=False)
    print(f"[+] Clean dataset saved: {len(df):,} rows → {CLEAN_PATH}")

    print("\n[Step 8] Saving normal-only dataset for model training...")
    _save_normal_only(df)

    print("\n=== Cleaning complete ===")
    print(f"\nFinal columns : {df.columns.tolist()}")
    print(f"Final shape   : {df.shape}")
    print(f"\nSample (5 rows):\n{df.head().to_string()}")

    return df


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    clean()