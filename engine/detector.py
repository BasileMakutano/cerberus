"""
Cerberus — engine/detector.py
Phase 5: Per-port Isolation Forest ML models.

This is Layer 2 of Cerberus's two-layer detection system.

How it works:
    Layer 1 (profiler + baseline) flags suspicious observations
    based on known behavioural rules — wrong service, unknown IP,
    frequency spike, packet length anomaly.

    Layer 2 (this module) receives those flagged observations and
    confirms whether they are statistically anomalous using a
    trained Isolation Forest model.

Why Isolation Forest?
    - Unsupervised: trains on normal traffic only, no labelled
      attack data required (matches scope from concept note)
    - Isolation principle: anomalies are easier to isolate than
      normal points because they are few and different. The model
      builds random trees — anomalies get isolated in fewer splits,
      yielding a high anomaly score.
    - Low overhead: linear time complexity, suitable for Kali VM
    - Explainable: anomaly score is a float, easy to threshold

Training strategy:
    One model per port. Each model trains exclusively on normal
    traffic rows for its specific port from combined_normal.csv.

    Why per-port?
        Port 443 (HTTPS) has large variable-length TLS packets.
        Port 53 (DNS) has small fixed-length UDP queries.
        A single model would blur these differences and reduce
        detection sensitivity for both.

Contamination = 0.05:
    Tells the model to treat the most anomalous 5% of training
    data as boundary cases. Too low = too strict (many false
    positives). Too high = too loose (misses real attacks).
    0.05 is the scikit-learn recommended default.

Evaluation:
    Each model is evaluated against clean.csv which has both
    normal (bad_packet=0) and malicious (bad_packet=1) rows.
    This gives precision, recall, and F1 per port.

Output:
    models/ports/port_22.pkl    — trained model per port
    models/ports/scaler_22.pkl  — fitted scaler per port
    models/evaluation.json      — precision/recall/F1 per port

What the correlator must pass to score_observation():
    observation = {
        "length":       int    packet length in bytes (0–1500)
        "source_port":  int    ephemeral source port (1024–65535)
        "dest_port":    int    destination port being scored
        "protocol_enc": int    protocol encoded as int:
                               0=ICMP, 1=TCP, 2=UDP, 3=ARP,
                               4=TLS, 5=other
    }
    All four fields must be present. Missing fields are filled
    with 0 and a warning is logged — scores will be degraded.
"""

# FIX 1: sys.path.insert moved here, immediately after sys/os imports,
# before any other imports. This ensures from engine.db import BASE_DIR
# resolves correctly when the script is run directly (python3 detector.py).
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

import joblib
import numpy  as np
import pandas as pd
from sklearn.ensemble      import IsolationForest
from sklearn.metrics       import f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from engine.db import BASE_DIR


# =============================================================================
# PATHS
# =============================================================================

COMBINED_PATH = os.path.join(BASE_DIR, "data", "dataset", "combined_normal.csv")
CLEAN_PATH    = os.path.join(BASE_DIR, "data", "dataset", "clean.csv")
MODELS_DIR    = os.path.join(BASE_DIR, "models", "ports")

# FIX 3: Renamed from evaluation_report.json to evaluation.json to match
# the filename declared in the project file structure (models/evaluation.json).
# The correlator and dashboard both read from this path.
EVAL_PATH     = os.path.join(BASE_DIR, "models", "evaluation.json")

MIN_TRAIN_ROWS = 50

IF_PARAMS = {
    "contamination": 0.1,
    "n_estimators":  100,
    "random_state":  42,
    "n_jobs":        -1,
}

# Feature columns — must match combined_normal.csv column names exactly.
# Order here is the canonical feature order used in both training and inference.
# If combined_normal.csv is regenerated, verify these column names still exist.
FEATURES = ["length", "source_port", "dest_port", "protocol_enc"]

# Whitelist of ports Cerberus is designed to monitor.
# -1 is the sentinel for ICMP/ARP traffic (no dest_port).
# combined_normal.csv may contain additional ports leaked from the Kaggle
# dataset (e.g. ephemeral ports 49734, 57912, 57914) — these are filtered
# out here so no models are trained on out-of-scope ports.
MONITORED_PORTS = {
    -1,
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017, 2181,
}


# =============================================================================
# UTILITIES
# =============================================================================

def _model_path(port: int) -> str:
    return os.path.join(MODELS_DIR, f"port_{port}.pkl")


def _scaler_path(port: int) -> str:
    return os.path.join(MODELS_DIR, f"scaler_{port}.pkl")


def _load_combined() -> pd.DataFrame:
    if not os.path.exists(COMBINED_PATH):
        print("[!] combined_normal.csv not found. Run Phase 4b first.")
        sys.exit(1)
    df = pd.read_csv(COMBINED_PATH)
    print(f"[+] Training data: {len(df):,} rows")
    return df


def _load_clean() -> pd.DataFrame:
    if not os.path.exists(CLEAN_PATH):
        print("[!] clean.csv not found. Run Phase 3 first.")
        return pd.DataFrame()
    df = pd.read_csv(CLEAN_PATH)
    print(f"[+] Evaluation data: {len(df):,} rows")
    return df


# =============================================================================
# TRAINING
# =============================================================================

def _train_port_model(port: int, port_data: pd.DataFrame) -> tuple:
    """
    Train an Isolation Forest model for one port.

    Why StandardScaler before Isolation Forest?
        Features have very different ranges:
            length       : 0 – 1500
            source_port  : 1024 – 65535
            dest_port    : 21 – 27017
            protocol_enc : 0 – 5

        Without scaling, length and source_port dominate every
        random split. StandardScaler brings all features to
        mean=0, std=1, giving each equal influence on the model.

    Returns (model, scaler) — both saved to disk.
    """
    X = port_data[FEATURES].fillna(0).values

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(**IF_PARAMS)
    model.fit(X_scaled)

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(model,  _model_path(port))
    joblib.dump(scaler, _scaler_path(port))

    return model, scaler


# =============================================================================
# EVALUATION
# =============================================================================

def _evaluate_port_model(
    port:     int,
    model:    IsolationForest,
    scaler:   StandardScaler,
    clean_df: pd.DataFrame,
) -> dict:
    """
    Evaluate a trained model against labelled clean.csv data.

    Isolation Forest predict() convention:
         1 = normal
        -1 = anomaly

    We convert to match bad_packet labels:
        0 = normal   (bad_packet=0)
        1 = anomaly  (bad_packet=1)

    Metrics:
        Precision — of all flagged packets, how many were truly malicious
        Recall    — of all malicious packets, how many did we catch
        F1        — harmonic mean of precision and recall

    Recall is the priority metric in security — missing an attack
    (false negative) is worse than a false alarm (false positive).
    """
    if clean_df.empty:
        return {"port": port, "status": "no_eval_data"}

    port_eval = clean_df[clean_df["dest_port"] == port].copy()

    if len(port_eval) < 10:
        return {
            "port":   port,
            "status": "insufficient_eval_data",
            "rows":   len(port_eval),
        }

    class_counts = port_eval["bad_packet"].value_counts()
    if len(class_counts) < 2:
        return {
            "port":   port,
            "status": "single_class_only",
            "class":  int(class_counts.index[0]),
            "count":  int(class_counts.iloc[0]),
        }

    X_eval = port_eval[FEATURES].fillna(0).values
    y_true = port_eval["bad_packet"].values

    X_scaled  = scaler.transform(X_eval)
    raw_preds = model.predict(X_scaled)
    y_pred    = (raw_preds == -1).astype(int)
    scores    = model.score_samples(X_scaled)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    f1        = f1_score(y_true, y_pred, zero_division=0)

    return {
        "port":                 port,
        "status":               "evaluated",
        "eval_rows":            len(port_eval),
        "normal_rows":          int(class_counts.get(0, 0)),
        "malicious_rows":       int(class_counts.get(1, 0)),
        "precision":            round(precision, 4),
        "recall":               round(recall, 4),
        "f1_score":             round(f1, 4),
        "mean_score_normal":    round(float(scores[y_true == 0].mean()), 4)
                                if (y_true == 0).any() else None,
        "mean_score_malicious": round(float(scores[y_true == 1].mean()), 4)
                                if (y_true == 1).any() else None,
    }


# =============================================================================
# TRAIN ALL
# =============================================================================

def train_all() -> dict:
    """
    Train one Isolation Forest model per port in combined_normal.csv.

    Steps per port:
        1. Filter combined_normal.csv to rows for this port
        2. Skip if fewer than MIN_TRAIN_ROWS
        3. Train IsolationForest with StandardScaler
        4. Save model + scaler to models/ports/
        5. Evaluate against clean.csv labels
        6. Record evaluation metrics

    Saves models/evaluation.json when done.
    Returns evaluation report dict.
    """
    print("=== Cerberus — Isolation Forest Trainer ===\n")

    combined_df = _load_combined()
    clean_df    = _load_clean()

    all_ports  = set(int(p) for p in combined_df["dest_port"].unique())
    ports      = sorted(all_ports & MONITORED_PORTS)
    extra      = sorted(all_ports - MONITORED_PORTS)

    print(f"\n[*] Ports in training data : {ports}")
    if extra:
        print(f"[!] Out-of-scope ports filtered out : {extra}")
    print(f"[*] Min rows to train      : {MIN_TRAIN_ROWS}")
    print(f"[*] contamination          : {IF_PARAMS['contamination']}")
    print(f"[*] n_estimators           : {IF_PARAMS['n_estimators']}\n")

    evaluation_report = {}
    trained_ports     = []
    skipped_ports     = []

    for port in ports:
        port_data = combined_df[combined_df["dest_port"] == port]
        n         = len(port_data)

        if n < MIN_TRAIN_ROWS:
            skipped_ports.append(port)
            print(f"  [!] Port {port:>5} | {n:>5} rows | skipped (need {MIN_TRAIN_ROWS}+)")
            continue

        model, scaler = _train_port_model(port, port_data)
        trained_ports.append(port)

        eval_result = _evaluate_port_model(port, model, scaler, clean_df)
        evaluation_report[str(port)] = eval_result

        if eval_result["status"] == "evaluated":
            eval_str = (
                f"P={eval_result['precision']:.2f} "
                f"R={eval_result['recall']:.2f} "
                f"F1={eval_result['f1_score']:.2f}"
            )
        else:
            eval_str = eval_result["status"]

        print(
            f"  [+] Port {port:>5} | "
            f"{n:>5} rows | "
            f"saved: port_{port}.pkl | "
            f"eval: {eval_str}"
        )

    os.makedirs(os.path.dirname(EVAL_PATH), exist_ok=True)
    with open(EVAL_PATH, "w") as f:
        # np.int64 keys/values from pandas are not JSON serializable by default.
        # We convert the entire report through a round-trip via a custom encoder
        # that casts numpy scalar types to native Python ints/floats.
        class _NumpyEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, (np.integer,)):
                    return int(obj)
                if isinstance(obj, (np.floating,)):
                    return float(obj)
                return super().default(obj)

        json.dump(evaluation_report, f, indent=2, cls=_NumpyEncoder)

    print(f"\n[+] Evaluation report → {EVAL_PATH}")
    print(f"\n--- Summary ---")
    print(f"  Trained : {len(trained_ports)} ports → {trained_ports}")
    print(f"  Skipped : {len(skipped_ports)} ports → {skipped_ports}")

    print(f"\n--- Evaluation Results ---")
    for port_str, result in evaluation_report.items():
        if result["status"] == "evaluated":
            print(
                f"  Port {int(port_str):>5} | "
                f"Precision: {result['precision']:.4f} | "
                f"Recall: {result['recall']:.4f} | "
                f"F1: {result['f1_score']:.4f} | "
                f"rows: {result['eval_rows']}"
            )
        else:
            print(f"  Port {int(port_str):>5} | {result['status']}")

    return evaluation_report


# =============================================================================
# INFERENCE  (called by Phase 6 correlator)
# =============================================================================

def load_model(port: int) -> tuple:
    """
    Load trained model and scaler for one port.
    Returns (model, scaler) or (None, None) if not found or corrupted.

    If a .pkl file exists but is unreadable (e.g. corrupted from a failed
    prior run), the exception is caught here and logged visibly. The
    correlator receives (None, None) and scores the port as 'no_model',
    meaning Layer 2 is skipped for that port.

    To fix a corrupted model: delete the .pkl files and re-run train_all().
        rm models/ports/port_<N>.pkl models/ports/scaler_<N>.pkl
        venv/bin/python3 engine/detector.py
    """
    mp = _model_path(port)
    sp = _scaler_path(port)

    if not os.path.exists(mp) or not os.path.exists(sp):
        return None, None

    try:
        return joblib.load(mp), joblib.load(sp)
    except Exception as exc:
        # FIX 4: Corrupt model failure is now logged visibly, not silently
        # swallowed. This surfaces during correlator runs so the operator
        # knows to delete and retrain the affected port model.
        print(f"  [!] CORRUPT or unreadable model for port {port}: {exc}")
        print(f"      Fix: rm {mp} {sp} && venv/bin/python3 engine/detector.py")
        return None, None


def score_observation(observation: dict, port: int) -> dict:
    """
    Score a single observation against the trained model for its port.

    Called by the correlator ONLY for observations already flagged
    by Layer 1. Layer 2 either confirms the anomaly or dismisses it.

    Parameters:
        observation : dict — the correlator must provide all four fields:
                      {
                        "length":       int  packet length in bytes
                        "source_port":  int  ephemeral source port
                        "dest_port":    int  destination port
                        "protocol_enc": int  0=ICMP,1=TCP,2=UDP,3=ARP,
                                             4=TLS,5=other
                      }
        port        : destination port number (used for model lookup)

    Returns:
        {
            port         : int
            anomaly      : bool    True = confirmed anomaly
            score        : float   more negative = more anomalous
            threshold    : float   IF decision boundary (model.offset_)
            model_status : str     ok / no_model / error
        }

    Score interpretation:
        Isolation Forest score_samples() returns roughly [-0.5, 0.5].
        Near 0 or positive → normal behaviour
        Near -0.5 or below → highly anomalous
        The threshold (model.offset_) is set by the contamination param.
        Anything below the threshold is flagged as an anomaly.

    FIX 2: Missing field warning.
        The four features (length, source_port, dest_port, protocol_enc)
        must come from the correlator's live observation dict. If any are
        absent, they fall back to 0 and a warning is printed. A zero
        source_port or length degrades score accuracy — the correlator
        should always populate all four fields from the nmap/ss/tcpdump
        data before calling this function.
    """
    model, scaler = load_model(port)

    if model is None:
        return {
            "port":         port,
            "anomaly":      False,
            "score":        None,
            "threshold":    None,
            "model_status": "no_model",
        }

    try:
        # FIX 2: Warn explicitly when fields are missing so the correlator
        # developer knows the observation dict is incomplete. Silently
        # defaulting to 0 previously caused every missing-field observation
        # to score identically, making detection unreliable for live data.
        missing = [
            f for f in ["length", "source_port", "protocol_enc"]
            if observation.get(f) is None
        ]
        if missing:
            print(
                f"  [~] Port {port}: observation missing fields {missing} "
                f"— defaulting to 0. Layer 2 score may be degraded."
            )

        row = [[
            float(observation.get("length",       0)),
            float(observation.get("source_port",  0)),
            float(observation.get("dest_port",    port)),
            float(observation.get("protocol_enc", 1)),
        ]]

        X_scaled   = scaler.transform(row)
        prediction = model.predict(X_scaled)[0]
        score      = float(model.score_samples(X_scaled)[0])
        threshold  = float(model.offset_)

        return {
            "port":         port,
            "anomaly":      prediction == -1,
            "score":        round(score, 6),
            "threshold":    round(threshold, 6),
            "model_status": "ok",
        }

    except Exception as exc:
        return {
            "port":         port,
            "anomaly":      False,
            "score":        None,
            "threshold":    None,
            "model_status": f"error: {exc}",
        }


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    report = train_all()

    evaluated = {k: v for k, v in report.items() if v.get("status") == "evaluated"}
    if evaluated:
        best = max(evaluated, key=lambda k: evaluated[k].get("eval_rows", 0))
        print(f"\n--- Best evaluated port: {best} ---")
        print(json.dumps(evaluated[best], indent=2))