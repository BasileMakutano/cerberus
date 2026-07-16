import sqlite3, pandas as pd, numpy as np, os, json, joblib
from sklearn.metrics import precision_score, recall_score, f1_score

BASE_DIR   = os.path.expanduser("~/Documents/cerberus")
DB_PATH    = os.path.join(BASE_DIR, "data", "recon.db")
EVAL_PATH  = os.path.join(BASE_DIR, "models", "evaluation.json")
MODELS_DIR = os.path.join(BASE_DIR, "models", "ports")

FEATURES        = ["length", "source_port", "dest_port", "protocol_enc"]
PROTO_MAP       = {"tcp":1, "udp":2, "icmp":0, "arp":3}
MONITORED_PORTS = [21, 22, 25, 80, 139, 443, 445, 3306, 8080, 8888]

conn = sqlite3.connect(DB_PATH)

raw = pd.read_sql("""
    SELECT port AS dest_port, protocol
    FROM port_observations
    WHERE port IN (21,22,25,80,139,443,445,3306,8080,8888)
""", conn).reset_index(drop=True)

conn.close()

raw["protocol_enc"] = raw["protocol"].str.lower().map(PROTO_MAP).fillna(5).astype(int)
raw["length"]       = np.random.randint(0, 500, len(raw))
raw["source_port"]  = np.random.randint(1024, 65535, len(raw))
raw["bad_packet"]   = 0
raw["dest_port"]    = raw["dest_port"].astype(int)

normal_df = raw[FEATURES + ["bad_packet", "dest_port"]].reset_index(drop=True)

# ── Generate synthetic attack rows per port ───────────────────────────────────
attack_frames = []
for port in MONITORED_PORTS:
    n = max(50, int(len(normal_df[normal_df.dest_port == port]) * 0.3))
    attack_frames.append(pd.DataFrame({
        "dest_port":    [port] * n,
        "protocol_enc": [1] * n,
        "length":       np.random.randint(1200, 1500, n),
        "source_port":  np.random.randint(1024, 65535, n),
        "bad_packet":   [1] * n,
    }))

attack_df = pd.concat(attack_frames, ignore_index=True)
eval_df   = pd.concat([normal_df, attack_df], ignore_index=True)

print(f"Evaluation dataset: {len(eval_df)} rows — "
      f"{(eval_df.bad_packet==0).sum()} normal, "
      f"{(eval_df.bad_packet==1).sum()} attack\n")

# ── Evaluate each port model ──────────────────────────────────────────────────
results = {}
for port in MONITORED_PORTS:
    mp = os.path.join(MODELS_DIR, f"port_{port}.pkl")
    sp = os.path.join(MODELS_DIR, f"scaler_{port}.pkl")
    if not os.path.exists(mp):
        print(f"  Port {port:>5} | no model found — skipping")
        continue

    port_df = eval_df[eval_df.dest_port == port].copy().reset_index(drop=True)
    if len(port_df) < 10:
        print(f"  Port {port:>5} | insufficient rows ({len(port_df)}) — skipping")
        continue

    model  = joblib.load(mp)
    scaler = joblib.load(sp)

    X      = port_df[FEATURES].fillna(0).values
    y      = port_df["bad_packet"].values
    X_s    = scaler.transform(X)
    preds  = (model.predict(X_s) == -1).astype(int)
    scores = model.score_samples(X_s)

    p = precision_score(y, preds, zero_division=0)
    r = recall_score(y, preds, zero_division=0)
    f = f1_score(y, preds, zero_division=0)

    results[str(port)] = {
        "port":               port,
        "status":             "evaluated",
        "eval_rows":          len(port_df),
        "normal_rows":        int((y == 0).sum()),
        "attack_rows":        int((y == 1).sum()),
        "precision":          round(p, 4),
        "recall":             round(r, 4),
        "f1_score":           round(f, 4),
        "mean_score_normal":  round(float(scores[y == 0].mean()), 4),
        "mean_score_attack":  round(float(scores[y == 1].mean()), 4),
    }

    print(f"  Port {port:>5} | "
          f"P={p:.4f}  R={r:.4f}  F1={f:.4f} | "
          f"rows={len(port_df)}  "
          f"(normal={int((y==0).sum())}  attack={int((y==1).sum())})")

# ── Merge with existing evaluation.json (preserve port -1) ───────────────────
existing = {}
if os.path.exists(EVAL_PATH):
    with open(EVAL_PATH) as f:
        existing = json.load(f)

existing.update(results)
with open(EVAL_PATH, "w") as f:
    json.dump(existing, f, indent=2)

print(f"\n[+] evaluation.json updated → {EVAL_PATH}")
