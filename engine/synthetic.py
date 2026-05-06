"""
Cerberus — engine/synthetic.py

Generates synthetic normal traffic observations for ports that have
insufficient real data from either the Kaggle dataset or live scans.

Why synthetic data is valid here:
    Port behaviour is extensively documented in RFCs and security
    literature. SSH (port 22) always uses TCP. DNS uses UDP on port 53.
    HTTP packet sizes follow known distributions. This is domain
    knowledge encoded as data, not fabrication.

    This technique is used in academic network security research:
    - Shiravi et al. (2012) CICIDS dataset uses generated traffic
    - Ring et al. (2019) survey acknowledges synthetic augmentation
      as standard practice when live capture is impractical

    All synthetic rows are tagged source='synthetic' in the combined
    dataset so they can be identified and reported on transparently.

Design:
    Each port profile specifies the dominant protocol and a realistic
    packet length distribution (mean ± std) based on RFC documentation.
    Lengths are clipped to [20, 1500] — min Ethernet payload to max
    unfragmented MTU. Source ports are randomised in the ephemeral
    range (1024–65535) as they are in real traffic.

    Random seed is deterministic per port (seed + port number) so
    results are reproducible across runs.
"""

import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# PORT PROFILES
# =============================================================================
# Each entry encodes documented normal behaviour for that port.
#
# protocol_enc:
#     1 = TCP   (connection-based, most application protocols)
#     2 = UDP   (connectionless, DNS / some streaming protocols)
#
# length_mean / length_std:
#     Packet payload size in bytes based on:
#     - RFC specifications for each protocol
#     - Wireshark community capture statistics
#     - SANS Institute protocol analysis guides
#
# n_samples:
#     200 per port — enough for Isolation Forest to learn a boundary
#     without overwhelming real data during weighted merging.

PORT_PROFILES = {
    # Port  : protocol  mean   std    n
    21:    {"protocol_enc": 1, "length_mean": 60,   "length_std": 10,  "n": 200},  # FTP control
    22:    {"protocol_enc": 1, "length_mean": 900,  "length_std": 200, "n": 200},  # SSH encrypted
    23:    {"protocol_enc": 1, "length_mean": 60,   "length_std": 15,  "n": 200},  # Telnet (small cmds)
    25:    {"protocol_enc": 1, "length_mean": 500,  "length_std": 200, "n": 200},  # SMTP email body
    53:    {"protocol_enc": 2, "length_mean": 80,   "length_std": 30,  "n": 200},  # DNS query/response
    80:    {"protocol_enc": 1, "length_mean": 800,  "length_std": 400, "n": 200},  # HTTP request/response
    110:   {"protocol_enc": 1, "length_mean": 300,  "length_std": 100, "n": 200},  # POP3 mail retrieval
    135:   {"protocol_enc": 1, "length_mean": 100,  "length_std": 30,  "n": 200},  # MS RPC endpoint mapper
    139:   {"protocol_enc": 1, "length_mean": 120,  "length_std": 40,  "n": 200},  # NetBIOS session
    143:   {"protocol_enc": 1, "length_mean": 350,  "length_std": 100, "n": 200},  # IMAP mail access
    443:   {"protocol_enc": 1, "length_mean": 800,  "length_std": 300, "n": 200},  # HTTPS/TLS
    445:   {"protocol_enc": 1, "length_mean": 200,  "length_std": 80,  "n": 200},  # SMB file sharing
    1433:  {"protocol_enc": 1, "length_mean": 200,  "length_std": 80,  "n": 200},  # Microsoft SQL Server
    1521:  {"protocol_enc": 1, "length_mean": 250,  "length_std": 80,  "n": 200},  # Oracle DB
    3306:  {"protocol_enc": 1, "length_mean": 180,  "length_std": 60,  "n": 200},  # MySQL
    3389:  {"protocol_enc": 1, "length_mean": 400,  "length_std": 150, "n": 200},  # RDP remote desktop
    5432:  {"protocol_enc": 1, "length_mean": 180,  "length_std": 60,  "n": 200},  # PostgreSQL
    5900:  {"protocol_enc": 1, "length_mean": 500,  "length_std": 200, "n": 200},  # VNC remote desktop
    6379:  {"protocol_enc": 1, "length_mean": 100,  "length_std": 40,  "n": 200},  # Redis key-value
    8080:  {"protocol_enc": 1, "length_mean": 800,  "length_std": 400, "n": 200},  # HTTP alternate
    8443:  {"protocol_enc": 1, "length_mean": 800,  "length_std": 300, "n": 200},  # HTTPS alternate
    8888:  {"protocol_enc": 1, "length_mean": 700,  "length_std": 300, "n": 200},  # HTTP dev server
    9200:  {"protocol_enc": 1, "length_mean": 600,  "length_std": 250, "n": 200},  # Elasticsearch REST
    27017: {"protocol_enc": 1, "length_mean": 300,  "length_std": 100, "n": 200},  # MongoDB
    2181:  {"protocol_enc": 1, "length_mean": 150,  "length_std": 50,  "n": 200},  # Apache Zookeeper
}


# =============================================================================
# GENERATORS
# =============================================================================

def generate_port(port: int, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic normal traffic rows for a single port.

    Parameters:
        port : port number — must exist in PORT_PROFILES
        seed : base random seed for reproducibility

    Returns a DataFrame with columns:
        length, source_port, dest_port, protocol_enc, source

    The 'source' column is always 'synthetic' — used downstream
    to distinguish synthetic from real rows in combined datasets
    and to report data composition in the project report.
    """
    if port not in PORT_PROFILES:
        return pd.DataFrame()

    profile = PORT_PROFILES[port]

    # Unique seed per port ensures ports don't share identical distributions
    rng = np.random.default_rng(seed + port)
    n   = profile["n"]

    # Packet lengths: normal distribution clipped to valid Ethernet range
    lengths = rng.normal(
        loc   = profile["length_mean"],
        scale = profile["length_std"],
        size  = n
    ).clip(20, 1500).round().astype(int)

    # Ephemeral source ports: random 1024–65535 as assigned by OS
    source_ports = rng.integers(1024, 65535, size=n)

    return pd.DataFrame({
        "length":       lengths,
        "source_port":  source_ports,
        "dest_port":    port,
        "protocol_enc": profile["protocol_enc"],
        "source":       "synthetic",
    })


def generate_all(ports: list = None, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic normal traffic for all ports in PORT_PROFILES,
    or a specific subset if ports list is provided.

    Returns a combined DataFrame tagged with source='synthetic'.
    """
    target_ports = ports if ports is not None else list(PORT_PROFILES.keys())

    frames = []
    for port in target_ports:
        df = generate_port(port, seed=seed)
        if not df.empty:
            frames.append(df)

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    print(f"[+] Synthetic: {len(combined):,} rows across {len(frames)} ports")
    return combined


# =============================================================================
# ENTRY POINT — run directly to inspect synthetic output
# =============================================================================

if __name__ == "__main__":
    print("=== Cerberus — Synthetic Data Generator ===\n")

    df = generate_all()
    print(f"\nShape  : {df.shape}")
    print(f"Columns: {df.columns.tolist()}")
    print(f"\nPer-port row counts:")
    print(df.groupby("dest_port").size().to_string())
    print(f"\nSample (5 rows):\n{df.head().to_string()}")