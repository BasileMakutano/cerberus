# Cerberus

> Adaptive network reconnaissance and threat detection using behavioural analysis and machine learning.

Cerberus continuously monitors your network, learns what normal looks like, and alerts you the moment something deviates. Like its namesake, nothing gets past unnoticed.

---

## What it does

Most lightweight security tools rely on fixed rules — they only catch what they already know. Cerberus takes a different approach: it first learns your network's normal behaviour, then flags anything that doesn't fit. No predefined attack signatures required.

It does this in five stages:

1. **Collects** — Bash scripts run on a schedule, scanning ports and capturing connection snapshots via `nmap`, `ss`, and `tcpdump`
2. **Parses** — A Python engine reads the raw scan output and stores structured observations in a local SQLite database
3. **Baselines** — For each of 25 critical ports, Cerberus builds a statistical profile of normal activity (frequency, connection counts, typical patterns)
4. **Detects** — An Isolation Forest model identifies observations that deviate from the learned baseline
5. **Alerts** — Anomalies are written to a structured log and surfaced through a lightweight HTML dashboard

---

## Who it's for

Cerberus is designed for small-scale and academic environments where enterprise tools like SIEM or XDR are too complex or costly to deploy. It runs entirely on a local Linux machine with no cloud dependency.

---

## Stack

| Layer             | Tools                                  |
| ----------------- | -------------------------------------- |
| Data collection   | Bash, `nmap`, `ss`, `tcpdump`          |
| Parsing & storage | Python, SQLite, Pandas                 |
| ML detection      | Scikit-learn (Isolation Forest), NumPy |
| Dashboard         | HTML, CSS, JavaScript                  |
| Platform          | Kali Linux                             |

---

## Project structure

```
cerberus/
├── scripts/          # Bash: data collection + cron setup
├── engine/           # Python: parser, baseline, detector, alerter
├── models/           # Saved ML model + per-port baselines
├── data/             # Raw scans, connection logs, SQLite DB
├── dashboard/        # HTML/JS alert dashboard
├── logs/             # Alert output (alerts.json)
└── main.py           # Entry point
```

---

## Getting started

```bash
# Clone the repo
git clone https://github.com/BasileMakutano/cerberus.git
cd cerberus

# Install Python dependencies
pip install -r requirements.txt --break-system-packages

# Deploy and start data collection
sudo bash scripts/cron_setup.sh

# After 3–7 days of data collection, run the full pipeline
sudo python3 main.py
```

> `nmap` SYN scanning requires root. Run collection scripts and `main.py` with `sudo`.

---

## Important notes

- Cerberus is intended for use on **local or simulated networks only** — not production environments
- It uses **unsupervised** anomaly detection — no labelled attack data needed
- Deep packet inspection, automated blocking, and enterprise-scale deployment are out of scope

---

## Author

**Basile Makutano Musavuli** — BSc Computer Networks & Cybersecurity, Strathmore University
