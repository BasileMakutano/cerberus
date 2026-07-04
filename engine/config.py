"""
Shared Cerberus configuration.

Keep filesystem paths here so scripts and engine modules can move with
the repository instead of assuming one user's home directory.
"""

import os
from pathlib import Path


BASE_DIR = Path(os.environ.get("CERBERUS_DIR", Path(__file__).resolve().parents[1]))
DATA_DIR = BASE_DIR / "data"
DATASET_DIR = DATA_DIR / "dataset"
SCANS_DIR = DATA_DIR / "scans"
CONNS_DIR = DATA_DIR / "connections"
LOGS_DIR = BASE_DIR / "logs"
MODELS_DIR = BASE_DIR / "models"
PORT_MODELS_DIR = MODELS_DIR / "ports"
SCRIPTS_DIR = BASE_DIR / "scripts"
DASHBOARD_DIR = BASE_DIR / "dashboard"

DB_PATH = DATA_DIR / "recon.db"
ALERTS_PATH = LOGS_DIR / "alerts.json"
RECON_LOG = LOGS_DIR / "recon.log"
CORR_LOG = LOGS_DIR / "correlation.log"
BASELINES_PATH = MODELS_DIR / "baselines.json"
PROFILES_PATH = MODELS_DIR / "port_profiles.json"
EVAL_PATH = MODELS_DIR / "evaluation.json"
SCAN_SCRIPT = SCRIPTS_DIR / "nmap_scan.sh"
SETTINGS_PATH = BASE_DIR / "settings.json"


def path_str(path: Path) -> str:
    return str(path)
