#!/bin/bash
#
# Cerberus — scripts/cron_setup.sh
# Installs root cron jobs for Phase 1 collection AND the parse/correlate/
# alert cycle that consumes what Phase 1 produces.
#
# FIX: the previous version only scheduled nmap_scan.sh and conn_monitor.sh
# (Phase 1). Nothing ever called main.py to parse the resulting scan_*.xml /
# conn_*.log files into recon.db, so port_observations / connection_snapshots
# never grew on their own — the DB, baselines, alerts.json, and therefore the
# dashboard only updated when someone manually ran a cycle from the Pipeline
# view or the terminal. Recon looked like it was "running" (files piling up,
# recon.log growing) while nothing downstream of Phase 1 ever moved.
#
# Fix: add a third cron entry that runs `main.py --alert-only` (which itself
# was fixed to run Phase 2 parsing before correlating — see main.py). It's
# offset by 1 minute and runs every 2 minutes so it always has at least one
# fresh nmap/ss snapshot to ingest before correlating, rather than racing the
# collectors on the exact same minute mark.
#
# Note: this installs into ROOT's crontab, same as before, so nmap_scan.sh
# can perform its SYN scan (-sS) without needing setcap/sudoers tricks in
# cron context. As a side effect, data/, logs/, and recon.db will be root-
# owned. If you also run main.py or the Flask dashboard manually as your own
# user, you may need:
#   sudo chown -R "$USER:$USER" "$HOME/Documents/cerberus"
# after cron has run at least once, if you hit permission errors doing so.

CERBERUS_DIR="$HOME/Documents/cerberus"
SCRIPT_DIR="$CERBERUS_DIR/scripts"
VENV_PYTHON="$CERBERUS_DIR/venv/bin/python3"
MAIN_PY="$CERBERUS_DIR/main.py"
CRON_LOG="$CERBERUS_DIR/logs/cron_alert_cycle.log"

echo "[*] Making scripts executable..."
chmod +x "$SCRIPT_DIR"/*.sh

if [ ! -x "$VENV_PYTHON" ]; then
    echo "[!] WARNING: venv python not found at $VENV_PYTHON"
    echo "    The alert-cycle cron job will fail until the venv exists."
fi

mkdir -p "$CERBERUS_DIR/logs"

CRON_TMP=$(mktemp)

# Preserve any existing root crontab entries
sudo crontab -l 2>/dev/null > "$CRON_TMP"

# Only add if cerberus jobs are not already present
if ! grep -q "cerberus" "$CRON_TMP"; then
    echo "" >> "$CRON_TMP"
    echo "# === cerberus jobs — do not edit manually ===" >> "$CRON_TMP"
    echo "*/1  * * * * $SCRIPT_DIR/nmap_scan.sh"    >> "$CRON_TMP"
    echo "*/1  * * * * $SCRIPT_DIR/conn_monitor.sh" >> "$CRON_TMP"
    # Phase 2/6/7: parse newly-collected files, correlate, alert.
    # Offset by 1 minute past the hour boundary so it runs after the
    # collectors have had a chance to write at least one fresh file.
    echo "1-59/2  * * * * $VENV_PYTHON $MAIN_PY --alert-only >> $CRON_LOG 2>&1" >> "$CRON_TMP"
    echo "[+] Cerberus cron jobs added (scan + conn_monitor + alert-cycle)."
else
    echo "[*] Cerberus cron jobs already present — skipping."
    echo "    If you're re-running this after fixing main.py/paths, remove"
    echo "    the existing '# === cerberus jobs ===' block with:"
    echo "        sudo crontab -e"
    echo "    then re-run this script to reinstall with the current paths."
fi

sudo crontab "$CRON_TMP"
rm "$CRON_TMP"

echo ""
echo "[+] Current root crontab:"
sudo crontab -l
