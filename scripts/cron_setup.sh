#!/bin/bash
# =============================================================================
# Cerberus — cron_setup.sh
# Installs Cerberus collection scripts as root cron jobs.
# Safe to run multiple times — checks for duplicates before adding.
# =============================================================================

CERBERUS_DIR="$HOME/Documents/cerberus"
SCRIPT_DIR="$CERBERUS_DIR/scripts"

echo "[*] Making scripts executable..."
chmod +x "$SCRIPT_DIR"/*.sh

CRON_TMP=$(mktemp)

# Preserve any existing root crontab entries
sudo crontab -l 2>/dev/null > "$CRON_TMP"

# Only add if cerberus jobs are not already present
if ! grep -q "cerberus" "$CRON_TMP"; then
    echo "" >> "$CRON_TMP"
    echo "# === cerberus jobs — do not edit manually ===" >> "$CRON_TMP"
    echo "*/5  * * * * $SCRIPT_DIR/nmap_scan.sh"    >> "$CRON_TMP"
    echo "*/5  * * * * $SCRIPT_DIR/conn_monitor.sh" >> "$CRON_TMP"
    echo "[+] Cerberus cron jobs added."
else
    echo "[*] Cerberus cron jobs already present — skipping."
fi

sudo crontab "$CRON_TMP"
rm "$CRON_TMP"

echo ""
echo "[+] Current root crontab:"
sudo crontab -l