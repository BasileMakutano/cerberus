#!/bin/bash

CERBERUS_DIR="$HOME/Documents/cerberus"
SCRIPT_DIR="$CERBERUS_DIR/scripts"

# Make all scripts executable
chmod +x "$SCRIPT_DIR"/*.sh

CRON_TMP=$(mktemp)

# Preserve root's existing crontab
sudo crontab -l 2>/dev/null > "$CRON_TMP"

# Add cerberus jobs only if not already present
if ! grep -q "cerberus" "$CRON_TMP"; then
    echo "" >> "$CRON_TMP"
    echo "# === cerberus jobs ===" >> "$CRON_TMP"
    echo "*/5 * * * * $SCRIPT_DIR/nmap_scan.sh" >> "$CRON_TMP"
    echo "*/5 * * * * $SCRIPT_DIR/conn_monitor.sh" >> "$CRON_TMP"
    echo "*/10 * * * * $SCRIPT_DIR/traffic_meta.sh" >> "$CRON_TMP"
fi

sudo crontab "$CRON_TMP"
rm "$CRON_TMP"

echo "[+] Cron jobs installed. Current root crontab:"
sudo crontab -l