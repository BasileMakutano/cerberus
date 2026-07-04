#!/bin/bash
# =============================================================================
# Cerberus — cron_setup.sh
# Installs Cerberus collection scripts as root cron jobs.
# Safe to run multiple times — checks for duplicates before adding.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERBERUS_DIR="${CERBERUS_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SCRIPT_DIR="$CERBERUS_DIR/scripts"
SETTINGS_FILE="$CERBERUS_DIR/settings.json"

SCAN_INTERVAL=5
if [ -f "$SETTINGS_FILE" ]; then
    SCAN_INTERVAL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("scan_interval", 5))' "$SETTINGS_FILE" 2>/dev/null || echo 5)
fi

case "$SCAN_INTERVAL" in
    ''|*[!0-9]*) SCAN_INTERVAL=5 ;;
esac
if [ "$SCAN_INTERVAL" -lt 1 ] || [ "$SCAN_INTERVAL" -gt 60 ]; then
    SCAN_INTERVAL=5
fi

echo "[*] Making scripts executable..."
chmod +x "$SCRIPT_DIR"/*.sh

CRON_TMP=$(mktemp)

# Preserve any existing root crontab entries
sudo crontab -l 2>/dev/null > "$CRON_TMP"

# Only add if cerberus jobs are not already present
if ! grep -q "cerberus" "$CRON_TMP"; then
    echo "" >> "$CRON_TMP"
    echo "# === cerberus jobs — do not edit manually ===" >> "$CRON_TMP"
    echo "*/$SCAN_INTERVAL  * * * * $SCRIPT_DIR/nmap_scan.sh"    >> "$CRON_TMP"
    echo "*/$SCAN_INTERVAL  * * * * $SCRIPT_DIR/conn_monitor.sh" >> "$CRON_TMP"
    echo "[+] Cerberus cron jobs added."
else
    echo "[*] Cerberus cron jobs already present — skipping."
fi

sudo crontab "$CRON_TMP"
rm "$CRON_TMP"

echo ""
echo "[+] Current root crontab:"
sudo crontab -l
