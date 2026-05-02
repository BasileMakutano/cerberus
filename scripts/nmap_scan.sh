#!/bin/bash
# =============================================================================
# Cerberus — nmap_scan.sh
# Scans 25 critical ports on the local machine every 5 minutes.
# Output: timestamped XML files in data/scans/
# Requires: root (SYN scan needs raw socket access)
# =============================================================================

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CERBERUS_DIR="/home/blessing/Documents/cerberus"
OUTPUT_DIR="$CERBERUS_DIR/data/scans"
LOG_FILE="$CERBERUS_DIR/logs/recon.log"
TARGET="192.168.100.100"

# 25 critical ports as defined in the concept note
PORTS="21,22,23,25,53,80,110,135,139,143,443,445,\
1433,1521,3306,3389,5432,5900,6379,\
8080,8443,8888,9200,27017,2181"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

echo "[$(date)] Starting nmap scan on $TARGET..." >> "$LOG_FILE"

nmap -sS \
     -sV \
     -p "$PORTS" \
     --open \
     -T4 \
     -oX "$OUTPUT_DIR/scan_${TIMESTAMP}.xml" \
     "$TARGET" >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    echo "[$(date)] Scan complete → scan_${TIMESTAMP}.xml" >> "$LOG_FILE"
else
    echo "[$(date)] ERROR: nmap scan failed. Are you running as root?" >> "$LOG_FILE"
    exit 1
fi