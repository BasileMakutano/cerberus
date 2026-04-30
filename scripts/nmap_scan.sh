#!/bin/bash

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$HOME/Documents/cerberus/data/scans"
LOG_FILE="$HOME/Documents/cerberus/logs/recon.log"
TARGET="127.0.0.1"
PORTS="21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017,2181"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

echo "[$(date)] Starting nmap scan..." >> "$LOG_FILE"

nmap -sS -sV \
     -p "$PORTS" \
     --open \
     -T4 \
     -oX "$OUTPUT_DIR/scan_${TIMESTAMP}.xml" \
     "$TARGET" >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    echo "[$(date)] Scan complete → scan_${TIMESTAMP}.xml" >> "$LOG_FILE"
else
    echo "[$(date)] ERROR: nmap scan failed" >> "$LOG_FILE"
fi