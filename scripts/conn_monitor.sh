#!/bin/bash

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$HOME/Documents/cerberus/data/connections"
LOG_FILE="$HOME/Documents/cerberus/logs/recon.log"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

OUTFILE="$OUTPUT_DIR/conn_${TIMESTAMP}.log"

echo "=== TIMESTAMP: $TIMESTAMP ===" > "$OUTFILE"
echo "" >> "$OUTFILE"

echo "--- LISTENING PORTS ---" >> "$OUTFILE"
ss -tlnp >> "$OUTFILE"

echo "" >> "$OUTFILE"
echo "--- ACTIVE CONNECTIONS ---" >> "$OUTFILE"
ss -tunp >> "$OUTFILE"

echo "" >> "$OUTFILE"
echo "--- ESTABLISHED CONNECTIONS (count by port) ---" >> "$OUTFILE"
ss -tan state established | awk 'NR>1 {print $5}' | \
    cut -d: -f2 | sort | uniq -c | sort -rn >> "$OUTFILE"

echo "[$(date)] Connection snapshot saved → conn_${TIMESTAMP}.log" >> "$LOG_FILE"
