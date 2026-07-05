#!/bin/bash

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CERBERUS_DIR="/home/blessing/Documents/cerberus"
OUTPUT_DIR="$CERBERUS_DIR/data/connections"
LOG_FILE="$CERBERUS_DIR/logs/recon.log"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

OUTFILE="$OUTPUT_DIR/conn_${TIMESTAMP}.log"

    # Header parser.py will read this to know when the snapshot was taken
echo "=== TIMESTAMP: $TIMESTAMP ===" > "$OUTFILE"
echo "" >> "$OUTFILE"

echo "--- LISTENING PORTS ---" >> "$OUTFILE"
ss -tlnp >> "$OUTFILE"

echo "" >> "$OUTFILE"
echo "--- ACTIVE CONNECTIONS ---" >> "$OUTFILE"
ss -tunp >> "$OUTFILE"

echo "" >> "$OUTFILE"
echo "--- ESTABLISHED CONNECTIONS (count by port) ---" >> "$OUTFILE"
ss -tan state established \
    | awk 'NR>1 {print $5}' \
    | cut -d: -f2 \
    | sort \
    | uniq -c \
    | sort -rn >> "$OUTFILE"

echo "[$(date)] Connection snapshot saved → conn_${TIMESTAMP}.log" >> "$LOG_FILE"