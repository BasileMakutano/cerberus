#!/bin/bash

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$HOME/Documents/cerberus/data/traffic"
LOG_FILE="$HOME/Documents/cerberus/logs/recon.log"
DURATION=30

mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Auto-detect active interface (skip loopback)
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if [ -z "$IFACE" ]; then
    echo "[$(date)] ERROR: No active interface found" >> "$LOG_FILE"
    exit 1
fi

echo "[$(date)] Capturing traffic on $IFACE for ${DURATION}s..." >> "$LOG_FILE"

tcpdump -i "$IFACE" \
        -nn \
        -c 500 \
        --snapshot-length=96 \
        -w "$OUTPUT_DIR/traffic_${TIMESTAMP}.pcap" \
        2>> "$LOG_FILE" &

TCPDUMP_PID=$!
sleep "$DURATION"
kill "$TCPDUMP_PID" 2>/dev/null

echo "[$(date)] Traffic capture done → traffic_${TIMESTAMP}.pcap" >> "$LOG_FILE"
