#!/bin/bash
#
# Cerberus — scripts/conn_monitor.sh
# Phase 1: connection snapshot collector (ss -tlnp / ss -tunp).
#
# FIX: previously hardcoded CERBERUS_DIR="/home/netadmin/Documents/cerberus"
# (the Ubuntu VM's path). On Kali (blessing@cybershell), engine/config.py
# resolves BASE_DIR from the project's own location on disk, i.e.
# /home/blessing/Documents/cerberus. Because those two paths point at
# different hosts entirely, every conn_*.log file this script wrote was
# invisible to engine/parser.py — connection_snapshots never got new rows,
# no matter how often cron ran this script.
#
# Fix: self-locate CERBERUS_DIR from the script's own path, same pattern
# already used correctly in nmap_scan.sh. This makes the script portable
# across Kali and the Ubuntu VM without editing a hardcoded path, and
# still allows an explicit override via the CERBERUS_DIR env var.

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERBERUS_DIR="${CERBERUS_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

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
