#!/bin/bash

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERBERUS_DIR="${CERBERUS_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
OUTPUT_DIR="$CERBERUS_DIR/data/scans"
LOG_FILE="$CERBERUS_DIR/logs/recon.log"
TARGET="127.0.0.1"

PORTS="21,22,23,25,53,80,110,135,139,143,443,445,\
1433,1521,3306,3389,5432,5900,6379,\
8080,8443,8888,9200,27017,2181"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

OUTFILE="$OUTPUT_DIR/scan_${TIMESTAMP}.xml"
TMPFILE="${OUTFILE}.tmp"

echo "[$(date)] Starting nmap scan on $TARGET..." >> "$LOG_FILE"

# FIX: hard-cap the whole invocation at 90s with `timeout`, in addition to
# nmap's own --host-timeout. Without this, a listener that echoes back
# probe traffic (e.g. a plain `nc -l` on a monitored port) can make -sV
# version detection hang well past the 2-minute cron interval, causing
# overlapping cron runs and killed/truncated XML output that the parser
# can never successfully ingest (see engine/parser.py invalid_xml status,
# which is retried and re-logged as an error on every future cycle since
# it's the one status that never gets marked as parsed).
#
# FIX: write to a .tmp file and only `mv` it into place after nmap exits
# successfully. mv within the same filesystem is atomic, so the parser
# (which globs scan_*.xml) will never see a partially-written file — it
# either sees the complete final XML or nothing at all.
timeout 90 nmap -sS \
     -sV \
     --host-timeout 60s \
     -p "$PORTS" \
     --open \
     -T4 \
     -oX "$TMPFILE" \
     "$TARGET" >> "$LOG_FILE" 2>&1

NMAP_EXIT=$?

if [ $NMAP_EXIT -eq 0 ] && [ -s "$TMPFILE" ]; then
    mv "$TMPFILE" "$OUTFILE"
    echo "[$(date)] Scan complete → scan_${TIMESTAMP}.xml" >> "$LOG_FILE"
elif [ $NMAP_EXIT -eq 124 ]; then
    echo "[$(date)] ERROR: nmap scan timed out after 90s — discarding partial output." >> "$LOG_FILE"
    rm -f "$TMPFILE"
    exit 1
elif [ $NMAP_EXIT -eq 0 ]; then
    echo "[$(date)] ERROR: nmap exited 0 but produced no output — discarding empty file." >> "$LOG_FILE"
    rm -f "$TMPFILE"
    exit 1
else
    echo "[$(date)] ERROR: nmap scan failed (exit $NMAP_EXIT). Are you running as root?" >> "$LOG_FILE"
    rm -f "$TMPFILE"
    exit 1
fi
