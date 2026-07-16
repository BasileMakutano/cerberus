"""
Run this ON THE CERBERUS VM from the project root:
    venv/bin/python3 apply_scan_fix.py

Patches engine/profiler.py's detect_port_scan() to filter by monitored_ports,
fixing the false-positive bug where our own outbound ephemeral-port traffic
(DHCP renewals, CDN connections) was misidentified as a port scan.
"""

import re

PATH = "engine/profiler.py"

with open(PATH) as f:
    content = f.read()

OLD = '''def detect_port_scan(
    conn_rows:      list,
    window_minutes: int = SCAN_WINDOW_MINUTES,
    port_threshold: int = SCAN_PORT_THRESHOLD,
) -> list:'''

NEW = '''def detect_port_scan(
    conn_rows:       list,
    window_minutes:  int = SCAN_WINDOW_MINUTES,
    port_threshold:  int = SCAN_PORT_THRESHOLD,
    monitored_ports: set | None = None,
) -> list:'''

if OLD not in content:
    print("[!] Signature block not found verbatim — aborting, no changes made.")
    print("    Please check engine/profiler.py manually.")
    raise SystemExit(1)

content = content.replace(OLD, NEW, 1)

# Insert the monitored_ports default + filter logic into the loop body.
OLD_LOOP = '''    by_ip = defaultdict(list)

    for row in conn_rows:
        remote = str(row.get("remote_address") or "").strip()
        if not remote or remote in SCAN_IGNORE_REMOTES:
            continue

        ts   = row.get("timestamp")
        port = row.get("local_port")
        if not ts or port is None:
            continue

        try:
            dt = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            continue

        by_ip[remote].append((dt, ts, int(port)))'''

NEW_LOOP = '''    if monitored_ports is None:
        monitored_ports = set(CRITICAL_PORTS)

    by_ip = defaultdict(list)

    for row in conn_rows:
        remote = str(row.get("remote_address") or "").strip()
        if not remote or remote in SCAN_IGNORE_REMOTES:
            continue

        ts   = row.get("timestamp")
        port = row.get("local_port")
        if not ts or port is None:
            continue

        try:
            port_int = int(port)
        except (ValueError, TypeError):
            continue

        # Only count ports we actually monitor/expose. A local_port outside
        # this set means WE initiated an outbound connection (ephemeral
        # source port assigned by our own OS), not a remote host probing
        # one of our services. Without this filter, our own outbound
        # traffic to a single remote IP (e.g. the gateway, or a CDN) can
        # rack up several "distinct ports" purely from ephemeral source
        # ports and falsely look like that IP is scanning us.
        if port_int not in monitored_ports:
            continue

        try:
            dt = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            continue

        by_ip[remote].append((dt, ts, port_int))'''

if OLD_LOOP not in content:
    print("[!] Loop body not found verbatim — aborting, no changes made.")
    print("    Please check engine/profiler.py manually.")
    raise SystemExit(1)

content = content.replace(OLD_LOOP, NEW_LOOP, 1)

with open(PATH, "w") as f:
    f.write(content)

print("[+] Patch applied successfully to engine/profiler.py")
print("[+] Verifying...")

with open(PATH) as f:
    verify = f.read()

assert "monitored_ports" in verify
print("[+] Confirmed: 'monitored_ports' now present in engine/profiler.py")
