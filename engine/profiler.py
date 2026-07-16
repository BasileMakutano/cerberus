import sqlite3
import json
import os
import sys
from datetime import datetime, timezone
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.db import BASE_DIR, DB_PATH


PROFILES_PATH  = os.path.join(BASE_DIR, "models", "port_profiles.json")
MIN_SCANS      = 5     # minimum scans before a port gets a profile
STD_MULTIPLIER = 2.0   # mean ± 2σ for thresholds (~95% of normal)

CRITICAL_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888,
    9200, 27017, 2181
]

# ── Port-scan detection tuning ───────────────────────────────────────────────
# Vertical scan = one source IP touching many distinct destination ports
# within a short rolling window. These are separate from per-port baseline
# checks — this is a cross-port aggregate pattern.
SCAN_WINDOW_MINUTES = 5    # rolling window to count distinct ports in
SCAN_PORT_THRESHOLD = 5    # distinct ports within window → SCAN_DETECTED

# Local/self traffic that should never count toward a scan signature —
# e.g. the dashboard's own control port, or addresses that are not real
# remote peers (ss reports these on LISTEN rows with no actual remote peer).
SCAN_IGNORE_REMOTES = {"0.0.0.0", "::", "127.0.0.1", "Address:Port", ""}


# =============================================================================
# DATABASE READS
# =============================================================================

def _get_db() -> sqlite3.Connection:
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(
            f"recon.db not found at {DB_PATH}. "
            f"Run Phase 2 (parser) first to populate the database."
        )
    uri  = f"file:{DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _load_port_observations(conn: sqlite3.Connection) -> list:
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            timestamp,
            ip,
            port,
            protocol,
            state,
            service,
            version
        FROM port_observations
        WHERE state = 'open'
        ORDER BY timestamp ASC
    """)
    return cursor.fetchall()


def _load_connection_snapshots(conn: sqlite3.Connection) -> list:
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            timestamp,
            local_address,
            local_port,
            remote_address,
            remote_port,
            state,
            process
        FROM connection_snapshots
        WHERE local_port > 0
        ORDER BY timestamp ASC
    """)
    return cursor.fetchall()


# =============================================================================
# FREQUENCY ANALYSIS
# =============================================================================

def _compute_hourly_frequency(timestamps: list) -> dict:

    if not timestamps:
        return {}

    # Group by hour bucket
    hourly = defaultdict(int)
    for ts in timestamps:
        try:
            dt   = datetime.fromisoformat(ts)
            hour = dt.strftime("%Y-%m-%dT%H")
            hourly[hour] += 1
        except (ValueError, TypeError):
            continue

    if not hourly:
        return {}

    counts = list(hourly.values())
    n      = len(counts)
    mean   = sum(counts) / n
    variance = sum((c - mean) ** 2 for c in counts) / n if n > 1 else 0.0
    std    = variance ** 0.5
    std    = std if std > 0 else 1.0   # avoid zero-width window

    return {
        "mean":           round(mean, 4),
        "std":            round(std, 4),
        "min":            min(counts),
        "max":            max(counts),
        "lower":          round(max(0.0, mean - STD_MULTIPLIER * std), 4),
        "upper":          round(mean + STD_MULTIPLIER * std, 4),
        "hours_observed": n,
    }


# =============================================================================
# PER-PORT PROFILE BUILDER
# =============================================================================

def _build_port_profile(
    port:         int,
    observations: list,
    connections:  list,
) -> dict:
    n = len(observations)

    if n < MIN_SCANS:
        return {
            "port":               port,
            "status":             "insufficient_data",
            "total_observations": n,
            "confidence":         "LOW",
            "note": (
                f"Only {n} observations. Need at least {MIN_SCANS} "
                f"before this port has a reliable behavioural profile. "
                f"Keep collecting data."
            )
        }

    # ── Timestamps ────────────────────────────────────────────────────────
    timestamps  = [row["timestamp"] for row in observations]
    first_seen  = min(timestamps)
    last_seen   = max(timestamps)

    # ── Known IPs ─────────────────────────────────────────────────────────
    # These are the IPs nmap found this port open on.
    # In a typical lab setup this is just your Ubuntu VM IP.
    # Any new IP not in this list is suspicious.
    known_ips = sorted(set(
        row["ip"] for row in observations
        if row["ip"] and row["ip"] != "unknown"
    ))

    # ── Service intelligence ───────────────────────────────────────────────
    # What service names has nmap reported on this port?
    # We track all of them but flag the dominant one as expected.
    # If nmap suddenly reports a different service, that's suspicious.
    service_counts = defaultdict(int)
    for row in observations:
        svc = (row["service"] or "unknown").strip().lower()
        service_counts[svc] += 1

    expected_service = max(service_counts, key=service_counts.get)
    all_services     = dict(sorted(
        service_counts.items(), key=lambda x: x[1], reverse=True
    ))

    # ── Protocol intelligence ──────────────────────────────────────────────
    protocol_counts = defaultdict(int)
    for row in observations:
        proto = (row["protocol"] or "unknown").strip().lower()
        protocol_counts[proto] += 1

    expected_protocol = max(protocol_counts, key=protocol_counts.get)

    # ── Version strings ────────────────────────────────────────────────────
    # Track all version strings nmap has reported.
    # A sudden version change could indicate service replacement.
    versions_seen = sorted(set(
        row["version"].strip()
        for row in observations
        if row["version"] and row["version"].strip()
    ))

    # ── Hourly frequency (from port_observations) ──────────────────────────
    frequency = _compute_hourly_frequency(timestamps)

    # ── Connection snapshot intelligence ──────────────────────────────────
    # From ss output: processes, states, remote IPs
    known_processes     = set()
    known_states        = set()
    known_remote_ips    = set()
    conn_timestamps     = []

    for row in connections:
        process = (row["process"] or "").strip()
        state   = (row["state"]   or "").strip()
        remote  = (row["remote_address"] or "").strip()

        if process and process not in ("", "*"):
            # ss wraps process in brackets e.g. 'users:(("sshd",pid=123))'
            # Extract just the process name
            if "((" in process:
                try:
                    proc_name = process.split("((")[1].split(",")[0].strip('"')
                    known_processes.add(proc_name)
                except IndexError:
                    known_processes.add(process)
            else:
                known_processes.add(process)

        if state and state not in ("", "*"):
            known_states.add(state)

        if remote and remote not in ("", "*", "0.0.0.0", "::"):
            known_remote_ips.add(remote)

        if row["timestamp"]:
            conn_timestamps.append(row["timestamp"])

    # Hourly connection frequency from ss snapshots
    conn_frequency = _compute_hourly_frequency(conn_timestamps)

    # ── Presence consistency ───────────────────────────────────────────────
    # How consistently was this port open across all scans?
    # A port that is always open should raise an alert if it disappears.
    # A port that is rarely open is less reliable as a baseline.
    #
    # We calculate this as: observations / (hours_observed * scans_per_hour)
    # scans_per_hour = 12 (one scan every 5 minutes)
    hours_observed    = frequency.get("hours_observed", 1)
    expected_max_scans = hours_observed * 12
    presence_rate     = round(n / expected_max_scans, 4) if expected_max_scans > 0 else 0.0
    presence_rate     = min(presence_rate, 1.0)  # cap at 100%

    # ── Confidence ────────────────────────────────────────────────────────
    if n >= 100 and hours_observed >= 10:
        confidence = "HIGH"
    elif n >= MIN_SCANS:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "port":               port,
        "status":             "ok",
        "confidence":         confidence,
        "total_observations": n,
        "first_seen":         first_seen,
        "last_seen":          last_seen,

        # IP intelligence
        "known_ips": {
            "list":  known_ips,
            "count": len(known_ips),
        },

        # Service intelligence
        "service": {
            "expected":    expected_service,
            "all_seen":    all_services,
            "versions":    versions_seen,
        },

        # Protocol intelligence
        "protocol": {
            "expected": expected_protocol,
            "all_seen": dict(protocol_counts),
        },

        # Hourly frequency from nmap scans
        "scan_frequency": frequency,

        # Hourly frequency from ss connection snapshots
        "connection_frequency": conn_frequency,

        # Connection snapshot intelligence
        "connections": {
            "known_processes":  sorted(known_processes),
            "known_states":     sorted(known_states),
            "known_remote_ips": sorted(known_remote_ips),
        },

        # Presence consistency
        "presence": {
            "rate":        presence_rate,
            "description": (
                "consistently open" if presence_rate >= 0.8
                else "intermittently open" if presence_rate >= 0.3
                else "rarely open"
            ),
        },
    }


# =============================================================================
# BUILD ALL PROFILES
# =============================================================================

def build_all_profiles() -> dict:
    """
    Build behavioural profiles for all 25 critical ports plus any
    additional ports discovered during live scanning.

    Steps:
        1. Load all open port observations from SQLite
        2. Load all connection snapshots from SQLite
        3. Group both by port number
        4. Build a profile for each port found
        5. Also attempt profiles for CRITICAL_PORTS with no data
           (marked insufficient_data so correlator skips them)
        6. Save to models/port_profiles.json

    Returns the full profiles dict.
    """
    print("=== Cerberus — Behavioural Profiler ===\n")

    # ── Load data ─────────────────────────────────────────────────────────
    try:
        conn = _get_db()
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    print("[*] Loading port observations from SQLite...")
    observations = _load_port_observations(conn)
    print(f"[+] Loaded {len(observations):,} open port observations")

    print("[*] Loading connection snapshots from SQLite...")
    connections = _load_connection_snapshots(conn)
    print(f"[+] Loaded {len(connections):,} connection snapshots")
    conn.close()

    if not observations:
        print("\n[!] No open port observations found in recon.db.")
        print("    Run the Bash collectors first, then the parser.")
        sys.exit(1)

    # ── Group by port ─────────────────────────────────────────────────────
    obs_by_port  = defaultdict(list)
    conn_by_port = defaultdict(list)

    for row in observations:
        obs_by_port[row["port"]].append(row)

    for row in connections:
        conn_by_port[row["local_port"]].append(row)

    # ── Discovered ports (found in live scans, may not be in CRITICAL_PORTS)
    discovered_ports = sorted(obs_by_port.keys())

    # ── All ports to profile ───────────────────────────────────────────────
    # Critical ports + any additional ports discovered in live scans
    all_ports = sorted(set(CRITICAL_PORTS) | set(discovered_ports))

    print(f"\n[*] Profiling {len(all_ports)} ports...")
    print(f"    Critical ports    : {len(CRITICAL_PORTS)}")
    print(f"    Discovered ports  : {len(discovered_ports)}")
    if set(discovered_ports) - set(CRITICAL_PORTS):
        extra = sorted(set(discovered_ports) - set(CRITICAL_PORTS))
        print(f"    Extra (not in critical list): {extra}")
    print()

    profiles = {}
    ok_ports  = []
    low_ports = []

    for port in all_ports:
        port_obs   = obs_by_port.get(port, [])
        port_conns = conn_by_port.get(port, [])

        profile = _build_port_profile(port, port_obs, port_conns)
        profiles[str(port)] = profile

        if profile["status"] == "ok":
            ok_ports.append(port)
            freq  = profile["scan_frequency"]
            print(
                f"  [+] Port {port:>5} | "
                f"{profile['total_observations']:>4} obs | "
                f"{profile['confidence']:<6} | "
                f"service: {profile['service']['expected']:<12} | "
                f"proto: {profile['protocol']['expected']:<4} | "
                f"known IPs: {profile['known_ips']['count']} | "
                f"freq/hr: {freq.get('mean', 0):.1f} "
                f"[upper: {freq.get('upper', 0):.1f}]"
            )
        else:
            low_ports.append(port)
            print(
                f"  [!] Port {port:>5} | "
                f"{profile['total_observations']:>4} obs | "
                f"insufficient data — needs {MIN_SCANS}+ scans"
            )

    # ── Save ──────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(PROFILES_PATH), exist_ok=True)
    with open(PROFILES_PATH, "w") as f:
        json.dump(profiles, f, indent=2, default=str)

    print(f"\n[+] Profiles saved → {PROFILES_PATH}")
    print(f"\n--- Summary ---")
    print(f"  Ports profiled (ok)          : {len(ok_ports)}  → {ok_ports}")
    print(f"  Ports with insufficient data : {len(low_ports)}")
    if low_ports:
        print(f"  Insufficient ports           : {low_ports}")
    print(
        f"\n  Note: Ports with insufficient data will be skipped by the "
        f"correlator until more scan data is collected."
    )

    return profiles


# =============================================================================
# PROFILE LOADER  (used by Phase 6 correlator)
# =============================================================================

def load_profiles() -> dict:
    """
    Load port_profiles.json from disk.
    Returns empty dict if file does not exist.
    Called once at startup by the correlator.
    """
    if not os.path.exists(PROFILES_PATH):
        print("[!] port_profiles.json not found. Run profiler first.")
        return {}

    with open(PROFILES_PATH, "r") as f:
        return json.load(f)


# =============================================================================
# BEHAVIOURAL CHECKER  (used by Phase 6 correlator)
# =============================================================================

def check_observation(observation: dict, profiles: dict) -> dict:
    port     = int(observation.get("port", -1))
    ip       = str(observation.get("ip", "")).strip()
    service  = str(observation.get("service", "")).strip().lower()
    protocol = str(observation.get("protocol", "")).strip().lower()
    version  = str(observation.get("version", "")).strip()

    profile  = profiles.get(str(port))

    # ── Unknown port — highest severity ───────────────────────────────────
    if profile is None or profile.get("status") != "ok":
        return {
            "port":       port,
            "flagged":    True,
            "severity":   "HIGH",
            "triggers":   [{
                "type":    "UNKNOWN_PORT",
                "detail":  f"Port {port} has no established behavioural profile",
                "expected": "Port should not be open",
                "observed": f"Port {port} found open",
            }],
            "confidence": "LOW",
        }

    triggers = []

    # ── Check 1: Unknown IP ───────────────────────────────────────────────
    known_ips = profile["known_ips"]["list"]
    if ip and known_ips and ip not in known_ips:
        triggers.append({
            "type":     "UNKNOWN_IP",
            "detail":   f"IP {ip} has never been seen on port {port}",
            "expected": f"Known IPs: {known_ips}",
            "observed": ip,
        })

    # ── Check 2: Wrong service ────────────────────────────────────────────
    expected_svc = profile["service"]["expected"]
    if service and service != "unknown" and service != expected_svc:
        triggers.append({
            "type":     "WRONG_SERVICE",
            "detail":   f"Service mismatch on port {port}",
            "expected": expected_svc,
            "observed": service,
        })

    # ── Check 3: Wrong protocol ───────────────────────────────────────────
    expected_proto = profile["protocol"]["expected"]
    if protocol and protocol != "unknown" and protocol != expected_proto:
        triggers.append({
            "type":     "WRONG_PROTOCOL",
            "detail":   f"Protocol mismatch on port {port}",
            "expected": expected_proto,
            "observed": protocol,
        })

    # ── Check 4: New version string ───────────────────────────────────────
    known_versions = profile["service"]["versions"]
    if version and known_versions and version not in known_versions:
        triggers.append({
            "type":     "NEW_VERSION",
            "detail":   f"New service version detected on port {port}",
            "expected": f"Known versions: {known_versions}",
            "observed": version,
        })

    # ── Determine severity ────────────────────────────────────────────────
    trigger_types = [t["type"] for t in triggers]

    if "WRONG_SERVICE" in trigger_types or "WRONG_PROTOCOL" in trigger_types:
        severity = "HIGH"
    elif "UNKNOWN_IP" in trigger_types or "FREQUENCY_SPIKE" in trigger_types:
        severity = "MEDIUM"
    elif triggers:
        severity = "LOW"
    else:
        severity = "NONE"

    return {
        "port":       port,
        "flagged":    len(triggers) > 0,
        "severity":   severity,
        "triggers":   triggers,
        "confidence": profile["confidence"],
    }


def check_frequency(port: int, current_count: int, profiles: dict) -> dict:
    profile = profiles.get(str(port))
    if not profile or profile.get("status") != "ok":
            return {
            "flagged": False,
            "triggers": [],
            "severity": "LOW",
            "confidence": "LOW"
    }
    freq  = profile.get("scan_frequency", {})
    upper = freq.get("upper", None)

    if upper is None:
        return {
        "flagged": False,
        "triggers": [],
        "severity": "LOW",
        "confidence": "LOW"
    }

    if current_count > upper:
        return {
        "flagged": True,
        "triggers": [{
            "type": "FREQUENCY_SPIKE",
            "detail": f"Connection count for port {port} exceeds threshold",
            "expected": f"Upper threshold: {upper:.1f}/hr",
            "observed": f"{current_count}/hr"
        }],
        "severity": "MEDIUM",
        "confidence": profile.get("confidence", "LOW")
    }

    return {
    "flagged": False,
    "triggers": [],
    "severity": "LOW",
    "confidence": profile.get("confidence", "LOW")
}


# =============================================================================
# VERTICAL PORT-SCAN DETECTION  (Phase 6 correlator — cross-port pattern)
# =============================================================================

def detect_port_scan(
    conn_rows:       list,
    window_minutes:  int = SCAN_WINDOW_MINUTES,
    port_threshold:  int = SCAN_PORT_THRESHOLD,
    monitored_ports: set | None = None,
) -> list:
    if monitored_ports is None:
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

        by_ip[remote].append((dt, ts, port_int))

    events = []

    for ip, hits in by_ip.items():
        hits.sort(key=lambda x: x[0])

        window_start_dt = None
        window_start_ts = None
        ports_in_window  = set()
        tripped          = False

        for dt, ts, port in hits:
            if window_start_dt is None:
                window_start_dt = dt
                window_start_ts = ts
                ports_in_window = {port}
                continue

            if (dt - window_start_dt).total_seconds() <= window_minutes * 60:
                ports_in_window.add(port)
            else:
                # Window expired — start a new one from this hit
                window_start_dt = dt
                window_start_ts = ts
                ports_in_window = {port}

            if len(ports_in_window) >= port_threshold:
                events.append({
                    "ip":         ip,
                    "type":       "SCAN_DETECTED",
                    "detail": (
                        f"{len(ports_in_window)} distinct ports touched by "
                        f"{ip} within {window_minutes} min "
                        f"(window {window_start_ts} → {ts})"
                    ),
                    "ports":      sorted(ports_in_window),
                    "window_end": ts,
                })
                tripped = True
                break  # one event per IP per call is enough

        if tripped:
            continue

    return events


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    profiles = build_all_profiles()

    # Show sample profile for the most-observed port
    ok = {
        k: v for k, v in profiles.items()
        if v.get("status") == "ok"
    }
    if ok:
        sample_port = max(ok, key=lambda k: ok[k]["total_observations"])
        print(f"\n--- Sample profile (port {sample_port}) ---")
        print(json.dumps(profiles[sample_port], indent=2, default=str))