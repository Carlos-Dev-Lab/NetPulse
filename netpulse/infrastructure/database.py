"""
NetPulse — SQLite Database (aggregated stats only)
Per-second summaries are stored — never individual packets.
Uses WAL mode for concurrent reads/writes.
"""
import sqlite3
import json
import ipaddress
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from netpulse.domain.network_scan import (
    NetworkScan,
    ScanFinding,
    ScanHost,
    ScanService,
)

# ── Schema ────────────────────────────────────────────────────────────────────
_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time      TEXT    NOT NULL,
    end_time        TEXT,
    interface       TEXT    NOT NULL DEFAULT 'All',
    total_pkts      INTEGER DEFAULT 0,
    total_bytes_in  INTEGER DEFAULT 0,
    total_bytes_out INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    ts          TEXT    NOT NULL,
    bytes_in    INTEGER DEFAULT 0,
    bytes_out   INTEGER DEFAULT 0,
    pkts_in     INTEGER DEFAULT 0,
    pkts_out    INTEGER DEFAULT 0,
    n_tcp       INTEGER DEFAULT 0,
    n_udp       INTEGER DEFAULT 0,
    n_https     INTEGER DEFAULT 0,
    n_http      INTEGER DEFAULT 0,
    n_dns       INTEGER DEFAULT 0,
    n_icmp      INTEGER DEFAULT 0,
    n_other     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS top_ips (
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    ip          TEXT    NOT NULL,
    total_bytes INTEGER DEFAULT 0,
    total_pkts  INTEGER DEFAULT 0,
    last_seen   TEXT,
    PRIMARY KEY (session_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_stats_session ON stats(session_id, ts);

CREATE TABLE IF NOT EXISTS quality_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    interface TEXT,
    gateway TEXT,
    received INTEGER NOT NULL,
    samples INTEGER NOT NULL,
    latency_ms REAL,
    jitter_ms REAL,
    loss_percent REAL,
    dns_ms REAL,
    internet_reachable INTEGER
);
CREATE INDEX IF NOT EXISTS idx_quality_checks_ts ON quality_checks(ts);

CREATE TABLE IF NOT EXISTS network_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    target          TEXT NOT NULL,
    profile         TEXT NOT NULL,
    command         TEXT,
    nmap_version    TEXT,
    duration_seconds REAL DEFAULT 0,
    host_count      INTEGER DEFAULT 0,
    open_port_count INTEGER DEFAULT 0,
    risk_score      INTEGER DEFAULT 0,
    risk_level      TEXT DEFAULT 'low'
);

CREATE TABLE IF NOT EXISTS scan_hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES network_scans(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    status      TEXT,
    hostname    TEXT,
    mac         TEXT,
    vendor      TEXT,
    os_name     TEXT,
    latency_ms  REAL,
    risk_score  INTEGER DEFAULT 0,
    risk_level  TEXT DEFAULT 'low'
    ,device_id  INTEGER REFERENCES inventory_devices(id)
);

CREATE TABLE IF NOT EXISTS scan_services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES scan_hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    state       TEXT,
    name        TEXT,
    product     TEXT,
    version     TEXT,
    extra_info  TEXT,
    tunnel      TEXT,
    risk_level  TEXT DEFAULT 'low',
    risk_reason TEXT
);

CREATE TABLE IF NOT EXISTS scan_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES network_scans(id) ON DELETE CASCADE,
    severity    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    host        TEXT,
    title       TEXT NOT NULL,
    detail      TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_network_scans_target ON network_scans(target, started_at);
CREATE INDEX IF NOT EXISTS idx_scan_hosts_scan ON scan_hosts(scan_id, address);
CREATE INDEX IF NOT EXISTS idx_scan_services_host ON scan_services(host_id, port);
CREATE INDEX IF NOT EXISTS idx_scan_alerts_scan ON scan_alerts(scan_id, severity);

CREATE TABLE IF NOT EXISTS device_inventory (
    address         TEXT PRIMARY KEY,
    mac             TEXT,
    detected_name   TEXT,
    alias           TEXT,
    device_type     TEXT DEFAULT 'unknown',
    owner           TEXT,
    location        TEXT,
    notes           TEXT,
    trust_status    TEXT DEFAULT 'new',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    last_scan_id    INTEGER REFERENCES network_scans(id)
);

CREATE INDEX IF NOT EXISTS idx_inventory_mac ON device_inventory(mac);
CREATE INDEX IF NOT EXISTS idx_inventory_trust ON device_inventory(trust_status);

CREATE TABLE IF NOT EXISTS inventory_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT,
    current_address TEXT NOT NULL,
    detected_name   TEXT,
    alias           TEXT,
    device_type     TEXT DEFAULT 'unknown',
    owner           TEXT,
    location        TEXT,
    notes           TEXT,
    trust_status    TEXT DEFAULT 'new',
    identity_source TEXT DEFAULT 'ip',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    last_scan_id    INTEGER REFERENCES network_scans(id)
    ,criticality     TEXT DEFAULT 'medium'
    ,lifecycle_status TEXT DEFAULT 'new'
    ,tags            TEXT DEFAULT ''
    ,last_reviewed   TEXT
    ,identity_confidence TEXT DEFAULT 'low'
    ,review_required INTEGER DEFAULT 1
    ,merged_into_device_id INTEGER REFERENCES inventory_devices(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_devices_mac
ON inventory_devices(mac COLLATE NOCASE) WHERE mac IS NOT NULL AND mac <> '';
CREATE INDEX IF NOT EXISTS idx_inventory_devices_address
ON inventory_devices(current_address, last_seen DESC);

CREATE TABLE IF NOT EXISTS device_ip_history (
    device_id    INTEGER NOT NULL REFERENCES inventory_devices(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    last_scan_id INTEGER REFERENCES network_scans(id),
    PRIMARY KEY (device_id, address)
);

CREATE TABLE IF NOT EXISTS asset_observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL REFERENCES inventory_devices(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    value           TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'nmap',
    confidence      TEXT NOT NULL DEFAULT 'medium',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    last_scan_id    INTEGER REFERENCES network_scans(id),
    metadata        TEXT DEFAULT '',
    UNIQUE(device_id, kind, normalized_value)
);
CREATE INDEX IF NOT EXISTS idx_asset_observation_lookup
ON asset_observations(kind, normalized_value, last_seen DESC);

CREATE TABLE IF NOT EXISTS asset_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES inventory_devices(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    scan_id     INTEGER REFERENCES network_scans(id),
    severity    TEXT DEFAULT 'info',
    summary     TEXT NOT NULL,
    details     TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_asset_events_device
ON asset_events(device_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS asset_merge_suggestions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_a_id INTEGER NOT NULL REFERENCES inventory_devices(id),
    device_b_id INTEGER NOT NULL REFERENCES inventory_devices(id),
    score       INTEGER NOT NULL,
    reasons     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE(device_a_id, device_b_id, status)
);

CREATE TABLE IF NOT EXISTS scan_profiles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    target      TEXT NOT NULL,
    profile     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_schedules (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id          INTEGER NOT NULL REFERENCES scan_profiles(id) ON DELETE CASCADE,
    interval_minutes    INTEGER NOT NULL,
    enabled             INTEGER NOT NULL DEFAULT 1,
    notify_changes_only INTEGER NOT NULL DEFAULT 1,
    last_run            TEXT,
    next_run            TEXT NOT NULL,
    last_status         TEXT,
    last_error          TEXT
);

CREATE INDEX IF NOT EXISTS idx_schedules_due ON scan_schedules(enabled, next_run);
"""


class DB:
    """Thread-safe SQLite wrapper (check_same_thread=False)."""

    def __init__(self, path: str | Path = "netpulse.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._cx() as c:
            c.executescript(_SCHEMA)
            self._migrate_asset_schema(c)
            c.execute(
                """INSERT OR IGNORE INTO inventory_devices
                   (mac,current_address,detected_name,alias,device_type,owner,
                    location,notes,trust_status,identity_source,first_seen,last_seen,last_scan_id,
                    lifecycle_status,identity_confidence,review_required)
                   SELECT NULLIF(mac,''),address,detected_name,alias,device_type,owner,
                          location,notes,trust_status,
                          CASE WHEN mac<>'' THEN 'mac' ELSE 'ip' END,
                          first_seen,last_seen,last_scan_id,
                          CASE trust_status WHEN 'authorized' THEN 'authorized'
                            WHEN 'blocked' THEN 'blocked' WHEN 'known' THEN 'observing'
                            ELSE 'new' END,
                          CASE WHEN mac<>'' THEN 'high' ELSE 'low' END,
                          CASE WHEN mac<>'' THEN 0 ELSE 1 END
                   FROM device_inventory legacy
                   WHERE NOT EXISTS (
                       SELECT 1 FROM inventory_devices current
                       WHERE (legacy.mac<>'' AND current.mac=legacy.mac COLLATE NOCASE)
                          OR (legacy.mac='' AND current.mac IS NULL
                              AND current.current_address=legacy.address)
                   )"""
            )
            self._seed_asset_observations(c)
            c.execute("DROP TABLE IF EXISTS device_inventory")

    @staticmethod
    def _add_column(c, table: str, definition: str) -> bool:
        name = definition.split()[0]
        columns = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
        if name not in columns:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
            return True
        return False

    def _migrate_asset_schema(self, c) -> None:
        added = {}
        for definition in (
            "criticality TEXT DEFAULT 'medium'",
            "lifecycle_status TEXT DEFAULT 'new'",
            "tags TEXT DEFAULT ''",
            "last_reviewed TEXT",
            "identity_confidence TEXT DEFAULT 'low'",
            "review_required INTEGER DEFAULT 1",
            "merged_into_device_id INTEGER REFERENCES inventory_devices(id)",
        ):
            added[definition.split()[0]] = self._add_column(
                c, "inventory_devices", definition
            )
        self._add_column(c, "scan_hosts", "device_id INTEGER REFERENCES inventory_devices(id)")
        if added.get("lifecycle_status") or added.get("identity_confidence"):
            c.execute(
                """UPDATE inventory_devices SET
                 lifecycle_status=CASE WHEN ? THEN CASE trust_status
                   WHEN 'authorized' THEN 'authorized'
                   WHEN 'blocked' THEN 'blocked'
                   WHEN 'known' THEN 'observing'
                   ELSE 'new' END ELSE lifecycle_status END,
                 identity_confidence=CASE WHEN ? THEN CASE
                   WHEN mac IS NOT NULL AND mac<>'' THEN 'high' ELSE 'low' END
                   ELSE identity_confidence END,
                 review_required=CASE WHEN ? THEN CASE
                   WHEN mac IS NOT NULL AND mac<>'' THEN 0 ELSE 1 END
                   ELSE review_required END""",
                (int(added.get("lifecycle_status", False)),
                 int(added.get("identity_confidence", False)),
                 int(added.get("review_required", False))),
            )

    @staticmethod
    def _seed_asset_observations(c) -> None:
        assets = c.execute("SELECT * FROM inventory_devices").fetchall()
        for asset in assets:
            seen = asset["last_seen"] or asset["first_seen"]
            values = (
                ("ip", asset["current_address"], "medium"),
                ("mac", asset["mac"], "high"),
                ("hostname", asset["detected_name"], "medium"),
            )
            for kind, value, confidence in values:
                if value:
                    DB._upsert_observation(
                        c, asset["id"], kind, value, "migration", confidence,
                        asset["first_seen"], seen, asset["last_scan_id"],
                    )
            for history in c.execute(
                "SELECT * FROM device_ip_history WHERE device_id=?", (asset["id"],)
            ).fetchall():
                DB._upsert_observation(
                    c, asset["id"], "ip", history["address"], "migration", "medium",
                    history["first_seen"], history["last_seen"], history["last_scan_id"],
                )

    # ── Internal ──────────────────────────────────────────────────────────
    @contextmanager
    def _cx(self):
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _normalize_observation(kind: str, value: str) -> str:
        value = (value or "").strip()
        if kind == "mac":
            return value.upper().replace("-", ":")
        return value.casefold()

    @staticmethod
    def _upsert_observation(
        c, device_id: int, kind: str, value: str, source: str, confidence: str,
        first_seen: str, last_seen: str, scan_id: int | None, metadata: str = "",
    ) -> None:
        normalized = DB._normalize_observation(kind, value)
        if not normalized:
            return
        c.execute(
            """INSERT INTO asset_observations
               (device_id,kind,value,normalized_value,source,confidence,
                first_seen,last_seen,last_scan_id,metadata)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(device_id,kind,normalized_value) DO UPDATE SET
                 value=excluded.value,last_seen=excluded.last_seen,
                 last_scan_id=excluded.last_scan_id,source=excluded.source,
                 confidence=excluded.confidence,metadata=excluded.metadata""",
            (device_id, kind, value, normalized, source, confidence,
             first_seen, last_seen, scan_id, metadata),
        )

    @staticmethod
    def _event(c, device_id: int, event_type: str, occurred_at: str,
               scan_id: int | None, summary: str, severity: str = "info",
               details: str = "") -> None:
        c.execute(
            """INSERT INTO asset_events
               (device_id,event_type,occurred_at,scan_id,severity,summary,details)
               VALUES (?,?,?,?,?,?,?)""",
            (device_id, event_type, occurred_at, scan_id, severity, summary, details),
        )

    @staticmethod
    def _same_subnet(left: str, right: str) -> bool:
        try:
            return ipaddress.ip_network(f"{left}/24", strict=False) == ipaddress.ip_network(
                f"{right}/24", strict=False
            )
        except ValueError:
            return False

    def _similar_assets(self, c, host: ScanHost, exclude_id: int) -> list[tuple[int, int, list[str]]]:
        hostname = self._normalize_observation("hostname", host.hostname)
        vendor = self._normalize_observation("vendor", host.vendor)
        os_name = self._normalize_observation("os", host.os_name)
        services = {
            self._normalize_observation(
                "service", f"{s.port}/{s.protocol}:{s.name}:{s.product}:{s.version}"
            ) for s in host.open_ports
        }
        matches = []
        for asset in c.execute(
            """SELECT * FROM inventory_devices
               WHERE id<>? AND merged_into_device_id IS NULL""", (exclude_id,)
        ).fetchall():
            observations = c.execute(
                "SELECT kind,normalized_value FROM asset_observations WHERE device_id=?",
                (asset["id"],),
            ).fetchall()
            values: dict[str, set[str]] = {}
            for item in observations:
                values.setdefault(item["kind"], set()).add(item["normalized_value"])
            score, reasons = 0, []
            if hostname and hostname in values.get("hostname", set()):
                score += 30; reasons.append("same hostname")
            if vendor and vendor in values.get("vendor", set()):
                score += 15; reasons.append("same vendor")
            if os_name and os_name in values.get("os", set()):
                score += 20; reasons.append("same operating system")
            shared_services = services & values.get("service", set())
            if shared_services:
                score += min(25, 10 + len(shared_services) * 5)
                reasons.append(f"{len(shared_services)} matching service fingerprint(s)")
            if self._same_subnet(host.address, asset["current_address"]):
                score += 5; reasons.append("same network segment")
            if score >= 50:
                matches.append((asset["id"], min(score, 100), reasons))
        return sorted(matches, key=lambda item: item[1], reverse=True)

    def _resolve_asset(self, c, host: ScanHost, seen_at: str, scan_id: int) -> int:
        normalized_mac = self._normalize_observation("mac", host.mac)
        device = None
        if normalized_mac:
            device = c.execute(
                """SELECT * FROM inventory_devices
                   WHERE mac=? COLLATE NOCASE AND merged_into_device_id IS NULL""",
                (normalized_mac,),
            ).fetchone()
        if device is None:
            device = c.execute(
                """SELECT * FROM inventory_devices
                   WHERE current_address=? AND (mac IS NULL OR mac='')
                     AND merged_into_device_id IS NULL
                   ORDER BY last_seen DESC LIMIT 1""", (host.address,),
            ).fetchone()
        detected_name = host.hostname or host.vendor
        if device is None:
            device_id = c.execute(
                """INSERT INTO inventory_devices
                   (mac,current_address,detected_name,identity_source,first_seen,last_seen,
                    last_scan_id,identity_confidence,review_required,lifecycle_status)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (normalized_mac or None, host.address, detected_name,
                 "mac" if normalized_mac else "ip", seen_at, seen_at, scan_id,
                 "high" if normalized_mac else "low", 0 if normalized_mac else 1, "new"),
            ).lastrowid
            self._event(c, device_id, "created", seen_at, scan_id,
                        f"Asset first observed at {host.address}")
            for candidate_id, score, reasons in self._similar_assets(c, host, device_id):
                left, right = sorted((device_id, candidate_id))
                c.execute(
                    """INSERT OR IGNORE INTO asset_merge_suggestions
                       (device_a_id,device_b_id,score,reasons,status,created_at)
                       VALUES (?,?,?,?, 'pending', ?)""",
                    (left, right, score, json.dumps(reasons), seen_at),
                )
        else:
            device_id = device["id"]
            identity_conflict = False
            conflict_reasons = []
            if normalized_mac and (device["mac"] or "").upper() == normalized_mac:
                known_rows = c.execute(
                    "SELECT kind,normalized_value FROM asset_observations WHERE device_id=?",
                    (device_id,),
                ).fetchall()
                known: dict[str, set[str]] = {}
                for row in known_rows:
                    known.setdefault(row["kind"], set()).add(row["normalized_value"])
                for kind, value in (("hostname", host.hostname), ("vendor", host.vendor),
                                    ("os", host.os_name)):
                    normalized = self._normalize_observation(kind, value)
                    if normalized and known.get(kind) and normalized not in known[kind]:
                        conflict_reasons.append(f"different {kind}")
                incoming_services = {
                    self._normalize_observation(
                        "service", f"{s.port}/{s.protocol}:{s.name}:{s.product}:{s.version}"
                    ) for s in host.open_ports
                }
                if incoming_services and known.get("service") and not (
                    incoming_services & known["service"]
                ):
                    conflict_reasons.append("incompatible service fingerprint")
                identity_conflict = len(conflict_reasons) >= 2
            if device["current_address"] != host.address:
                self._event(
                    c, device_id, "ip_changed", seen_at, scan_id,
                    f"IP changed from {device['current_address']} to {host.address}",
                    details=json.dumps({"from": device["current_address"], "to": host.address}),
                )
            c.execute(
                """UPDATE inventory_devices SET current_address=?,
                   mac=CASE WHEN ?<>'' THEN ? ELSE mac END,
                   detected_name=CASE WHEN ?<>'' THEN ? ELSE detected_name END,
                   identity_source=CASE WHEN ?<>'' THEN 'mac' ELSE identity_source END,
                   identity_confidence=CASE WHEN ?<>'' THEN 'high' ELSE identity_confidence END,
                   review_required=CASE WHEN ?<>'' THEN 0 ELSE review_required END,
                   last_seen=?,last_scan_id=? WHERE id=?""",
                (host.address, normalized_mac, normalized_mac, detected_name, detected_name,
                 normalized_mac, normalized_mac, normalized_mac, seen_at, scan_id, device_id),
            )
            if identity_conflict:
                c.execute(
                    """UPDATE inventory_devices SET identity_confidence='medium',
                       review_required=1 WHERE id=?""", (device_id,),
                )
                self._event(
                    c, device_id, "identity_conflict", seen_at, scan_id,
                    "Stable MAC presented incompatible identity signals", "high",
                    json.dumps(conflict_reasons),
                )
            if device["lifecycle_status"] == "blocked":
                self._event(c, device_id, "blocked_present", seen_at, scan_id,
                            f"Blocked asset responded at {host.address}", "high")

        previous_host = c.execute(
            """SELECT * FROM scan_hosts WHERE device_id=? AND scan_id<>?
               ORDER BY id DESC LIMIT 1""", (device_id, scan_id),
        ).fetchone()
        if previous_host:
            old_services = {
                f"{row['port']}/{row['protocol']}:{row['name']}:{row['product']}:{row['version']}"
                for row in c.execute(
                    "SELECT * FROM scan_services WHERE host_id=? AND state='open'",
                    (previous_host["id"],),
                ).fetchall()
            }
            new_services = {
                f"{s.port}/{s.protocol}:{s.name}:{s.product}:{s.version}"
                for s in host.open_ports
            }
            if old_services != new_services:
                self._event(
                    c, device_id, "services_changed", seen_at, scan_id,
                    "Exposed services changed", "medium",
                    json.dumps({"opened": sorted(new_services - old_services),
                                "closed": sorted(old_services - new_services)}),
                )
            old_risk = previous_host["risk_score"] or 0
            if old_risk != host.risk_score:
                severity = "high" if host.risk_score > old_risk else "info"
                self._event(
                    c, device_id, "risk_changed", seen_at, scan_id,
                    f"Risk score changed from {old_risk} to {host.risk_score}", severity,
                )

        observations = [
            ("ip", host.address, "medium", ""),
            ("mac", normalized_mac, "high", ""),
            ("hostname", host.hostname, "medium", ""),
            ("vendor", host.vendor, "medium", ""),
            ("os", host.os_name, "medium", ""),
        ]
        observations.extend(
            ("service", f"{s.port}/{s.protocol}:{s.name}:{s.product}:{s.version}",
             "medium", json.dumps({"risk": s.risk_level}))
            for s in host.open_ports
        )
        for kind, value, confidence, metadata in observations:
            if value:
                self._upsert_observation(c, device_id, kind, value, "nmap", confidence,
                                         seen_at, seen_at, scan_id, metadata)
        c.execute(
            """INSERT INTO device_ip_history
               (device_id,address,first_seen,last_seen,last_scan_id) VALUES (?,?,?,?,?)
               ON CONFLICT(device_id,address) DO UPDATE SET
                 last_seen=excluded.last_seen,last_scan_id=excluded.last_scan_id""",
            (device_id, host.address, seen_at, seen_at, scan_id),
        )
        return device_id

    # ── Sessions ──────────────────────────────────────────────────────────
    def new_session(self, iface: str) -> int:
        with self._cx() as c:
            return c.execute(
                "INSERT INTO sessions (start_time, interface) VALUES (?,?)",
                (datetime.now().isoformat(), iface or "All"),
            ).lastrowid

    def close_session(self, sid: int, pkts: int, b_in: int, b_out: int):
        with self._cx() as c:
            c.execute(
                """UPDATE sessions
                   SET end_time=?, total_pkts=?, total_bytes_in=?, total_bytes_out=?
                   WHERE id=?""",
                (datetime.now().isoformat(), pkts, b_in, b_out, sid),
            )

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._cx() as c:
            rows = c.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT 100"
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Stats ─────────────────────────────────────────────────────────────
    def save_stat(self, sid: int, d: Dict[str, int]):
        with self._cx() as c:
            c.execute(
                """INSERT INTO stats
                   (session_id, ts, bytes_in, bytes_out, pkts_in, pkts_out,
                    n_tcp, n_udp, n_https, n_http, n_dns, n_icmp, n_other)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid, datetime.now().isoformat(),
                    d.get("bytes_in", 0),  d.get("bytes_out", 0),
                    d.get("pkts_in",  0),  d.get("pkts_out",  0),
                    d.get("TCP",   0), d.get("UDP",   0),
                    d.get("HTTPS", 0), d.get("HTTP",  0),
                    d.get("DNS",   0), d.get("ICMP",  0),
                    d.get("OTHER", 0),
                ),
            )

    def get_stats(self, sid: int) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM stats WHERE session_id=? ORDER BY ts", (sid,)
            ).fetchall()]

    def save_quality_check(self, interface: str, result) -> int:
        reachable = (1 if result.internet_reachable is True else
                     0 if result.internet_reachable is False else None)
        with self._cx() as c:
            return c.execute(
                """INSERT INTO quality_checks
                   (ts,interface,gateway,received,samples,latency_ms,jitter_ms,
                    loss_percent,dns_ms,internet_reachable)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (datetime.now().isoformat(), interface or "All", result.target,
                 result.received, result.samples, result.latency_ms, result.jitter_ms,
                 result.loss_percent, result.dns_ms, reachable),
            ).lastrowid

    def list_quality_checks(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._cx() as c:
            rows = c.execute(
                "SELECT * FROM quality_checks ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    # ── Top IPs ───────────────────────────────────────────────────────────
    def upsert_ips(self, sid: int, ips_data: List[tuple]):
        """Batch upsert multiple top IPs in a single transaction."""
        if not ips_data:
            return
        now_str = datetime.now().isoformat()
        params = [(sid, ip, nb, np_, now_str) for ip, nb, np_ in ips_data]
        with self._cx() as c:
            c.executemany(
                """INSERT INTO top_ips (session_id, ip, total_bytes, total_pkts, last_seen)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(session_id, ip) DO UPDATE SET
                     total_bytes = total_bytes + excluded.total_bytes,
                     total_pkts  = total_pkts  + excluded.total_pkts,
                     last_seen   = excluded.last_seen""",
                params,
            )

    def get_top_ips(self, sid: int, n: int = 15) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM top_ips WHERE session_id=? ORDER BY total_bytes DESC LIMIT ?",
                (sid, n),
            ).fetchall()]

    # ── Active network scans ─────────────────────────────────────────────
    def save_network_scan(self, scan: NetworkScan) -> int:
        with self._cx() as c:
            scan_id = c.execute(
                """INSERT INTO network_scans
                   (started_at, finished_at, target, profile, command, nmap_version,
                    duration_seconds, host_count, open_port_count, risk_score, risk_level)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan.started_at.isoformat(), scan.finished_at.isoformat(),
                    scan.target, scan.profile, scan.command, scan.nmap_version,
                    scan.duration_seconds, len(scan.hosts), scan.open_port_count,
                    scan.risk_score, scan.risk_level,
                ),
            ).lastrowid
            previous_row = c.execute(
                """SELECT id FROM network_scans WHERE target=? AND id<>?
                   ORDER BY started_at DESC LIMIT 1""", (scan.target, scan_id),
            ).fetchone()
            previous_device_ids = set()
            if previous_row:
                previous_device_ids = {
                    row["device_id"] for row in c.execute(
                        """SELECT device_id FROM scan_hosts
                           WHERE scan_id=? AND device_id IS NOT NULL""",
                        (previous_row["id"],),
                    ).fetchall()
                }
            current_device_ids = set()
            for host in scan.hosts:
                host_id = c.execute(
                    """INSERT INTO scan_hosts
                       (scan_id, address, status, hostname, mac, vendor, os_name,
                        latency_ms, risk_score, risk_level)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        scan_id, host.address, host.status, host.hostname, host.mac,
                        host.vendor, host.os_name, host.latency_ms, host.risk_score,
                        host.risk_level,
                    ),
                ).lastrowid
                c.executemany(
                    """INSERT INTO scan_services
                       (host_id, port, protocol, state, name, product, version,
                        extra_info, tunnel, risk_level, risk_reason)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            host_id, service.port, service.protocol, service.state,
                            service.name, service.product, service.version,
                            service.extra_info, service.tunnel, service.risk_level,
                            service.risk_reason,
                        )
                        for service in host.services
                    ],
                )
                seen_at = scan.finished_at.isoformat()
                device_id = self._resolve_asset(c, host, seen_at, scan_id)
                host.device_id = device_id
                current_device_ids.add(device_id)
                c.execute("UPDATE scan_hosts SET device_id=? WHERE id=?", (device_id, host_id))
                if previous_row and device_id not in previous_device_ids:
                    self._event(c, device_id, "appeared", seen_at, scan_id,
                                f"Asset appeared at {host.address}", "medium")
            if previous_row:
                for missing_id in previous_device_ids - current_device_ids:
                    asset = c.execute(
                        "SELECT lifecycle_status,current_address FROM inventory_devices WHERE id=?",
                        (missing_id,),
                    ).fetchone()
                    if asset and asset["lifecycle_status"] not in {"retired", "stale"}:
                        self._event(
                            c, missing_id, "disappeared", scan.finished_at.isoformat(), scan_id,
                            f"Asset did not respond at {asset['current_address']}", "medium",
                        )
            now = datetime.now().isoformat()
            c.executemany(
                """INSERT INTO scan_alerts
                   (scan_id, severity, kind, host, title, detail, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                [
                    (
                        scan_id, finding.severity, finding.kind, finding.host,
                        finding.title, finding.detail, now,
                    )
                    for finding in scan.findings
                ],
            )
        scan.scan_id = scan_id
        return scan_id

    # ── Persistent device inventory ─────────────────────────────────────
    def list_inventory(self) -> List[Dict[str, Any]]:
        with self._cx() as c:
            items = [dict(row) for row in c.execute(
                """SELECT id AS device_id,current_address AS address,mac,detected_name,
                          alias,device_type,owner,location,notes,trust_status,
                          identity_source,first_seen,last_seen,last_scan_id,criticality,
                          lifecycle_status,tags,last_reviewed,identity_confidence,
                          review_required,merged_into_device_id
                   FROM inventory_devices WHERE merged_into_device_id IS NULL
                   ORDER BY current_address"""
            ).fetchall()]
            for item in items:
                item["merged_device_ids"] = [
                    row["id"] for row in c.execute(
                        "SELECT id FROM inventory_devices WHERE merged_into_device_id=?",
                        (item["device_id"],),
                    ).fetchall()
                ]
            return items

    def get_inventory_device(self, address: str | None = None,
                             device_id: int | None = None) -> Dict[str, Any] | None:
        with self._cx() as c:
            if device_id is not None:
                where, params = "id=?", (device_id,)
            else:
                where, params = "current_address=?", (address,)
            row = c.execute(
                """SELECT id AS device_id,current_address AS address,mac,detected_name,
                          alias,device_type,owner,location,notes,trust_status,
                          identity_source,first_seen,last_seen,last_scan_id,criticality,
                          lifecycle_status,tags,last_reviewed,identity_confidence,
                          review_required,merged_into_device_id
                   FROM inventory_devices WHERE """ + where +
                " ORDER BY last_seen DESC LIMIT 1", params
            ).fetchone()
            return dict(row) if row else None

    def list_device_ip_history(self, address: str) -> List[Dict[str, Any]]:
        """Return every observed address for the device currently at ``address``."""
        with self._cx() as c:
            device = c.execute(
                """SELECT id FROM inventory_devices WHERE current_address=?
                   ORDER BY last_seen DESC LIMIT 1""", (address,),
            ).fetchone()
            if not device:
                return []
            return [dict(row) for row in c.execute(
                """SELECT address,first_seen,last_seen,last_scan_id
                   FROM device_ip_history WHERE device_id=?
                   ORDER BY last_seen DESC""", (device["id"],),
            ).fetchall()]

    def update_inventory_device(
        self, address: str, *, alias: str = "", device_type: str = "unknown",
        owner: str = "", location: str = "", notes: str = "",
        trust_status: str = "new", criticality: str = "medium",
        lifecycle_status: str | None = None, tags: str = "",
        reviewed: bool = False,
    ) -> None:
        allowed_trust = {"new", "known", "authorized", "blocked"}
        if trust_status not in allowed_trust:
            raise ValueError("Invalid device trust status.")
        lifecycle_status = lifecycle_status or {
            "new": "new", "known": "observing", "authorized": "authorized",
            "blocked": "blocked",
        }[trust_status]
        if lifecycle_status not in {"new", "observing", "authorized", "blocked", "retired", "stale"}:
            raise ValueError("Invalid asset lifecycle status.")
        if criticality not in {"low", "medium", "high", "critical"}:
            raise ValueError("Invalid asset criticality.")
        reviewed_at = datetime.now().isoformat() if reviewed else None
        with self._cx() as c:
            device = c.execute(
                """SELECT * FROM inventory_devices WHERE current_address=?
                   ORDER BY last_seen DESC LIMIT 1""", (address,)
            ).fetchone()
            if not device:
                raise ValueError(f"Inventory device not found: {address}")
            updated = c.execute(
                """UPDATE inventory_devices SET alias=?, device_type=?, owner=?,
                   location=?, notes=?, trust_status=?,criticality=?,lifecycle_status=?,
                   tags=?,last_reviewed=COALESCE(?,last_reviewed),
                   review_required=CASE WHEN ? THEN 0 ELSE review_required END
                   WHERE id=?""",
                (alias.strip(), device_type.strip() or "unknown", owner.strip(),
                 location.strip(), notes.strip(), trust_status, criticality,
                 lifecycle_status, tags.strip(), reviewed_at, int(reviewed), device["id"]),
            ).rowcount
            if not updated:
                raise ValueError(f"Inventory device not found: {address}")
            if lifecycle_status != device["lifecycle_status"]:
                self._event(
                    c, device["id"], "lifecycle_changed", datetime.now().isoformat(), None,
                    f"Lifecycle changed from {device['lifecycle_status']} to {lifecycle_status}",
                )
            if owner.strip() != (device["owner"] or ""):
                self._event(c, device["id"], "owner_changed", datetime.now().isoformat(),
                            None, f"Owner changed to {owner.strip() or 'unassigned'}")

    def list_asset_observations(self, device_id: int) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(row) for row in c.execute(
                """SELECT * FROM asset_observations WHERE device_id=?
                   ORDER BY kind,last_seen DESC""", (device_id,)
            ).fetchall()]

    def list_asset_events(self, device_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(row) for row in c.execute(
                """SELECT * FROM asset_events WHERE device_id=?
                   ORDER BY occurred_at DESC,id DESC LIMIT ?""", (device_id, limit)
            ).fetchall()]

    def list_merge_suggestions(self, status: str = "pending") -> List[Dict[str, Any]]:
        with self._cx() as c:
            rows = c.execute(
                """SELECT s.*,a.current_address AS address_a,b.current_address AS address_b,
                          a.alias AS alias_a,b.alias AS alias_b
                   FROM asset_merge_suggestions s
                   JOIN inventory_devices a ON a.id=s.device_a_id
                   JOIN inventory_devices b ON b.id=s.device_b_id
                   WHERE s.status=? ORDER BY s.score DESC,s.created_at DESC""", (status,)
            ).fetchall()
            output = []
            for row in rows:
                item = dict(row)
                try: item["reasons"] = json.loads(item["reasons"])
                except (TypeError, json.JSONDecodeError): item["reasons"] = []
                output.append(item)
            return output

    def list_merged_assets(self) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(row) for row in c.execute(
                """SELECT child.id AS source_device_id,child.current_address AS source_address,
                          parent.id AS target_device_id,parent.current_address AS target_address,
                          child.alias AS source_alias,parent.alias AS target_alias
                   FROM inventory_devices child
                   JOIN inventory_devices parent ON parent.id=child.merged_into_device_id
                   ORDER BY child.last_seen DESC"""
            ).fetchall()]

    def merge_assets(self, target_device_id: int, source_device_id: int,
                     suggestion_id: int | None = None) -> None:
        if target_device_id == source_device_id:
            raise ValueError("An asset cannot be merged into itself.")
        with self._cx() as c:
            target = c.execute("SELECT * FROM inventory_devices WHERE id=?", (target_device_id,)).fetchone()
            source = c.execute("SELECT * FROM inventory_devices WHERE id=?", (source_device_id,)).fetchone()
            if not target or not source or source["merged_into_device_id"] is not None:
                raise ValueError("Invalid asset merge.")
            c.execute("UPDATE inventory_devices SET merged_into_device_id=? WHERE id=?",
                      (target_device_id, source_device_id))
            now = datetime.now().isoformat()
            self._event(c, target_device_id, "asset_merged", now, None,
                        f"Asset #{source_device_id} linked to this asset")
            self._event(c, source_device_id, "merged_into", now, None,
                        f"Asset linked to #{target_device_id}")
            if suggestion_id:
                c.execute("""UPDATE asset_merge_suggestions SET status='accepted',resolved_at=?
                             WHERE id=?""", (now, suggestion_id))

    def separate_asset(self, source_device_id: int) -> None:
        with self._cx() as c:
            row = c.execute("SELECT merged_into_device_id FROM inventory_devices WHERE id=?",
                            (source_device_id,)).fetchone()
            if not row or row["merged_into_device_id"] is None:
                raise ValueError("Asset is not merged.")
            target_id = row["merged_into_device_id"]
            c.execute("UPDATE inventory_devices SET merged_into_device_id=NULL WHERE id=?",
                      (source_device_id,))
            now = datetime.now().isoformat()
            self._event(c, source_device_id, "asset_separated", now, None,
                        f"Asset separated from #{target_id}")
            self._event(c, target_id, "asset_separated", now, None,
                        f"Asset #{source_device_id} separated")

    def dismiss_merge_suggestion(self, suggestion_id: int) -> None:
        with self._cx() as c:
            c.execute("""UPDATE asset_merge_suggestions SET status='dismissed',resolved_at=?
                         WHERE id=?""", (datetime.now().isoformat(), suggestion_id))

    def asset_attention_summary(self, online_device_ids: set[int] | None = None) -> Dict[str, int]:
        online_device_ids = online_device_ids or set()
        assets = self.list_inventory()
        return {
            "new": sum(a["lifecycle_status"] == "new" for a in assets),
            "unclassified": sum(bool(a["review_required"]) for a in assets),
            "critical": sum(a["criticality"] == "critical" for a in assets),
            "stale": sum(a["lifecycle_status"] == "stale" for a in assets),
            "missing": sum(
                a["lifecycle_status"] not in {"retired", "stale"}
                and a["device_id"] not in online_device_ids for a in assets
            ) if online_device_ids else 0,
            "blocked_online": sum(
                a["lifecycle_status"] == "blocked" and a["device_id"] in online_device_ids
                for a in assets
            ),
            "pending_merges": len(self.list_merge_suggestions()),
        }

    def search_global(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search inventory, historical hosts, services and captured endpoints."""
        value = query.strip()
        if not value:
            return []
        pattern = f"%{value}%"
        results: list[dict[str, Any]] = []
        with self._cx() as c:
            inventory = c.execute(
                """SELECT id AS device_id,current_address AS address,mac,detected_name,
                          alias,device_type,owner,location,trust_status,lifecycle_status,
                          criticality,tags,identity_confidence
                   FROM inventory_devices
                   WHERE merged_into_device_id IS NULL AND
                     (current_address LIKE ? OR mac LIKE ? OR detected_name LIKE ?
                      OR alias LIKE ? OR device_type LIKE ? OR owner LIKE ?
                      OR location LIKE ? OR notes LIKE ? OR tags LIKE ?
                      OR lifecycle_status LIKE ? OR criticality LIKE ?)
                   ORDER BY last_seen DESC LIMIT ?""",
                (*([pattern] * 11), limit),
            ).fetchall()
            for row in inventory:
                item = dict(row)
                results.append({
                    "category": "inventory", "label": item["alias"] or item["detected_name"] or item["address"],
                    "value": item["address"],
                    "detail": (f"Asset #{item['device_id']} · {item['mac'] or '-'} · "
                               f"{item['device_type']} · {item['owner'] or '-'} · "
                               f"{item['lifecycle_status']} · {item['criticality']}"),
                })
            remaining = max(0, limit - len(results))
            if remaining:
                observations = c.execute(
                    """SELECT DISTINCT d.id AS device_id,d.current_address,d.alias,
                                      d.detected_name,o.kind,o.value
                       FROM asset_observations o JOIN inventory_devices d ON d.id=o.device_id
                       WHERE d.merged_into_device_id IS NULL AND o.value LIKE ?
                       ORDER BY o.last_seen DESC LIMIT ?""", (pattern, remaining),
                ).fetchall()
                known = {item["value"] for item in results if item["category"] == "inventory"}
                for row in observations:
                    if row["current_address"] in known:
                        continue
                    results.append({
                        "category": "inventory",
                        "label": row["alias"] or row["detected_name"] or row["current_address"],
                        "value": row["current_address"],
                        "detail": f"Asset #{row['device_id']} · historical {row['kind']}: {row['value']}",
                    })
            remaining = max(0, limit - len(results))
            if remaining:
                services = c.execute(
                    """SELECT sh.address, sh.hostname, ss.port, ss.protocol, ss.name,
                              ss.product, ss.version, ns.started_at
                       FROM scan_services ss
                       JOIN scan_hosts sh ON sh.id=ss.host_id
                       JOIN network_scans ns ON ns.id=sh.scan_id
                       WHERE CAST(ss.port AS TEXT) LIKE ? OR ss.name LIKE ?
                          OR ss.product LIKE ? OR ss.version LIKE ?
                          OR sh.address LIKE ? OR sh.hostname LIKE ?
                       ORDER BY ns.started_at DESC LIMIT ?""",
                    (*([pattern] * 6), remaining),
                ).fetchall()
                for row in services:
                    item = dict(row)
                    results.append({
                        "category": "service",
                        "label": f"{item['port']}/{item['protocol']} {item['name'] or 'unknown'}",
                        "value": item["address"],
                        "detail": " ".join(part for part in
                                           (item["hostname"], item["product"], item["version"]) if part),
                    })
            remaining = max(0, limit - len(results))
            if remaining:
                endpoints = c.execute(
                    """SELECT ip, SUM(total_bytes) total_bytes, MAX(last_seen) last_seen
                       FROM top_ips WHERE ip LIKE ? GROUP BY ip
                       ORDER BY total_bytes DESC LIMIT ?""",
                    (pattern, remaining),
                ).fetchall()
                results.extend({
                    "category": "traffic", "label": row["ip"], "value": row["ip"],
                    "detail": f"{row['total_bytes'] or 0:,} bytes · last seen {row['last_seen'] or '-'}",
                } for row in endpoints)
        return results[:limit]

    # ── Custom scan profiles and schedules ─────────────────────────────
    def save_scan_profile(self, name: str, target: str, profile: str) -> int:
        name, target = name.strip(), target.strip()
        if not name or not target:
            raise ValueError("Profile name and target are required.")
        now = datetime.now().isoformat()
        with self._cx() as c:
            c.execute(
                """INSERT INTO scan_profiles(name,target,profile,created_at,updated_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(name) DO UPDATE SET target=excluded.target,
                     profile=excluded.profile, updated_at=excluded.updated_at""",
                (name, target, profile, now, now),
            )
            return c.execute("SELECT id FROM scan_profiles WHERE name=?", (name,)).fetchone()["id"]

    def list_scan_profiles(self) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(row) for row in c.execute(
                "SELECT * FROM scan_profiles ORDER BY name COLLATE NOCASE"
            ).fetchall()]

    def get_scan_profile(self, profile_id: int) -> Dict[str, Any] | None:
        with self._cx() as c:
            row = c.execute("SELECT * FROM scan_profiles WHERE id=?", (profile_id,)).fetchone()
            return dict(row) if row else None

    def delete_scan_profile(self, profile_id: int) -> None:
        with self._cx() as c:
            c.execute("DELETE FROM scan_schedules WHERE profile_id=?", (profile_id,))
            c.execute("DELETE FROM scan_profiles WHERE id=?", (profile_id,))

    def save_scan_schedule(
        self, profile_id: int, interval_minutes: int,
        notify_changes_only: bool = True, now: datetime | None = None,
    ) -> int:
        if interval_minutes < 1:
            raise ValueError("Schedule interval must be at least one minute.")
        from datetime import timedelta
        current = now or datetime.now()
        next_run = (current + timedelta(minutes=interval_minutes)).isoformat()
        with self._cx() as c:
            if not c.execute("SELECT 1 FROM scan_profiles WHERE id=?", (profile_id,)).fetchone():
                raise ValueError("Scan profile not found.")
            return c.execute(
                """INSERT INTO scan_schedules
                   (profile_id,interval_minutes,enabled,notify_changes_only,next_run)
                   VALUES (?,?,1,?,?)""",
                (profile_id, interval_minutes, int(notify_changes_only), next_run),
            ).lastrowid

    def list_scan_schedules(self) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(row) for row in c.execute(
                """SELECT ss.*, sp.name, sp.target, sp.profile
                   FROM scan_schedules ss JOIN scan_profiles sp ON sp.id=ss.profile_id
                   ORDER BY sp.name COLLATE NOCASE, ss.id"""
            ).fetchall()]

    def list_due_schedules(self, now: datetime | None = None) -> List[Dict[str, Any]]:
        current = (now or datetime.now()).isoformat()
        return [item for item in self.list_scan_schedules()
                if item["enabled"] and item["next_run"] <= current]

    def set_schedule_enabled(self, schedule_id: int, enabled: bool) -> None:
        with self._cx() as c:
            c.execute("UPDATE scan_schedules SET enabled=? WHERE id=?",
                      (int(enabled), schedule_id))

    def delete_scan_schedule(self, schedule_id: int) -> None:
        with self._cx() as c:
            c.execute("DELETE FROM scan_schedules WHERE id=?", (schedule_id,))

    def mark_schedule_run(
        self, schedule_id: int, success: bool, error: str = "",
        now: datetime | None = None,
    ) -> None:
        from datetime import timedelta
        current = now or datetime.now()
        with self._cx() as c:
            row = c.execute(
                "SELECT interval_minutes FROM scan_schedules WHERE id=?", (schedule_id,)
            ).fetchone()
            if not row:
                return
            next_run = current + timedelta(minutes=row["interval_minutes"])
            c.execute(
                """UPDATE scan_schedules SET last_run=?, next_run=?, last_status=?,
                   last_error=? WHERE id=?""",
                (current.isoformat(), next_run.isoformat(),
                 "completed" if success else "error", error[:1000], schedule_id),
            )

    def list_network_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._cx() as c:
            return [dict(row) for row in c.execute(
                "SELECT * FROM network_scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()]

    def get_latest_network_scan(
        self, target: str | None = None, before_id: int | None = None
    ) -> NetworkScan | None:
        query = "SELECT id FROM network_scans"
        params: list[Any] = []
        clauses = []
        if target:
            clauses.append("target=?")
            params.append(target)
        if before_id:
            clauses.append("id<?")
            params.append(before_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY started_at DESC LIMIT 1"
        with self._cx() as c:
            row = c.execute(query, params).fetchone()
        return self.get_network_scan(row["id"]) if row else None

    def get_network_scan(self, scan_id: int) -> NetworkScan | None:
        with self._cx() as c:
            scan_row = c.execute(
                "SELECT * FROM network_scans WHERE id=?", (scan_id,)
            ).fetchone()
            if not scan_row:
                return None
            host_rows = c.execute(
                "SELECT * FROM scan_hosts WHERE scan_id=? ORDER BY address", (scan_id,)
            ).fetchall()
            hosts = []
            for host_row in host_rows:
                service_rows = c.execute(
                    "SELECT * FROM scan_services WHERE host_id=? ORDER BY port",
                    (host_row["id"],),
                ).fetchall()
                services = [
                    ScanService(
                        port=row["port"], protocol=row["protocol"], state=row["state"],
                        name=row["name"] or "unknown", product=row["product"] or "",
                        version=row["version"] or "", extra_info=row["extra_info"] or "",
                        tunnel=row["tunnel"] or "", risk_level=row["risk_level"] or "low",
                        risk_reason=row["risk_reason"] or "",
                    )
                    for row in service_rows
                ]
                hosts.append(ScanHost(
                    address=host_row["address"], status=host_row["status"] or "unknown",
                    hostname=host_row["hostname"] or "", mac=host_row["mac"] or "",
                    vendor=host_row["vendor"] or "", os_name=host_row["os_name"] or "",
                    latency_ms=host_row["latency_ms"], services=services,
                    risk_score=host_row["risk_score"] or 0,
                    risk_level=host_row["risk_level"] or "low",
                    device_id=host_row["device_id"],
                ))
            finding_rows = c.execute(
                "SELECT * FROM scan_alerts WHERE scan_id=? ORDER BY id", (scan_id,)
            ).fetchall()
            findings = [
                ScanFinding(
                    severity=row["severity"], kind=row["kind"], host=row["host"] or "",
                    title=row["title"], detail=row["detail"] or "",
                )
                for row in finding_rows
            ]
            return NetworkScan(
                target=scan_row["target"], profile=scan_row["profile"],
                command=scan_row["command"] or "",
                started_at=datetime.fromisoformat(scan_row["started_at"]),
                finished_at=datetime.fromisoformat(scan_row["finished_at"]),
                duration_seconds=scan_row["duration_seconds"] or 0.0,
                hosts=hosts, findings=findings,
                nmap_version=scan_row["nmap_version"] or "", scan_id=scan_id,
            )
