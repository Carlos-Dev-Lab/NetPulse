"""
NetPulse — SQLite Database (aggregated stats only)
Per-second summaries are stored — never individual packets.
Uses WAL mode for concurrent reads/writes.
"""
import sqlite3
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
            c.execute(
                """INSERT OR IGNORE INTO inventory_devices
                   (mac,current_address,detected_name,alias,device_type,owner,
                    location,notes,trust_status,identity_source,first_seen,last_seen,last_scan_id)
                   SELECT NULLIF(mac,''),address,detected_name,alias,device_type,owner,
                          location,notes,trust_status,
                          CASE WHEN mac<>'' THEN 'mac' ELSE 'ip' END,
                          first_seen,last_seen,last_scan_id
                   FROM device_inventory legacy
                   WHERE NOT EXISTS (
                       SELECT 1 FROM inventory_devices current
                       WHERE (legacy.mac<>'' AND current.mac=legacy.mac COLLATE NOCASE)
                          OR (legacy.mac='' AND current.mac IS NULL
                              AND current.current_address=legacy.address)
                   )"""
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
                normalized_mac = (host.mac or "").strip().upper()
                device = None
                if normalized_mac:
                    device = c.execute(
                        "SELECT * FROM inventory_devices WHERE mac=? COLLATE NOCASE",
                        (normalized_mac,),
                    ).fetchone()
                if device is None:
                    device = c.execute(
                        """SELECT * FROM inventory_devices
                           WHERE current_address=? AND (mac IS NULL OR mac='')
                           ORDER BY last_seen DESC LIMIT 1""",
                        (host.address,),
                    ).fetchone()
                detected_name = host.hostname or host.vendor
                if device is None:
                    device_id = c.execute(
                        """INSERT INTO inventory_devices
                           (mac,current_address,detected_name,identity_source,
                            first_seen,last_seen,last_scan_id)
                           VALUES (?,?,?,?,?,?,?)""",
                        (normalized_mac or None, host.address, detected_name,
                         "mac" if normalized_mac else "ip", seen_at, seen_at, scan_id),
                    ).lastrowid
                else:
                    device_id = device["id"]
                    c.execute(
                        """UPDATE inventory_devices SET
                           current_address=?,
                           mac=CASE WHEN ?<>'' THEN ? ELSE mac END,
                           detected_name=CASE WHEN ?<>'' THEN ? ELSE detected_name END,
                           identity_source=CASE WHEN ?<>'' THEN 'mac' ELSE identity_source END,
                           last_seen=?, last_scan_id=? WHERE id=?""",
                        (host.address, normalized_mac, normalized_mac,
                         detected_name, detected_name, normalized_mac,
                         seen_at, scan_id, device_id),
                    )
                c.execute(
                    """INSERT INTO device_ip_history
                       (device_id,address,first_seen,last_seen,last_scan_id)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(device_id,address) DO UPDATE SET
                         last_seen=excluded.last_seen,last_scan_id=excluded.last_scan_id""",
                    (device_id, host.address, seen_at, seen_at, scan_id),
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
            return [dict(row) for row in c.execute(
                """SELECT id AS device_id,current_address AS address,mac,detected_name,
                          alias,device_type,owner,location,notes,trust_status,
                          identity_source,first_seen,last_seen,last_scan_id
                   FROM inventory_devices ORDER BY current_address"""
            ).fetchall()]

    def get_inventory_device(self, address: str) -> Dict[str, Any] | None:
        with self._cx() as c:
            row = c.execute(
                """SELECT id AS device_id,current_address AS address,mac,detected_name,
                          alias,device_type,owner,location,notes,trust_status,
                          identity_source,first_seen,last_seen,last_scan_id
                   FROM inventory_devices WHERE current_address=?
                   ORDER BY last_seen DESC LIMIT 1""", (address,)
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
        trust_status: str = "new",
    ) -> None:
        allowed_trust = {"new", "known", "authorized", "blocked"}
        if trust_status not in allowed_trust:
            raise ValueError("Invalid device trust status.")
        with self._cx() as c:
            updated = c.execute(
                """UPDATE inventory_devices SET alias=?, device_type=?, owner=?,
                   location=?, notes=?, trust_status=?
                   WHERE id=(SELECT id FROM inventory_devices WHERE current_address=?
                             ORDER BY last_seen DESC LIMIT 1)""",
                (alias.strip(), device_type.strip() or "unknown", owner.strip(),
                 location.strip(), notes.strip(), trust_status, address),
            ).rowcount
            if not updated:
                raise ValueError(f"Inventory device not found: {address}")

    def search_global(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search inventory, historical hosts, services and captured endpoints."""
        value = query.strip()
        if not value:
            return []
        pattern = f"%{value}%"
        results: list[dict[str, Any]] = []
        with self._cx() as c:
            inventory = c.execute(
                """SELECT current_address AS address, mac, detected_name, alias, device_type, owner,
                          location, trust_status
                   FROM inventory_devices
                   WHERE current_address LIKE ? OR mac LIKE ? OR detected_name LIKE ?
                      OR alias LIKE ? OR device_type LIKE ? OR owner LIKE ?
                      OR location LIKE ? OR notes LIKE ?
                   ORDER BY last_seen DESC LIMIT ?""",
                (*([pattern] * 8), limit),
            ).fetchall()
            for row in inventory:
                item = dict(row)
                results.append({
                    "category": "inventory", "label": item["alias"] or item["detected_name"] or item["address"],
                    "value": item["address"],
                    "detail": f"{item['mac'] or '-'} · {item['device_type']} · {item['owner'] or '-'} · {item['trust_status']}",
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
