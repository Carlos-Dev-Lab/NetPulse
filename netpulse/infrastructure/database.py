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
"""


class DB:
    """Thread-safe SQLite wrapper (check_same_thread=False)."""

    def __init__(self, path: str | Path = "netpulse.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._cx() as c:
            c.executescript(_SCHEMA)

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
