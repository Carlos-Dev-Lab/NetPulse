"""Domain models for active network discovery and scan comparison."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class ScanService:
    port: int
    protocol: str
    state: str
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""
    risk_level: str = "low"
    risk_reason: str = ""

    @property
    def fingerprint(self) -> str:
        return " ".join(x for x in (self.product, self.version, self.extra_info) if x)


@dataclass(slots=True)
class ScanHost:
    address: str
    status: str = "up"
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_name: str = ""
    latency_ms: Optional[float] = None
    services: list[ScanService] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "low"
    device_id: Optional[int] = None

    @property
    def open_ports(self) -> list[ScanService]:
        return [service for service in self.services if service.state == "open"]


@dataclass(slots=True)
class ScanFinding:
    severity: str
    kind: str
    host: str
    title: str
    detail: str


@dataclass(slots=True)
class NetworkScan:
    target: str
    profile: str
    command: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    hosts: list[ScanHost] = field(default_factory=list)
    findings: list[ScanFinding] = field(default_factory=list)
    nmap_version: str = ""
    scan_id: Optional[int] = None

    @property
    def open_port_count(self) -> int:
        return sum(len(host.open_ports) for host in self.hosts)

    @property
    def risk_score(self) -> int:
        return max((host.risk_score for host in self.hosts), default=0)

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 70:
            return "high"
        if self.risk_score >= 35:
            return "medium"
        return "low"
