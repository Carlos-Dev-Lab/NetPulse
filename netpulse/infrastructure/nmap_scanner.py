"""Nmap subprocess adapter and XML result parser."""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from math import ceil
from pathlib import Path
from typing import Iterable

import psutil

from netpulse.domain.network_scan import (
    NetworkScan,
    ScanFinding,
    ScanHost,
    ScanService,
)


SCAN_PROFILES = {
    "discovery": {
        "label": "Device discovery",
        "description": "Fast host discovery without probing ports.",
        "args": [
            "-sn", "-T4", "-n", "--max-retries", "1",
            "--max-rtt-timeout", "1000ms", "--host-timeout", "20s",
        ],
        "timeout": 120,
    },
    "global_discovery": {
        "label": "Global discovery",
        "description": "Explore large CIDR ranges with host discovery only.",
        "args": [
            "-sn", "-T4", "-n", "--max-retries", "1",
            "--max-rtt-timeout", "1000ms", "--host-timeout", "20s",
        ],
        "timeout": 120,
        "batch_size": 16,
        "batch_timeout": 90,
    },
    "quick": {
        "label": "Quick ports",
        "description": "Fast discovery, then top TCP ports only on live devices.",
        "args": [
            "-sT", "-T4", "-n", "--top-ports", "50", "--open",
            "--max-retries", "1", "--max-rtt-timeout", "1000ms",
            "--host-timeout", "25s",
        ],
        "timeout": 240,
        "per_host_timeout": 8,
        "max_hosts": 128,
    },
    "services": {
        "label": "Service inventory",
        "description": "Discovery, then common TCP ports and service versions.",
        "args": [
            "-sT", "-T4", "-n", "--top-ports", "300", "--open",
            "--max-retries", "2", "--max-rtt-timeout", "1500ms",
            "--host-timeout", "60s", "-sV",
        ],
        "timeout": 900,
        "per_host_timeout": 35,
        "max_hosts": 128,
    },
    "deep": {
        "label": "Deep audit",
        "description": "Ports, versions, OS hints and safe default scripts.",
        "args": [
            "-sT", "-T4", "-n", "--top-ports", "1000", "--open",
            "--max-retries", "2", "--max-rtt-timeout", "2000ms",
            "--host-timeout", "120s", "-sV", "-O", "--script", "default,safe",
        ],
        "timeout": 1800,
        "per_host_timeout": 75,
        "max_hosts": 64,
    },
    "vulnerability": {
        "label": "Vulnerability audit",
        "description": "Service versions and Nmap vulnerability scripts. May take several minutes.",
        "args": [
            "-sT", "-T4", "-n", "--top-ports", "1000", "--open",
            "--max-retries", "2", "--max-rtt-timeout", "2000ms",
            "--host-timeout", "180s", "-sV", "--script", "vuln",
        ],
        "timeout": 2400,
        "per_host_timeout": 120,
        "max_hosts": 32,
    },
}


SUSPICIOUS_PORTS = {
    21: ("medium", "FTP may expose unencrypted credentials."),
    23: ("high", "Telnet transmits credentials and sessions without encryption."),
    445: ("medium", "SMB exposure should be restricted to trusted networks."),
    1433: ("high", "Microsoft SQL Server is directly reachable."),
    3306: ("high", "MySQL is directly reachable."),
    3389: ("medium", "Remote Desktop is exposed."),
    5432: ("high", "PostgreSQL is directly reachable."),
    5900: ("high", "VNC remote control is exposed."),
    6379: ("high", "Redis is frequently deployed without authentication."),
    9200: ("high", "Elasticsearch HTTP API is exposed."),
    11211: ("high", "Memcached is exposed."),
    27017: ("high", "MongoDB is directly reachable."),
}

_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_TARGET_SPLIT_RE = re.compile(r"[,;\s]+")
MAX_TARGETS = 64
MAX_INTERACTIVE_ADDRESSES = 4096
MAX_GLOBAL_DISCOVERY_ADDRESSES = 65_536


class NmapError(RuntimeError):
    """Raised when Nmap cannot run or returns an invalid result."""


class NmapCancelledError(NmapError):
    """Raised when an active scan is cancelled by the application."""


class NmapScanner:
    def __init__(self, executable: str | None = None):
        self.executable = executable or self._find_executable()
        self._process_lock = threading.Lock()
        self._active_process: subprocess.Popen | None = None

    @staticmethod
    def _find_executable() -> str:
        found = shutil.which("nmap")
        if found:
            return found
        candidates = (
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
            Path(r"C:\Program Files\Nmap\nmap.exe"),
        )
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return ""

    @property
    def available(self) -> bool:
        return bool(self.executable and Path(self.executable).exists())

    @staticmethod
    def default_target() -> str:
        preferred_ip = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 53))
                preferred_ip = sock.getsockname()[0]
        except OSError:
            pass
        stats = psutil.net_if_stats()
        interfaces = list(psutil.net_if_addrs().items())
        interfaces.sort(
            key=lambda item: not any(
                address.address == preferred_ip for address in item[1]
            )
        )
        for name, addresses in interfaces:
            if name in stats and not stats[name].isup:
                continue
            for address in addresses:
                if getattr(address.family, "name", "") != "AF_INET":
                    continue
                if address.address.startswith("127.") or not address.netmask:
                    continue
                network = ipaddress.ip_network(
                    f"{address.address}/{address.netmask}", strict=False
                )
                if network.prefixlen < 24:
                    network = ipaddress.ip_network(f"{address.address}/24", strict=False)
                return network.with_prefixlen
        return "127.0.0.1"

    @staticmethod
    def validate_target(target: str) -> str:
        targets = NmapScanner.parse_targets(target)
        return ", ".join(targets)

    @staticmethod
    def parse_targets(target: str) -> list[str]:
        """Parse IPs, hostnames and CIDRs separated by commas, spaces or lines."""
        targets = [item for item in _TARGET_SPLIT_RE.split(target.strip()) if item]
        if not targets:
            raise ValueError("Invalid target. Enter an IP, hostname or CIDR network.")
        if len(targets) > MAX_TARGETS:
            raise ValueError(f"Too many targets. Enter no more than {MAX_TARGETS} networks or hosts.")
        for item in targets:
            if (len(item) > 255 or not _TARGET_RE.fullmatch(item)
                    or item.startswith("-") or ".." in item):
                raise ValueError(
                    f"Invalid target: {item}. Use IPs, hostnames or CIDR networks."
                )
        # Preserve entry order while avoiding duplicate scans.
        return list(dict.fromkeys(targets))

    @staticmethod
    def _network_size(target: str) -> int:
        total = 0
        for item in NmapScanner.parse_targets(target):
            try:
                network = ipaddress.ip_network(item, strict=False)
                total += max(1, int(network.num_addresses))
            except ValueError:
                total += 1
        return total

    @staticmethod
    def _target_network(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        try:
            return ipaddress.ip_network(target, strict=False)
        except ValueError:
            return None

    @staticmethod
    def _is_network_target(target: str) -> bool:
        return any(
            "/" in item
            and (network := NmapScanner._target_network(item)) is not None
            and network.num_addresses > 1
            for item in NmapScanner.parse_targets(target)
        )

    @staticmethod
    def _local_subnet_suggestion(target: str) -> str:
        network = NmapScanner._target_network(target)
        if network is None or network.version != 4:
            return ""
        for _, addresses in psutil.net_if_addrs().items():
            for address in addresses:
                if getattr(address.family, "name", "") != "AF_INET":
                    continue
                if not address.address or address.address.startswith("127."):
                    continue
                try:
                    ip = ipaddress.ip_address(address.address)
                except ValueError:
                    continue
                if ip in network:
                    return ipaddress.ip_network(f"{address.address}/24", strict=False).with_prefixlen
        return ""

    @staticmethod
    def _validate_interactive_scope(target: str, profile: str) -> None:
        address_count = NmapScanner._network_size(target)
        if profile == "global_discovery":
            if address_count <= MAX_GLOBAL_DISCOVERY_ADDRESSES:
                return
            raise NmapError(
                f"Targets contain {address_count:,} addresses. "
                "Global discovery is limited to /16-sized ranges or smaller. "
                "Split the target into smaller CIDR blocks."
            )
        if address_count <= MAX_INTERACTIVE_ADDRESSES:
            return
        suggestion = next((NmapScanner._local_subnet_suggestion(item)
                           for item in NmapScanner.parse_targets(target)
                           if NmapScanner._local_subnet_suggestion(item)), "")
        suggestion_text = (
            f" Use Global discovery to explore the whole range, or try {suggestion} for this machine's local subnet."
            if suggestion else " Use Global discovery to explore the whole range, or split it into /24 or /23 ranges."
        )
        raise NmapError(
            f"Targets contain {address_count:,} addresses, which is too "
            f"large for an interactive {SCAN_PROFILES[profile]['label']} scan."
            f"{suggestion_text}"
        )

    @staticmethod
    def _live_addresses(scan: NetworkScan) -> list[str]:
        return [
            host.address for host in scan.hosts
            if host.status.lower() in {"up", "unknown"} and host.address
        ]

    @staticmethod
    def _sort_hosts(hosts: list[ScanHost]) -> list[ScanHost]:
        def key(host: ScanHost):
            try:
                return 0, int(ipaddress.ip_address(host.address))
            except ValueError:
                return 1, host.address

        return sorted(hosts, key=key)

    @staticmethod
    def _merge_discovery_hosts(scan: NetworkScan, discovery: NetworkScan) -> None:
        """Keep hosts found by discovery even when the port scan has no open ports."""
        by_address = {host.address: host for host in scan.hosts}
        for discovered in discovery.hosts:
            current = by_address.get(discovered.address)
            if current is None:
                scan.hosts.append(discovered)
                continue
            current.hostname = current.hostname or discovered.hostname
            current.mac = current.mac or discovered.mac
            current.vendor = current.vendor or discovered.vendor
            current.os_name = current.os_name or discovered.os_name
            if current.latency_ms is None:
                current.latency_ms = discovered.latency_ms
        scan.hosts = NmapScanner._sort_hosts(scan.hosts)

    @staticmethod
    def _discovery_batches(target: str, batch_size: int) -> list[list[str]]:
        targets: list[str] = []
        for item in NmapScanner.parse_targets(target):
            network = NmapScanner._target_network(item)
            if network is None or network.num_addresses <= 1:
                targets.append(item)
            elif network.version == 4 and network.prefixlen < 24:
                targets.extend(subnet.with_prefixlen for subnet in network.subnets(new_prefix=24))
            else:
                targets.append(network.with_prefixlen)
        return [
            targets[index:index + batch_size]
            for index in range(0, len(targets), batch_size)
        ]

    @staticmethod
    def _append_unique_hosts(target_hosts: list[ScanHost], new_hosts: list[ScanHost]) -> None:
        seen = {host.address for host in target_hosts}
        for host in new_hosts:
            if host.address in seen:
                continue
            seen.add(host.address)
            target_hosts.append(host)

    @staticmethod
    def _timeout_for(config: dict, target_count: int) -> int:
        per_host = int(config.get("per_host_timeout", 0))
        if not per_host:
            return int(config["timeout"])
        return max(int(config["timeout"]), min(3600, ceil(target_count * per_host)))

    def _run_nmap(
        self,
        args: list[str],
        targets: list[str],
        timeout: int,
        cancel_event: threading.Event | None,
    ) -> tuple[bytes, float, str]:
        command = [self.executable, *args, "--reason", "-oX", "-", *targets]
        start_clock = time.monotonic()
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        with self._process_lock:
            self._active_process = process
        try:
            deadline = start_clock + timeout
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    self.cancel()
                    process.communicate()
                    raise NmapCancelledError("Nmap scan cancelled.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.cancel()
                    process.communicate()
                    raise NmapError(
                        f"Nmap timed out after {timeout} seconds. "
                        "Try Device discovery first, reduce the CIDR range, or use Quick ports."
                    )
                try:
                    stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
        finally:
            with self._process_lock:
                if self._active_process is process:
                    self._active_process = None

        duration = time.monotonic() - start_clock
        if cancel_event is not None and cancel_event.is_set():
            raise NmapCancelledError("Nmap scan cancelled.")
        if process.returncode != 0:
            message = stderr.decode("utf-8", errors="replace").strip()
            raise NmapError(message or f"Nmap exited with code {process.returncode}.")
        return stdout, duration, " ".join([*args, "--reason", *targets])

    def cancel(self) -> None:
        """Stop the active Nmap child process, if there is one."""
        with self._process_lock:
            process = self._active_process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

    def _global_discovery(
        self,
        target: str,
        cancel_event: threading.Event | None,
        started: datetime,
    ) -> NetworkScan:
        config = SCAN_PROFILES["global_discovery"]
        batches = self._discovery_batches(target, int(config["batch_size"]))
        aggregate = NetworkScan(
            target=target,
            profile="global_discovery",
            command="",
            started_at=started,
            finished_at=started,
            duration_seconds=0.0,
            hosts=[],
            findings=[],
            nmap_version="",
        )
        commands: list[str] = []
        for index, batch in enumerate(batches, start=1):
            stdout, duration, command = self._run_nmap(
                config["args"],
                batch,
                int(config["batch_timeout"]),
                cancel_event,
            )
            partial = parse_nmap_xml(
                stdout,
                target=",".join(batch),
                profile="global_discovery",
                command=command,
                started_at=started,
                finished_at=datetime.now(),
                duration_seconds=duration,
            )
            self._append_unique_hosts(aggregate.hosts, partial.hosts)
            aggregate.duration_seconds += duration
            aggregate.nmap_version = aggregate.nmap_version or partial.nmap_version
            commands.append(command)
            if len(batches) > 1:
                aggregate.findings = [
                    finding for finding in aggregate.findings
                    if finding.kind != "global_progress"
                ]
                aggregate.findings.append(ScanFinding(
                    severity="low",
                    kind="global_progress",
                    host=target,
                    title=f"Global discovery batches {index}/{len(batches)} completed",
                    detail=f"{len(aggregate.hosts)} live host(s) found so far.",
                ))
        aggregate.hosts = self._sort_hosts(aggregate.hosts)
        aggregate.findings = [
            finding for finding in aggregate.findings
            if finding.kind != "global_progress"
        ]
        aggregate.findings.append(ScanFinding(
            severity="low",
            kind="global_discovery",
            host=target,
            title="Global discovery completed",
            detail=(
                f"Explored {self._network_size(target):,} addresses in "
                f"{len(batches)} discovery batch(es). Port scans were skipped."
            ),
        ))
        aggregate.command = " | ".join(commands)
        aggregate.finished_at = datetime.now()
        return aggregate

    def scan(
        self,
        target: str,
        profile: str = "quick",
        cancel_event: threading.Event | None = None,
    ) -> NetworkScan:
        if not self.available:
            raise NmapError("Nmap was not found. Install it from nmap.org.")
        if cancel_event is not None and cancel_event.is_set():
            raise NmapCancelledError("Nmap scan cancelled.")
        target = self.validate_target(target)
        input_targets = self.parse_targets(target)
        if profile not in SCAN_PROFILES:
            raise ValueError(f"Unknown scan profile: {profile}")
        self._validate_interactive_scope(target, profile)
        config = SCAN_PROFILES[profile]
        started = datetime.now()
        if profile == "global_discovery":
            return self._global_discovery(target, cancel_event, started)

        targets = input_targets
        discovery_duration = 0.0
        findings: list[ScanFinding] = []
        discovery_command = ""
        discovery_scan: NetworkScan | None = None
        if profile != "discovery" and self._is_network_target(target):
            discovery_config = SCAN_PROFILES["discovery"]
            discovery_timeout = min(
                300,
                self._timeout_for(
                    {"timeout": 120, "per_host_timeout": 1},
                    self._network_size(target),
                ),
            )
            discovery_stdout, discovery_duration, discovery_command = self._run_nmap(
                discovery_config["args"],
                input_targets,
                discovery_timeout,
                cancel_event,
            )
            discovery_scan = parse_nmap_xml(
                discovery_stdout,
                target=target,
                profile="discovery",
                command=discovery_command,
                started_at=started,
                finished_at=datetime.now(),
                duration_seconds=discovery_duration,
            )
            targets = self._live_addresses(discovery_scan)
            if not targets:
                discovery_scan.profile = profile
                discovery_scan.command = (
                    f"{discovery_command} | no live hosts found; port scan skipped"
                )
                discovery_scan.duration_seconds = discovery_duration
                return discovery_scan
            max_hosts = int(config.get("max_hosts", len(targets)))
            if len(targets) > max_hosts:
                skipped = len(targets) - max_hosts
                targets = targets[:max_hosts]
                findings.append(ScanFinding(
                    severity="medium",
                    kind="scan_limited",
                    host=target,
                    title=f"Scan limited to {max_hosts} live hosts",
                    detail=(
                        f"{skipped} additional live host(s) were discovered but not "
                        "port-scanned to keep the operation responsive."
                    ),
                ))

        timeout = self._timeout_for(config, len(targets))
        stdout, duration, command = self._run_nmap(
            config["args"],
            targets,
            timeout,
            cancel_event,
        )
        total_duration = discovery_duration + duration
        if discovery_command:
            command = f"{discovery_command} | {command}"
        scan = parse_nmap_xml(
            stdout,
            target=target,
            profile=profile,
            command=command,
            started_at=started,
            finished_at=datetime.now(),
            duration_seconds=total_duration,
        )
        scan.findings.extend(findings)
        if discovery_scan is not None:
            self._merge_discovery_hosts(scan, discovery_scan)
        return scan


def _risk_for_service(service: ScanService) -> tuple[str, str]:
    if service.port in SUSPICIOUS_PORTS:
        return SUSPICIOUS_PORTS[service.port]
    name = service.name.lower()
    if name in {"telnet", "rlogin", "rexec"}:
        return "high", f"Legacy clear-text remote service detected: {service.name}."
    if name in {"ftp", "tftp"}:
        return "medium", f"Legacy file-transfer service detected: {service.name}."
    return "low", ""


def _risk_score(levels: Iterable[str]) -> int:
    weights = {"low": 10, "medium": 40, "high": 75}
    values = [weights.get(level, 0) for level in levels]
    return min(100, max(values, default=0) + max(0, len([v for v in values if v >= 40]) - 1) * 5)


def parse_nmap_xml(
    xml_data: bytes | str,
    *,
    target: str,
    profile: str,
    command: str = "",
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    duration_seconds: float = 0.0,
) -> NetworkScan:
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        raise NmapError(f"Nmap returned invalid XML: {exc}") from exc

    hosts: list[ScanHost] = []
    findings: list[ScanFinding] = []
    for node in root.findall("host"):
        status_node = node.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        addresses = node.findall("address")
        ipv4 = next((a.get("addr", "") for a in addresses if a.get("addrtype") == "ipv4"), "")
        ipv6 = next((a.get("addr", "") for a in addresses if a.get("addrtype") == "ipv6"), "")
        address = ipv4 or ipv6
        if not address:
            continue
        mac_node = next((a for a in addresses if a.get("addrtype") == "mac"), None)
        hostname_node = node.find("hostnames/hostname")
        os_node = node.find("os/osmatch")
        times_node = node.find("times")
        latency = None
        if times_node is not None and times_node.get("srtt", "").isdigit():
            latency = int(times_node.get("srtt")) / 1000.0

        services: list[ScanService] = []
        for port_node in node.findall("ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            service = ScanService(
                port=int(port_node.get("portid", "0")),
                protocol=port_node.get("protocol", "tcp"),
                state=state_node.get("state", "unknown") if state_node is not None else "unknown",
                name=service_node.get("name", "unknown") if service_node is not None else "unknown",
                product=service_node.get("product", "") if service_node is not None else "",
                version=service_node.get("version", "") if service_node is not None else "",
                extra_info=service_node.get("extrainfo", "") if service_node is not None else "",
                tunnel=service_node.get("tunnel", "") if service_node is not None else "",
            )
            if service.state == "open":
                service.risk_level, service.risk_reason = _risk_for_service(service)
                if service.risk_reason:
                    findings.append(ScanFinding(
                        severity=service.risk_level,
                        kind="exposed_service",
                        host=address,
                        title=f"{service.name or 'Service'} exposed on {service.port}/{service.protocol}",
                        detail=service.risk_reason,
                    ))
            services.append(service)
            for script_node in port_node.findall("script"):
                output = (script_node.get("output") or "").strip()
                if not output:
                    continue
                vulnerable = "VULNERABLE" in output.upper()
                findings.append(ScanFinding(
                    severity="high" if vulnerable else "medium",
                    kind="nmap_script",
                    host=address,
                    title=f"NSE {script_node.get('id', 'script')} on {service.port}/{service.protocol}",
                    detail=output[:1200],
                ))

        for script_node in node.findall("hostscript/script"):
            output = (script_node.get("output") or "").strip()
            if output:
                findings.append(ScanFinding(
                    severity="high" if "VULNERABLE" in output.upper() else "medium",
                    kind="nmap_script",
                    host=address,
                    title=f"NSE {script_node.get('id', 'script')}",
                    detail=output[:1200],
                ))

        open_services = [service for service in services if service.state == "open"]
        score = _risk_score(service.risk_level for service in open_services)
        level = "high" if score >= 70 else "medium" if score >= 35 else "low"
        hosts.append(ScanHost(
            address=address,
            status=status,
            hostname=hostname_node.get("name", "") if hostname_node is not None else "",
            mac=mac_node.get("addr", "") if mac_node is not None else "",
            vendor=mac_node.get("vendor", "") if mac_node is not None else "",
            os_name=os_node.get("name", "") if os_node is not None else "",
            latency_ms=latency,
            services=services,
            risk_score=score,
            risk_level=level,
        ))

    return NetworkScan(
        target=target,
        profile=profile,
        command=command,
        started_at=started_at or datetime.now(),
        finished_at=finished_at or datetime.now(),
        duration_seconds=duration_seconds,
        hosts=hosts,
        findings=findings,
        nmap_version=root.get("version", ""),
    )


def compare_scans(previous: NetworkScan | None, current: NetworkScan) -> list[ScanFinding]:
    if previous is None:
        return []
    findings: list[ScanFinding] = []
    old_hosts = {host.address: host for host in previous.hosts}
    new_hosts = {host.address: host for host in current.hosts}

    for address in sorted(new_hosts.keys() - old_hosts.keys()):
        host = new_hosts[address]
        findings.append(ScanFinding(
            severity="medium",
            kind="new_device",
            host=address,
            title="New device detected",
            detail=host.hostname or host.vendor or "This address was not present in the previous scan.",
        ))
    for address in sorted(old_hosts.keys() - new_hosts.keys()):
        findings.append(ScanFinding(
            severity="low",
            kind="missing_device",
            host=address,
            title="Device no longer detected",
            detail="The device was present in the previous scan but did not respond now.",
        ))

    for address in sorted(old_hosts.keys() & new_hosts.keys()):
        old = old_hosts[address]
        new = new_hosts[address]
        old_ports = {(s.protocol, s.port): s for s in old.open_ports}
        new_ports = {(s.protocol, s.port): s for s in new.open_ports}
        for key in sorted(new_ports.keys() - old_ports.keys()):
            service = new_ports[key]
            severity = service.risk_level if service.risk_level != "low" else "medium"
            findings.append(ScanFinding(
                severity=severity,
                kind="new_port",
                host=address,
                title=f"New open port {service.port}/{service.protocol}",
                detail=service.fingerprint or service.name,
            ))
        for key in sorted(old_ports.keys() - new_ports.keys()):
            service = old_ports[key]
            findings.append(ScanFinding(
                severity="low",
                kind="closed_port",
                host=address,
                title=f"Port closed {service.port}/{service.protocol}",
                detail=service.fingerprint or service.name,
            ))
        for key in sorted(old_ports.keys() & new_ports.keys()):
            old_service, new_service = old_ports[key], new_ports[key]
            if old_service.fingerprint != new_service.fingerprint:
                findings.append(ScanFinding(
                    severity="medium",
                    kind="service_changed",
                    host=address,
                    title=f"Service changed on {new_service.port}/{new_service.protocol}",
                    detail=f"{old_service.fingerprint or old_service.name} -> "
                           f"{new_service.fingerprint or new_service.name}",
                ))
    return findings
