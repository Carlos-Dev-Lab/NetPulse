"""Structured before/after comparison of network scans."""

from dataclasses import dataclass, field
import ipaddress

from netpulse.domain.network_scan import NetworkScan, ScanHost


@dataclass(slots=True)
class PortChange:
    address: str
    port: int
    protocol: str
    service: str
    change: str
    severity: str


@dataclass(slots=True)
class AddressChange:
    mac: str
    previous_address: str
    current_address: str


@dataclass(slots=True)
class ScanComparison:
    previous_id: int | None = None
    current_id: int | None = None
    previous_hosts: int = 0
    current_hosts: int = 0
    previous_ports: int = 0
    current_ports: int = 0
    previous_risk: int = 0
    current_risk: int = 0
    new_devices: list[str] = field(default_factory=list)
    missing_devices: list[str] = field(default_factory=list)
    address_changes: list[AddressChange] = field(default_factory=list)
    port_changes: list[PortChange] = field(default_factory=list)

    @property
    def risk_delta(self) -> int:
        return self.current_risk - self.previous_risk

    @property
    def has_baseline(self) -> bool:
        return self.previous_id is not None or self.previous_hosts > 0

    @property
    def total_changes(self) -> int:
        return (len(self.new_devices) + len(self.missing_devices)
                + len(self.address_changes) + len(self.port_changes))


def _address_key(value: str):
    try:
        return 0, int(ipaddress.ip_address(value))
    except ValueError:
        return 1, value.lower()


def _hosts_by_mac(hosts: list[ScanHost]) -> dict[str, ScanHost]:
    return {host.mac.upper(): host for host in hosts if host.mac}


def compare_scan_details(
    previous: NetworkScan | None, current: NetworkScan
) -> ScanComparison:
    result = ScanComparison(
        previous_id=previous.scan_id if previous else None,
        current_id=current.scan_id,
        previous_hosts=len(previous.hosts) if previous else 0,
        current_hosts=len(current.hosts),
        previous_ports=previous.open_port_count if previous else 0,
        current_ports=current.open_port_count,
        previous_risk=previous.risk_score if previous else 0,
        current_risk=current.risk_score,
    )
    if previous is None:
        return result

    old_by_address = {host.address: host for host in previous.hosts}
    new_by_address = {host.address: host for host in current.hosts}
    old_only = set(old_by_address) - set(new_by_address)
    new_only = set(new_by_address) - set(old_by_address)

    old_by_mac, new_by_mac = _hosts_by_mac(previous.hosts), _hosts_by_mac(current.hosts)
    for mac in sorted(set(old_by_mac) & set(new_by_mac)):
        old_host, new_host = old_by_mac[mac], new_by_mac[mac]
        if old_host.address != new_host.address:
            result.address_changes.append(AddressChange(mac, old_host.address, new_host.address))
            old_only.discard(old_host.address)
            new_only.discard(new_host.address)

    result.new_devices = sorted(new_only, key=_address_key)
    result.missing_devices = sorted(old_only, key=_address_key)

    for address in sorted(set(old_by_address) & set(new_by_address), key=_address_key):
        old_ports = {(service.protocol, service.port): service
                     for service in old_by_address[address].open_ports}
        new_ports = {(service.protocol, service.port): service
                     for service in new_by_address[address].open_ports}
        for key in sorted(set(new_ports) - set(old_ports), key=lambda item: (item[1], item[0])):
            service = new_ports[key]
            result.port_changes.append(PortChange(
                address, service.port, service.protocol, service.name,
                "opened", service.risk_level if service.risk_level != "low" else "medium",
            ))
        for key in sorted(set(old_ports) - set(new_ports), key=lambda item: (item[1], item[0])):
            service = old_ports[key]
            result.port_changes.append(PortChange(
                address, service.port, service.protocol, service.name, "closed", "low",
            ))
    return result
