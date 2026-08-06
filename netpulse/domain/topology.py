"""Build a lightweight network topology from scan and inventory data."""

from dataclasses import dataclass, field
import ipaddress

from netpulse.domain.network_scan import NetworkScan


@dataclass(slots=True)
class TopologyNode:
    address: str
    label: str
    role: str
    risk_level: str
    trust_status: str


@dataclass(slots=True)
class TopologySegment:
    network: str
    nodes: list[TopologyNode] = field(default_factory=list)


def build_topology(
    scan: NetworkScan,
    inventory: list[dict],
    local_addresses: set[str] | None = None,
) -> list[TopologySegment]:
    local_addresses = local_addresses or set()
    inventory_by_ip = {item["address"]: item for item in inventory}
    segments: dict[str, TopologySegment] = {}
    for host in scan.hosts:
        try:
            address = ipaddress.ip_address(host.address)
            network = ipaddress.ip_network(f"{address}/24", strict=False).with_prefixlen
            last_octet = int(str(address).rsplit(".", 1)[-1]) if address.version == 4 else -1
        except ValueError:
            network, last_octet = "Other targets", -1
        item = inventory_by_ip.get(host.address, {})
        role = "local" if host.address in local_addresses else "router" if last_octet == 1 else "device"
        label = item.get("alias") or host.hostname or item.get("detected_name") or host.address
        segments.setdefault(network, TopologySegment(network)).nodes.append(TopologyNode(
            address=host.address, label=label, role=role,
            risk_level=host.risk_level, trust_status=item.get("trust_status", "new"),
        ))
    for segment in segments.values():
        segment.nodes.sort(key=lambda node: int(ipaddress.ip_address(node.address))
                           if _is_ip(node.address) else node.address)
    return sorted(segments.values(), key=lambda segment: segment.network)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
