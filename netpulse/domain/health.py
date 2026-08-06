"""Explainable network health score derived from scan and inventory evidence."""

from dataclasses import dataclass, field

from netpulse.domain.network_scan import NetworkScan


@dataclass(slots=True)
class HealthFactor:
    label: str
    deduction: int
    explanation: str
    severity: str


@dataclass(slots=True)
class NetworkHealth:
    score: int
    level: str
    factors: list[HealthFactor] = field(default_factory=list)

    @property
    def total_deduction(self) -> int:
        return sum(factor.deduction for factor in self.factors)


def _level(score: int) -> str:
    if score >= 90:
        return "excellent"
    if score >= 75:
        return "good"
    if score >= 60:
        return "attention"
    return "critical"


def calculate_network_health(scan: NetworkScan, inventory: list[dict]) -> NetworkHealth:
    """Return a 0-100 score and every evidence-backed deduction."""
    factors: list[HealthFactor] = []
    by_ip = {item.get("address", ""): item for item in inventory}

    high_services = sum(
        service.risk_level == "high" for host in scan.hosts for service in host.open_ports
    )
    medium_services = sum(
        service.risk_level == "medium" for host in scan.hosts for service in host.open_ports
    )
    if high_services:
        deduction = min(36, high_services * 12)
        factors.append(HealthFactor(
            "High-risk exposed services", deduction,
            f"{high_services} high-risk open service(s), 12 points each (maximum 36).", "high",
        ))
    if medium_services:
        deduction = min(24, medium_services * 6)
        factors.append(HealthFactor(
            "Medium-risk exposed services", deduction,
            f"{medium_services} medium-risk open service(s), 6 points each (maximum 24).", "medium",
        ))

    unclassified = [host.address for host in scan.hosts
                    if by_ip.get(host.address, {}).get("trust_status", "new") == "new"]
    if unclassified:
        deduction = min(20, len(unclassified) * 5)
        factors.append(HealthFactor(
            "Unclassified devices", deduction,
            f"{len(unclassified)} device(s) remain new in inventory, 5 points each (maximum 20).", "medium",
        ))
    blocked = [host.address for host in scan.hosts
               if by_ip.get(host.address, {}).get("trust_status") == "blocked"]
    if blocked:
        deduction = min(40, len(blocked) * 20)
        factors.append(HealthFactor(
            "Blocked devices online", deduction,
            f"{len(blocked)} blocked device(s) responded, 20 points each (maximum 40).", "high",
        ))

    relevant_changes = sum(
        finding.kind in {"new_device", "new_port", "service_changed"}
        and finding.severity in {"medium", "high"}
        for finding in scan.findings
    )
    if relevant_changes:
        deduction = min(15, relevant_changes * 3)
        factors.append(HealthFactor(
            "Relevant recent changes", deduction,
            f"{relevant_changes} security-relevant change(s), 3 points each (maximum 15).", "medium",
        ))

    script_findings = sum(
        finding.kind == "nmap_script" and finding.severity in {"medium", "high"}
        for finding in scan.findings
    )
    if script_findings:
        deduction = min(20, script_findings * 10)
        factors.append(HealthFactor(
            "Nmap script findings", deduction,
            f"{script_findings} relevant script finding(s), 10 points each (maximum 20).", "high",
        ))
    if any(finding.kind == "scan_limited" for finding in scan.findings):
        factors.append(HealthFactor(
            "Incomplete scan coverage", 10,
            "Some discovered devices were not port-scanned; the result has incomplete coverage.", "medium",
        ))

    score = max(0, 100 - sum(factor.deduction for factor in factors))
    factors.sort(key=lambda factor: (-factor.deduction, factor.label))
    return NetworkHealth(score=score, level=_level(score), factors=factors)
