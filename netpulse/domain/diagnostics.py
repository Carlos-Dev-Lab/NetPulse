"""Actionable diagnostics derived from consecutive network scans."""

from dataclasses import dataclass, field
import ipaddress

from netpulse.domain.network_scan import NetworkScan, ScanFinding, ScanService


SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}

PORT_GUIDANCE = {
    21: ("FTP puede exponer credenciales sin cifrado.",
         "Deshabilite FTP o sustitúyalo por SFTP; limite el acceso con firewall."),
    23: ("Telnet transmite credenciales y sesiones en texto claro.",
         "Deshabilite Telnet, use SSH y confirme que el puerto 23 quede cerrado."),
    445: ("SMB expuesto facilita movimiento lateral y ataques contra archivos compartidos.",
          "Restrinja SMB a equipos autorizados, aplique parches y bloquee el puerto 445 entre segmentos con el firewall."),
    3389: ("RDP expuesto es un objetivo frecuente de fuerza bruta y robo de credenciales.",
           "Limite RDP por VPN o firewall, active NLA y autenticación multifactor."),
    5900: ("VNC puede permitir control remoto del dispositivo.",
           "Restrinja VNC a una red administrativa y use cifrado y credenciales robustas."),
}

KIND_GUIDANCE = {
    "new_device": (
        "El dispositivo no estaba presente en el análisis anterior.",
        "Identifique al propietario y confirme si el dispositivo está autorizado.",
    ),
    "unknown_device": (
        "El dispositivo todavía no fue clasificado en el inventario.",
        "Identifique al propietario y márquelo como conocido, autorizado o bloqueado.",
    ),
    "missing_device": (
        "El dispositivo dejó de responder o abandonó la red.",
        "Compruebe su conectividad y confirme que la ausencia sea esperada.",
    ),
    "new_port": (
        "Un servicio comenzó a aceptar conexiones desde la red.",
        "Valide que el servicio sea necesario y restrinja su acceso en el firewall.",
    ),
    "service_changed": (
        "La identificación o versión del servicio cambió desde el análisis anterior.",
        "Confirme que el cambio fue autorizado y que la versión esté actualizada.",
    ),
    "nmap_script": (
        "Un script de Nmap reportó una condición que requiere revisión.",
        "Revise la evidencia, confirme el hallazgo y aplique la actualización recomendada por el fabricante.",
    ),
    "scan_limited": (
        "No todos los dispositivos descubiertos fueron analizados en profundidad.",
        "Divida la red en objetivos menores y repita el análisis para obtener cobertura completa.",
    ),
}


@dataclass(slots=True)
class DiagnosticItem:
    severity: str
    status: str
    kind: str
    host: str
    title: str
    why: str
    recommendation: str
    evidence: str = ""


@dataclass(slots=True)
class DiagnosticSummary:
    items: list[DiagnosticItem] = field(default_factory=list)
    new_devices: int = 0
    missing_devices: int = 0
    active_issues: int = 0
    resolved_issues: int = 0

    @property
    def priority(self) -> DiagnosticItem | None:
        return next((item for item in self.items if item.status == "active"), None)


@dataclass(slots=True)
class ServiceExplanation:
    title: str
    risk: str
    why: str
    recommendation: str
    verification: str


def _port_from_finding(finding: ScanFinding) -> int | None:
    for token in finding.title.replace("/", " ").split():
        if token.isdigit():
            return int(token)
    return None


def _guidance(finding: ScanFinding) -> tuple[str, str]:
    port = _port_from_finding(finding)
    if port in PORT_GUIDANCE:
        return PORT_GUIDANCE[port]
    return KIND_GUIDANCE.get(
        finding.kind,
        ("El análisis detectó una condición relevante para la seguridad o disponibilidad.",
         "Revise la evidencia y confirme si el comportamiento es esperado."),
    )


def _service_key(host: str, service: ScanService) -> tuple[str, str, int]:
    return host, service.protocol, service.port


def _host_sort_key(host: str) -> tuple[int, int | str]:
    """Sort IP addresses numerically and non-IP targets alphabetically last."""
    try:
        return 0, int(ipaddress.ip_address(host))
    except ValueError:
        return 1, host.lower()


def build_diagnostics(
    previous: NetworkScan | None, current: NetworkScan
) -> DiagnosticSummary:
    """Build prioritized, actionable and resolution-aware scan diagnostics."""
    summary = DiagnosticSummary()
    ignored = {"closed_port", "global_progress", "global_discovery"}
    for finding in current.findings:
        if finding.kind in ignored or finding.severity not in SEVERITY_WEIGHT:
            continue
        why, recommendation = _guidance(finding)
        summary.items.append(DiagnosticItem(
            severity=finding.severity,
            status="active",
            kind=finding.kind,
            host=finding.host,
            title=finding.title,
            why=why,
            recommendation=recommendation,
            evidence=finding.detail,
        ))
        summary.new_devices += finding.kind == "new_device"
        summary.missing_devices += finding.kind == "missing_device"

    if previous is not None:
        old_services = {
            _service_key(host.address, service): service
            for host in previous.hosts for service in host.open_ports
            if service.risk_level in {"medium", "high"}
        }
        new_services = {
            _service_key(host.address, service)
            for host in current.hosts for service in host.open_ports
        }
        for (host, protocol, port), service in old_services.items():
            if (host, protocol, port) in new_services:
                continue
            why, recommendation = PORT_GUIDANCE.get(
                port,
                (service.risk_reason or "El servicio presentaba exposición relevante.",
                 "Mantenga el servicio cerrado y verifique que no vuelva a exponerse."),
            )
            summary.items.append(DiagnosticItem(
                severity=service.risk_level,
                status="resolved",
                kind="resolved_port",
                host=host,
                title=f"Puerto {port}/{protocol} ya no está expuesto",
                why=why,
                recommendation="Verifique que el cierre sea intencional y mantenga el control aplicado. "
                               + recommendation,
                evidence=service.fingerprint or service.name,
            ))

    summary.items.sort(key=lambda item: (
        _host_sort_key(item.host), item.status != "active",
        -SEVERITY_WEIGHT.get(item.severity, 0), item.title,
    ))
    summary.active_issues = sum(item.status == "active" for item in summary.items)
    summary.resolved_issues = sum(item.status == "resolved" for item in summary.items)
    return summary


def findings_for_host(scan: NetworkScan, address: str) -> list[ScanFinding]:
    """Return only findings that belong to the explicitly selected host."""
    if not address:
        return []
    return [finding for finding in scan.findings if finding.host == address]


def explain_service(address: str, service: ScanService) -> ServiceExplanation:
    """Explain an exposed service and provide a bounded verification command."""
    why, recommendation = PORT_GUIDANCE.get(
        service.port,
        (service.risk_reason or
         "Un puerto abierto permite que otros equipos se conecten a este servicio.",
         "Confirme que el servicio sea necesario, esté actualizado y limitado por firewall."),
    )
    fingerprint = service.fingerprint or service.name
    return ServiceExplanation(
        title=f"{service.port}/{service.protocol} · {fingerprint}",
        risk=service.risk_level,
        why=why,
        recommendation=recommendation,
        verification=f"nmap -sV -p {service.port} {address}",
    )


def scheduled_scan_message(
    scan: NetworkScan, changes_only: bool,
    initial_unknown_addresses: list[str] | None = None,
) -> tuple[str, list[ScanFinding]] | None:
    """Return a concise notification only when schedule policy allows it."""
    relevant = [
        finding for finding in scan.findings
        if finding.kind in {"new_device", "new_port", "service_changed", "nmap_script"}
        and finding.severity in {"medium", "high"}
    ]
    relevant.extend(
        ScanFinding(
            severity="medium", kind="unknown_device", host=address,
            title="Unknown device requires classification",
            detail="First scheduled baseline; inventory status is new.",
        )
        for address in (initial_unknown_addresses or [])
    )
    relevant.sort(key=lambda item: (item.severity != "high", item.host, item.title))
    if changes_only and not relevant:
        return None
    if relevant:
        priority = relevant[0]
        return (
            f"{len(relevant)} relevant change(s). Priority: "
            f"{priority.host} - {priority.title}",
            relevant,
        )
    return f"Completed with {len(scan.hosts)} devices and no relevant changes.", []
