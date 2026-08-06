"""Read-only inspection of ports listening on the local machine."""

from dataclasses import dataclass
import socket

import psutil


SENSITIVE_PORTS = {
    21: ("high", "FTP puede exponer credenciales sin cifrado."),
    23: ("high", "Telnet transmite credenciales en texto claro."),
    135: ("medium", "RPC de Windows debe limitarse a redes confiables."),
    139: ("medium", "NetBIOS puede exponer recursos del equipo."),
    445: ("high", "SMB debe estar restringido a equipos autorizados."),
    3389: ("high", "RDP debe limitarse mediante firewall, VPN y NLA."),
    5900: ("high", "VNC permite control remoto del equipo."),
}


@dataclass(slots=True)
class LocalListener:
    address: str
    port: int
    protocol: str
    family: str
    pid: int | None
    process: str
    service: str
    exposure: str
    risk_level: str
    explanation: str


def _service_name(port: int, protocol: str) -> str:
    try:
        return socket.getservbyport(port, protocol.lower())
    except OSError:
        return "desconocido"


def _exposure(address: str) -> str:
    normalized = (address or "").split("%", 1)[0].lower()
    if normalized in {"127.0.0.1", "::1"}:
        return "local"
    if normalized in {"0.0.0.0", "::", "*", ""}:
        return "all_interfaces"
    return "network_interface"


def list_local_listeners() -> list[LocalListener]:
    """Return deduplicated TCP listeners and bound UDP sockets."""
    listeners: list[LocalListener] = []
    seen = set()
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return listeners

    for connection in connections:
        protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
        if protocol == "TCP" and connection.status != psutil.CONN_LISTEN:
            continue
        if not connection.laddr:
            continue
        address, port = connection.laddr.ip, int(connection.laddr.port)
        key = (address, port, protocol, connection.pid)
        if key in seen:
            continue
        seen.add(key)
        process = "Sistema" if connection.pid in {0, 4} else "Desconocido"
        if connection.pid not in {None, 0, 4}:
            try:
                process = psutil.Process(connection.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass
        exposure = _exposure(address)
        risk_level, explanation = SENSITIVE_PORTS.get(
            port,
            ("low", "Puerto local en escucha; confirme que el proceso sea esperado."),
        )
        if exposure == "local" and risk_level == "high":
            risk_level = "medium"
        listeners.append(LocalListener(
            address=address, port=port, protocol=protocol,
            family="IPv6" if connection.family == socket.AF_INET6 else "IPv4",
            pid=connection.pid, process=process,
            service=_service_name(port, protocol), exposure=exposure,
            risk_level=risk_level, explanation=explanation,
        ))
    return sorted(listeners, key=lambda item: (
        {"high": 0, "medium": 1, "low": 2}[item.risk_level],
        item.port, item.protocol, item.address,
    ))
