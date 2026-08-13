"""Conservative network-quality measurements for the Performance view."""

from __future__ import annotations

import re
import socket
import statistics
import subprocess
import time
import psutil
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class QualityResult:
    target: str
    samples: int
    received: int
    latency_ms: float | None
    jitter_ms: float | None
    loss_percent: float | None
    dns_ms: float | None
    internet_reachable: bool | None
    note: str = ""

    @property
    def confidence(self) -> str:
        return "sufficient" if self.received >= 3 else "insufficient"


def parse_ping_latencies(output: str) -> list[float]:
    """Extract reply times without depending on the Windows display language."""
    values = []
    for line in output.splitlines():
        match = re.search(r"(?:time|tiempo)[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", line, re.I)
        if match:
            values.append(float(match.group(1).replace(",", ".")))
    return values


def default_gateway(command_runner: Callable = subprocess.run) -> str | None:
    """Return the lowest-metric IPv4 default gateway reported by Windows."""
    try:
        completed = command_runner(
            ["route", "print", "-4", "0.0.0.0"], capture_output=True,
            text=True, timeout=5, errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None
    candidates = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == parts[1] == "0.0.0.0":
            try:
                socket.inet_aton(parts[2])
                candidates.append((int(parts[4]), parts[2]))
            except (OSError, ValueError):
                continue
    return min(candidates)[1] if candidates else None


def measure_quality(
    target: str | None = None,
    samples: int = 4,
    command_runner: Callable = subprocess.run,
    resolver: Callable = socket.getaddrinfo,
    connector: Callable = socket.create_connection,
) -> QualityResult:
    """Measure quality; unknown evidence remains unknown instead of becoming an alert."""
    target = target or default_gateway(command_runner)
    if not target:
        return QualityResult("Not detected", samples, 0, None, None, None, None, None,
                             "No IPv4 default gateway was detected.")

    latencies: list[float] = []
    try:
        ping = command_runner(
            ["ping", "-n", str(samples), "-w", "1200", target],
            capture_output=True, text=True, timeout=samples * 2 + 3, errors="replace",
        )
        latencies = parse_ping_latencies(ping.stdout)
    except (OSError, subprocess.SubprocessError):
        pass

    latency = statistics.fmean(latencies) if latencies else None
    jitter = (
        statistics.fmean(abs(b - a) for a, b in zip(latencies, latencies[1:]))
        if len(latencies) >= 2 else None
    )
    loss = ((samples - len(latencies)) * 100.0 / samples
            if len(latencies) >= 3 else None)

    dns_ms = None
    try:
        started = time.perf_counter()
        resolver("example.com", 443, type=socket.SOCK_STREAM)
        dns_ms = (time.perf_counter() - started) * 1000
    except OSError:
        pass

    reachable = None
    successful_endpoints = 0
    attempted_endpoints = 0
    for endpoint in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        attempted_endpoints += 1
        try:
            connection = connector(endpoint, timeout=1.5)
            connection.close()
            successful_endpoints += 1
        except OSError:
            continue
    if successful_endpoints:
        reachable = True
    elif attempted_endpoints == 2:
        # Local or upstream firewalls may block both endpoints. A failed active
        # probe is therefore inconclusive, never proof of an Internet outage.
        reachable = None

    note = ""
    if len(latencies) < 3:
        note = "ICMP evidence is insufficient; latency and loss are not classified."
    return QualityResult(target, samples, len(latencies), latency, jitter, loss,
                         dns_ms, reachable, note)


def classify_quality(result: QualityResult) -> tuple[str, str]:
    """Return a label and reason using minimum evidence thresholds."""
    if result.confidence != "sufficient":
        return "INSUFFICIENT DATA", result.note
    issues = []
    if result.loss_percent is not None and result.loss_percent >= 5:
        issues.append(f"loss {result.loss_percent:.0f}%")
    if result.jitter_ms is not None and result.jitter_ms >= 30:
        issues.append(f"jitter {result.jitter_ms:.0f} ms")
    if result.latency_ms is not None and result.latency_ms >= 100:
        issues.append(f"latency {result.latency_ms:.0f} ms")
    return (("REVIEW", ", ".join(issues)) if issues else
            ("STABLE", "Gateway samples show no degradation."))


def _outbound_ip(target: str, socket_factory: Callable = socket.socket) -> str | None:
    """Resolve the local IPv4 selected by the OS route table without sending data."""
    probe = None
    try:
        probe = socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((target, 53))
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        if probe is not None:
            probe.close()


def adapter_capacity(interface: str = "All", gateway: str | None = None,
                     socket_factory: Callable = socket.socket) -> dict:
    """Return the link speed for the adapter selected by the actual OS route."""
    try:
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
    except Exception:
        return {"name": "Not detected", "speed_mbps": None, "up": None}
    routed_ip = _outbound_ip(gateway or "1.1.1.1", socket_factory)
    routed_names = {
        name for name, items in addresses.items()
        if any(getattr(item, "address", None) == routed_ip for item in items)
    }
    candidates = [
        (name, item) for name, item in stats.items()
        if item.isup and item.speed and item.speed > 0
        and (name in routed_names if routed_names else
             interface not in ("", "All") and name == interface)
    ]
    if not candidates:
        return {"name": interface if interface not in ("", "All") else "Not detected",
                "speed_mbps": None, "up": None, "local_ip": routed_ip}
    name, item = candidates[0]
    return {"name": name, "speed_mbps": float(item.speed), "up": bool(item.isup),
            "local_ip": routed_ip}


def quality_trend(rows: list[dict], minimum: int = 5) -> tuple[str, str]:
    """Compare recent and earlier valid measurements only with enough evidence."""
    valid = [row for row in rows if row.get("received", 0) >= 3
             and row.get("latency_ms") is not None]
    if len(valid) < minimum:
        return "INSUFFICIENT DATA", f"{len(valid)}/{minimum} valid checks"
    recent = valid[:2]
    baseline = valid[2:minimum]
    recent_avg = statistics.fmean(row["latency_ms"] for row in recent)
    baseline_avg = statistics.fmean(row["latency_ms"] for row in baseline)
    increase = recent_avg - baseline_avg
    if increase >= 20 and recent_avg >= baseline_avg * 1.5:
        return "DEGRADING", f"Recent latency increased by {increase:.1f} ms"
    return "NO DEGRADATION", f"Recent {recent_avg:.1f} ms vs baseline {baseline_avg:.1f} ms"


def checks_needed_for_trend(rows: list[dict], minimum: int = 5) -> int:
    """Return how many checks one click should run to establish a trend baseline."""
    valid_count = sum(
        row.get("received", 0) >= 3 and row.get("latency_ms") is not None
        for row in rows
    )
    return max(1, minimum - valid_count)
