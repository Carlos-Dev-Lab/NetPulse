"""End-to-end diagnostic for NetPulse."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import time
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def run_tests() -> None:
    result = subprocess.run(
        [sys.executable, "-W", "error::DeprecationWarning", "-m", "unittest", "discover", "-v"],
        cwd=ROOT,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("The automated test suite failed")


def check_capture() -> tuple[int, set[str], set[str], float]:
    from netpulse.infrastructure.sniffer import Sniffer

    sniffer = Sniffer()
    started = time.perf_counter()
    try:
        sniffer.start()
        time.sleep(0.5)
        with urllib.request.urlopen("https://example.com", timeout=8) as response:
            response.read(128)
        deadline = time.perf_counter() + 3
        packets = []
        while time.perf_counter() < deadline and not packets:
            time.sleep(0.2)
            packets.extend(sniffer.drain())
    finally:
        sniffer.stop()

    if not packets:
        raise RuntimeError("No packets were captured")
    return (
        len(packets),
        {packet.protocol for packet in packets},
        {packet.direction for packet in packets},
        time.perf_counter() - started,
    )


def check_realtime_pipeline() -> tuple[float, float, int]:
    from datetime import datetime

    from netpulse.domain.models import Packet
    from netpulse.domain.state import AppState
    from netpulse.presentation.app import UPDATE_INTERVAL_SECONDS

    state = AppState()
    intervals = []
    previous = time.perf_counter()
    target = previous

    for index in range(10):
        target += UPDATE_INTERVAL_SECONDS
        time.sleep(max(0, target - time.perf_counter()))
        current = time.perf_counter()
        intervals.append(current - previous)
        previous = current
        state.process(
            [
                Packet(
                    ts=datetime.now(),
                    direction="IN" if index % 2 == 0 else "OUT",
                    protocol="HTTPS",
                    src="1.1.1.1",
                    dst="10.0.0.2",
                    sport=443,
                    dport=5000,
                    size=1024,
                    remote="1.1.1.1",
                )
            ],
            intervals[-1],
        )

    average = sum(intervals) / len(intervals)
    maximum = max(intervals)
    if state.total_pkts != 10 or maximum > UPDATE_INTERVAL_SECONDS * 1.75:
        raise RuntimeError(
            f"Realtime cadence exceeded tolerance: average={average:.3f}s, max={maximum:.3f}s"
        )
    return average, maximum, state.total_pkts


def check_nmap() -> tuple[str, int, float]:
    from netpulse.infrastructure.nmap_scanner import NmapScanner

    scanner = NmapScanner()
    started = time.perf_counter()
    scan = scanner.scan("127.0.0.1", "discovery")
    if not scan.hosts:
        raise RuntimeError("Nmap did not report localhost as an active host")
    return scan.nmap_version or "unknown", len(scan.hosts), time.perf_counter() - started


def main() -> int:
    import flet
    import psutil
    import scapy

    print(f"Python: {sys.version.split()[0]}", flush=True)
    print(
        f"Flet: {flet.__version__}; Scapy: {scapy.__version__}; psutil: {psutil.__version__}",
        flush=True,
    )

    run_tests()
    average, maximum, processed = check_realtime_pipeline()
    print(
        f"Realtime pipeline: {processed} ticks; average={average:.3f}s; max={maximum:.3f}s"
    )

    nmap_version, hosts, nmap_seconds = check_nmap()
    print(
        f"Nmap: {nmap_version}; localhost discovery={hosts} host(s) "
        f"in {nmap_seconds:.3f}s"
    )

    try:
        count, protocols, directions, capture_seconds = check_capture()
        print(
            "Capture: "
            f"{count} packets in {capture_seconds:.3f}s; "
            f"protocols={sorted(protocols)}; directions={sorted(directions)}"
        )
    except Exception as exc:
        print(f"Capture: FAILED ({exc})")
        return 2

    print("SYSTEM_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
