from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import threading
import unittest
from unittest import mock

from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import (
    NmapCancelledError,
    NmapError,
    NmapScanner,
    compare_scans,
    parse_nmap_xml,
)


SCAN_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" reason="syn-ack" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example Corp" />
    <hostnames><hostname name="nas.local" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0" />
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" />
        <service name="telnet" product="Legacy console" />
        <script id="test-vuln" output="VULNERABLE: example finding" />
      </port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95" /></os>
    <times srtt="1250" />
  </host>
</nmaprun>"""

DISCOVERY_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99">
  <host><status state="up" /><address addr="192.168.1.10" addrtype="ipv4" /></host>
  <host><status state="up" /><address addr="192.168.1.11" addrtype="ipv4" /></host>
</nmaprun>"""

PORT_SCAN_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99">
  <host>
    <status state="up" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="Example HTTP" />
      </port>
    </ports>
  </host>
</nmaprun>"""


class NmapTests(unittest.TestCase):
    def _scan(self):
        return parse_nmap_xml(
            SCAN_XML,
            target="192.168.1.0/24",
            profile="services",
            command="-sT -sV 192.168.1.0/24",
            started_at=datetime(2026, 1, 1, 10, 0, 0),
            finished_at=datetime(2026, 1, 1, 10, 0, 2),
            duration_seconds=2.0,
        )

    def test_parse_risk_services_and_nse_findings(self):
        scan = self._scan()
        self.assertEqual(scan.nmap_version, "7.99")
        self.assertEqual(len(scan.hosts), 1)
        host = scan.hosts[0]
        self.assertEqual(host.hostname, "nas.local")
        self.assertEqual(host.vendor, "Example Corp")
        self.assertEqual(host.open_ports[1].risk_level, "high")
        self.assertEqual(host.risk_level, "high")
        self.assertTrue(any(f.kind == "nmap_script" for f in scan.findings))

    def test_compare_and_database_roundtrip(self):
        previous = parse_nmap_xml(
            SCAN_XML.replace(b'portid="23"', b'portid="80"').replace(
                b'name="telnet"', b'name="http"'
            ),
            target="192.168.1.0/24",
            profile="services",
        )
        current = self._scan()
        current.findings.extend(compare_scans(previous, current))
        self.assertTrue(any(f.kind == "new_port" for f in current.findings))
        self.assertTrue(any(f.kind == "closed_port" for f in current.findings))

        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "scan.db")
            scan_id = db.save_network_scan(current)
            loaded = db.get_network_scan(scan_id)
            self.assertEqual(loaded.target, current.target)
            self.assertEqual(loaded.hosts[0].open_ports[1].port, 23)
            self.assertEqual(len(loaded.findings), len(current.findings))
            self.assertEqual(db.list_network_scans()[0]["host_count"], 1)

    def test_scan_honors_cancellation_before_starting_process(self):
        cancel_event = threading.Event()
        cancel_event.set()
        scanner = NmapScanner(executable=sys.executable)

        with self.assertRaises(NmapCancelledError):
            scanner.scan("127.0.0.1", "discovery", cancel_event)
        self.assertIsNone(scanner._active_process)

    def test_cidr_port_scan_discovers_live_hosts_first(self):
        calls = []

        class FakeProcess:
            outputs = [DISCOVERY_XML, PORT_SCAN_XML]

            def __init__(self, command, **kwargs):
                self.command = command
                self.returncode = 0
                calls.append(command)

            def communicate(self, timeout=None):
                return self.outputs.pop(0), b""

            def poll(self):
                return self.returncode

        scanner = NmapScanner(executable=sys.executable)
        with mock.patch("netpulse.infrastructure.nmap_scanner.subprocess.Popen", FakeProcess):
            scan = scanner.scan("192.168.1.0/24", "quick")

        self.assertEqual(len(calls), 2)
        self.assertIn("-sn", calls[0])
        self.assertIn("192.168.1.0/24", calls[0])
        self.assertNotIn("192.168.1.0/24", calls[1])
        self.assertIn("192.168.1.10", calls[1])
        self.assertIn("192.168.1.11", calls[1])
        self.assertEqual(len(scan.hosts), 2)
        self.assertEqual(scan.open_port_count, 1)
        self.assertIn("|", scan.command)

    def test_large_cidr_fails_fast_before_starting_nmap(self):
        scanner = NmapScanner(executable=sys.executable)
        with mock.patch(
            "netpulse.infrastructure.nmap_scanner.subprocess.Popen",
            side_effect=AssertionError("Nmap should not start for oversized CIDR"),
        ):
            with self.assertRaises(NmapError) as ctx:
                scanner.scan("172.26.0.0/16", "quick")

        message = str(ctx.exception)
        self.assertIn("65,536 addresses", message)
        self.assertIn("too large", message)
        self.assertIn("Global discovery", message)

    def test_multiple_cidrs_are_discovered_in_one_scan(self):
        calls = []

        class FakeProcess:
            def __init__(self, command, **kwargs):
                self.command = command
                self.returncode = 0
                calls.append(command)

            def communicate(self, timeout=None):
                return DISCOVERY_XML, b""

            def poll(self):
                return self.returncode

        scanner = NmapScanner(executable=sys.executable)
        with mock.patch("netpulse.infrastructure.nmap_scanner.subprocess.Popen", FakeProcess):
            scan = scanner.scan("172.26.4.0/24, 172.26.3.0/24", "discovery")

        self.assertEqual(len(calls), 1)
        self.assertIn("172.26.4.0/24", calls[0])
        self.assertIn("172.26.3.0/24", calls[0])
        self.assertEqual(scan.target, "172.26.4.0/24, 172.26.3.0/24")

    def test_multiple_targets_share_the_scope_limit(self):
        scanner = NmapScanner(executable=sys.executable)
        targets = " ".join(f"10.0.{index}.0/24" for index in range(17))
        with self.assertRaises(NmapError) as ctx:
            scanner.scan(targets, "quick")
        self.assertIn("4,352 addresses", str(ctx.exception))

    def test_global_discovery_allows_large_cidr_in_discovery_batches(self):
        calls = []

        class FakeProcess:
            def __init__(self, command, **kwargs):
                self.command = command
                self.returncode = 0
                calls.append(command)

            def communicate(self, timeout=None):
                return DISCOVERY_XML, b""

            def poll(self):
                return self.returncode

        scanner = NmapScanner(executable=sys.executable)
        with mock.patch("netpulse.infrastructure.nmap_scanner.subprocess.Popen", FakeProcess):
            scan = scanner.scan("172.26.0.0/16", "global_discovery")

        self.assertEqual(len(calls), 16)
        self.assertTrue(all("-sn" in call for call in calls))
        self.assertTrue(all("--top-ports" not in call for call in calls))
        self.assertEqual(scan.profile, "global_discovery")
        self.assertEqual(len(scan.hosts), 2)
        self.assertEqual(scan.open_port_count, 0)
        self.assertTrue(any(f.kind == "global_discovery" for f in scan.findings))


if __name__ == "__main__":
    unittest.main()
