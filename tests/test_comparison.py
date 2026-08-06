from datetime import datetime
import unittest

from netpulse.domain.comparison import compare_scan_details
from netpulse.domain.network_scan import NetworkScan, ScanHost, ScanService


def make_scan(hosts, scan_id):
    now = datetime(2026, 1, 1)
    return NetworkScan("10.0.0.0/24", "quick", "nmap", now, now, 1,
                       hosts=hosts, scan_id=scan_id)


class ComparisonTests(unittest.TestCase):
    def test_detects_devices_ip_changes_ports_and_risk_delta(self):
        old = make_scan([
            ScanHost("10.0.0.2", mac="AA", services=[
                ScanService(80, "tcp", "open", "http")]),
            ScanHost("10.0.0.20", mac="BB", risk_score=40, risk_level="medium"),
            ScanHost("10.0.0.30", mac="CC"),
        ], 1)
        current = make_scan([
            ScanHost("10.0.0.2", mac="AA", services=[
                ScanService(445, "tcp", "open", "microsoft-ds", risk_level="medium")]),
            ScanHost("10.0.0.25", mac="BB", risk_score=75, risk_level="high"),
            ScanHost("10.0.0.10", mac="DD"),
        ], 2)

        result = compare_scan_details(old, current)

        self.assertEqual(result.new_devices, ["10.0.0.10"])
        self.assertEqual(result.missing_devices, ["10.0.0.30"])
        self.assertEqual(result.address_changes[0].previous_address, "10.0.0.20")
        self.assertEqual(result.address_changes[0].current_address, "10.0.0.25")
        self.assertEqual([(item.port, item.change) for item in result.port_changes],
                         [(445, "opened"), (80, "closed")])
        self.assertEqual(result.risk_delta, 35)
        self.assertEqual(result.total_changes, 5)

    def test_first_scan_has_no_false_changes(self):
        current = make_scan([ScanHost("10.0.0.2")], 1)
        result = compare_scan_details(None, current)
        self.assertFalse(result.has_baseline)
        self.assertEqual(result.total_changes, 0)


if __name__ == "__main__":
    unittest.main()
