from datetime import datetime
import unittest

from netpulse.domain.health import calculate_network_health
from netpulse.domain.network_scan import NetworkScan, ScanFinding, ScanHost, ScanService


def make_scan(hosts=None, findings=None):
    now = datetime(2026, 1, 1)
    return NetworkScan("10.0.0.0/24", "services", "nmap", now, now, 1,
                       hosts=hosts or [], findings=findings or [])


class HealthTests(unittest.TestCase):
    def test_clean_authorized_network_scores_100(self):
        scan = make_scan([ScanHost("10.0.0.2")])
        health = calculate_network_health(
            scan, [{"address": "10.0.0.2", "trust_status": "authorized"}]
        )
        self.assertEqual(health.score, 100)
        self.assertEqual(health.level, "excellent")
        self.assertEqual(health.factors, [])

    def test_score_lists_exact_deductions_and_clamps_at_zero(self):
        hosts = [ScanHost(
            "10.0.0.2", services=[
                ScanService(23, "tcp", "open", "telnet", risk_level="high"),
                ScanService(445, "tcp", "open", "smb", risk_level="medium"),
            ],
        ), ScanHost("10.0.0.3")]
        findings = [
            ScanFinding("high", "new_port", "10.0.0.2", "New port", "23"),
            ScanFinding("high", "nmap_script", "10.0.0.2", "Vulnerable", "evidence"),
            ScanFinding("medium", "scan_limited", "10.0.0.0/24", "Limited", "coverage"),
        ]
        inventory = [
            {"address": "10.0.0.2", "trust_status": "blocked"},
            {"address": "10.0.0.3", "trust_status": "new"},
        ]
        health = calculate_network_health(make_scan(hosts, findings), inventory)

        self.assertEqual(health.score, 34)
        self.assertEqual(health.level, "critical")
        self.assertEqual(health.total_deduction, 66)
        self.assertEqual(
            {factor.label: factor.deduction for factor in health.factors},
            {
                "Blocked devices online": 20,
                "High-risk exposed services": 12,
                "Incomplete scan coverage": 10,
                "Medium-risk exposed services": 6,
                "Nmap script findings": 10,
                "Relevant recent changes": 3,
                "Unclassified devices": 5,
            },
        )

    def test_repeated_severe_factors_never_make_score_negative(self):
        services = [ScanService(port, "tcp", "open", "unsafe", risk_level="high")
                    for port in range(1, 20)]
        hosts = [ScanHost(f"10.0.0.{index}", services=services) for index in range(1, 6)]
        inventory = [{"address": host.address, "trust_status": "blocked"} for host in hosts]
        findings = [
            ScanFinding("high", "nmap_script", "10.0.0.1", f"Finding {index}", "evidence")
            for index in range(3)
        ] + [
            ScanFinding("high", "new_port", "10.0.0.1", f"Port {index}", "open")
            for index in range(2)
        ]
        health = calculate_network_health(make_scan(hosts, findings), inventory)
        self.assertEqual(health.score, 0)


if __name__ == "__main__":
    unittest.main()
