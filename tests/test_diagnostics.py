from datetime import datetime
import unittest

from netpulse.domain.diagnostics import (
    build_diagnostics, explain_service, findings_for_host, scheduled_scan_message,
)
from netpulse.domain.network_scan import (
    NetworkScan, ScanFinding, ScanHost, ScanService,
)


def scan(hosts=None, findings=None, scan_id=None):
    now = datetime(2026, 1, 1)
    return NetworkScan(
        target="172.26.3.0/24", profile="quick", command="nmap",
        started_at=now, finished_at=now, duration_seconds=1,
        hosts=hosts or [], findings=findings or [], scan_id=scan_id,
    )


class DiagnosticTests(unittest.TestCase):
    def test_prioritizes_high_risk_and_explains_sensitive_port(self):
        current = scan(findings=[
            ScanFinding("medium", "new_device", "172.26.3.20", "New device detected", "unknown"),
            ScanFinding("high", "new_port", "172.26.3.10", "New open port 23/tcp", "telnet"),
        ])
        result = build_diagnostics(None, current)

        self.assertEqual(result.priority.host, "172.26.3.10")
        self.assertIn("texto claro", result.priority.why)
        self.assertIn("SSH", result.priority.recommendation)
        self.assertEqual(result.new_devices, 1)
        self.assertEqual(result.active_issues, 2)

    def test_marks_previously_exposed_port_as_resolved(self):
        exposed = ScanService(
            port=445, protocol="tcp", state="open", name="microsoft-ds",
            risk_level="medium", risk_reason="SMB exposed",
        )
        previous = scan(hosts=[ScanHost("172.26.3.10", services=[exposed])], scan_id=1)
        current = scan(hosts=[ScanHost("172.26.3.10")], scan_id=2)

        result = build_diagnostics(previous, current)

        self.assertEqual(result.active_issues, 0)
        self.assertEqual(result.resolved_issues, 1)
        self.assertEqual(result.items[0].status, "resolved")
        self.assertIn("445/tcp", result.items[0].title)

    def test_no_previous_or_findings_produces_clean_summary(self):
        result = build_diagnostics(None, scan())
        self.assertIsNone(result.priority)
        self.assertEqual(result.items, [])

    def test_host_alerts_are_empty_until_ip_is_selected_and_then_filtered(self):
        current = scan(findings=[
            ScanFinding("high", "new_port", "172.26.3.10", "Port 23", "telnet"),
            ScanFinding("medium", "new_device", "172.26.3.20", "New device", "unknown"),
        ])

        self.assertEqual(findings_for_host(current, ""), [])
        selected = findings_for_host(current, "172.26.3.20")
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].host, "172.26.3.20")

    def test_diagnostic_center_is_ordered_by_numeric_ip(self):
        current = scan(findings=[
            ScanFinding("high", "new_port", "172.26.3.20", "Port 23", "telnet"),
            ScanFinding("low", "missing_device", "172.26.3.2", "Missing", "offline"),
            ScanFinding("medium", "new_device", "172.26.3.10", "New", "unknown"),
        ])

        result = build_diagnostics(None, current)

        self.assertEqual(
            [item.host for item in result.items],
            ["172.26.3.2", "172.26.3.10", "172.26.3.20"],
        )

    def test_sensitive_service_explanation_includes_safe_verification(self):
        service = ScanService(445, "tcp", "open", "microsoft-ds", risk_level="medium")
        explanation = explain_service("172.26.3.10", service)
        self.assertIn("SMB", explanation.why)
        self.assertIn("firewall", explanation.recommendation)
        self.assertEqual(explanation.verification, "nmap -sV -p 445 172.26.3.10")

    def test_scheduled_notification_respects_changes_only_policy(self):
        clean = scan(hosts=[ScanHost("172.26.3.10")])
        self.assertIsNone(scheduled_scan_message(clean, True))
        self.assertIn("no relevant changes", scheduled_scan_message(clean, False)[0])

        changed = scan(findings=[
            ScanFinding("medium", "new_device", "172.26.3.20", "New device", "unknown")
        ])
        message, relevant = scheduled_scan_message(changed, True)
        self.assertIn("172.26.3.20", message)
        self.assertEqual(len(relevant), 1)

        baseline_message, baseline_relevant = scheduled_scan_message(
            clean, True, ["172.26.3.10"]
        )
        self.assertIn("172.26.3.10", baseline_message)
        self.assertEqual(baseline_relevant[0].kind, "unknown_device")


if __name__ == "__main__":
    unittest.main()
