from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import csv
import unittest

from netpulse.domain.network_scan import NetworkScan, ScanFinding, ScanHost, ScanService
from netpulse.services.reporting import export_scan_reports


class ReportingTests(unittest.TestCase):
    def test_exports_pdf_html_and_csv_with_inventory_and_diagnostics(self):
        now = datetime(2026, 1, 1, 10, 30)
        scan = NetworkScan(
            "172.26.3.0/24", "services", "nmap -sV", now, now, 2.5,
            hosts=[ScanHost("172.26.3.10", hostname="server", services=[
                ScanService(445, "tcp", "open", "microsoft-ds", risk_level="medium")
            ], risk_score=40, risk_level="medium")],
            findings=[ScanFinding("medium", "new_port", "172.26.3.10",
                                  "New open port 445/tcp", "microsoft-ds")],
            nmap_version="7.99", scan_id=7,
        )
        inventory = [{"address": "172.26.3.10", "alias": "Servidor principal",
                      "trust_status": "authorized", "device_type": "server"}]
        with TemporaryDirectory() as directory:
            paths = export_scan_reports(scan, None, inventory, directory)
            self.assertEqual(set(paths), {"pdf", "html", "csv"})
            self.assertTrue(all(path.exists() and path.stat().st_size > 100 for path in paths.values()))
            self.assertTrue(paths["pdf"].read_bytes().startswith(b"%PDF"))
            html = paths["html"].read_text(encoding="utf-8")
            self.assertIn("Servidor principal", html)
            self.assertIn("Accion:", html)
            self.assertIn("Salud", html)
            self.assertIn("Factores de salud", html)
            with paths["csv"].open(encoding="utf-8-sig") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[0]["puerto"], "445")
            self.assertEqual(rows[0]["confianza"], "authorized")


if __name__ == "__main__":
    unittest.main()
