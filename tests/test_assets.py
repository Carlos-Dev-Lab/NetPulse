from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from netpulse.domain.health import calculate_network_health
from netpulse.domain.network_scan import NetworkScan, ScanHost, ScanService
from netpulse.infrastructure.database import DB


def scan(at, hosts, target="10.0.0.0/24"):
    return NetworkScan(target, "quick", "nmap", at, at, 1, hosts=hosts)


class EnterpriseAssetTests(unittest.TestCase):
    def test_ip_reuse_by_different_mac_does_not_inherit_authorization(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "assets.db")
            now = datetime(2026, 1, 1)
            db.save_network_scan(scan(now, [ScanHost(
                "10.0.0.10", hostname="printer", mac="AA:AA:AA:AA:AA:AA"
            )]))
            db.update_inventory_device("10.0.0.10", trust_status="authorized")
            db.save_network_scan(scan(now + timedelta(hours=1), [ScanHost(
                "10.0.0.10", hostname="camera", mac="BB:BB:BB:BB:BB:BB"
            )]))

            assets = db.list_inventory()
            self.assertEqual(len(assets), 2)
            newest = max(assets, key=lambda item: item["last_scan_id"])
            self.assertEqual(newest["lifecycle_status"], "new")
            self.assertNotEqual(newest["device_id"], min(assets, key=lambda a: a["first_seen"])["device_id"])

    def test_changed_mac_creates_explained_merge_suggestion(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "suggestions.db")
            now = datetime(2026, 1, 1)
            services = [ScanService(443, "tcp", "open", "https", "nginx", "1.2")]
            db.save_network_scan(scan(now, [ScanHost(
                "10.0.0.10", hostname="srv01", mac="AA:AA", vendor="Acme",
                os_name="Linux", services=services,
            )]))
            db.save_network_scan(scan(now + timedelta(hours=1), [ScanHost(
                "10.0.0.20", hostname="srv01", mac="BB:BB", vendor="Acme",
                os_name="Linux", services=services,
            )]))

            suggestions = db.list_merge_suggestions()
            self.assertEqual(len(db.list_inventory()), 2)
            self.assertEqual(len(suggestions), 1)
            self.assertGreaterEqual(suggestions[0]["score"], 50)
            self.assertIn("same hostname", suggestions[0]["reasons"])

    def test_same_mac_with_incompatible_signals_requires_review(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "conflict.db")
            now = datetime(2026, 1, 1)
            db.save_network_scan(scan(now, [ScanHost(
                "10.0.0.10", hostname="server", mac="AA:BB", vendor="Acme",
                os_name="Linux", services=[ScanService(443, "tcp", "open", "https")],
            )]))
            db.save_network_scan(scan(now + timedelta(hours=1), [ScanHost(
                "10.0.0.11", hostname="phone", mac="AA:BB", vendor="Other",
                os_name="Android", services=[ScanService(5555, "tcp", "open", "adb")],
            )]))

            asset = db.list_inventory()[0]
            self.assertTrue(asset["review_required"])
            self.assertEqual(asset["identity_confidence"], "medium")
            self.assertTrue(any(event["event_type"] == "identity_conflict"
                                for event in db.list_asset_events(asset["device_id"])))

    def test_merge_and_separate_preserve_each_assets_history(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "merge.db")
            now = datetime(2026, 1, 1)
            first = scan(now, [ScanHost("10.0.0.10", hostname="srv", mac="AA")])
            second = scan(now + timedelta(hours=1), [ScanHost("10.0.0.20", hostname="srv", mac="BB")])
            db.save_network_scan(first); db.save_network_scan(second)
            target, source = first.hosts[0].device_id, second.hosts[0].device_id
            before = db.list_asset_observations(source)

            db.merge_assets(target, source)
            self.assertEqual(len(db.list_inventory()), 1)
            db.separate_asset(source)

            self.assertEqual(len(db.list_inventory()), 2)
            self.assertEqual(db.list_asset_observations(source), before)
            self.assertTrue(any(e["event_type"] == "asset_separated"
                                for e in db.list_asset_events(source)))

    def test_retired_asset_absence_does_not_reduce_health(self):
        now = datetime(2026, 1, 1)
        result = calculate_network_health(
            scan(now, []),
            [{"device_id": 1, "address": "10.0.0.2", "lifecycle_status": "retired"}],
        )
        self.assertEqual(result.score, 100)

    def test_blocked_asset_reappearance_is_high_priority_event(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "blocked.db")
            now = datetime(2026, 1, 1)
            host = ScanHost("10.0.0.10", mac="AA")
            db.save_network_scan(scan(now, [host]))
            db.update_inventory_device("10.0.0.10", trust_status="blocked")
            db.save_network_scan(scan(now + timedelta(hours=1), [ScanHost(
                "10.0.0.11", mac="AA"
            )]))
            events = db.list_asset_events(host.device_id)
            blocked = next(item for item in events if item["event_type"] == "blocked_present")
            self.assertEqual(blocked["severity"], "high")

    def test_legacy_inventory_is_migrated_and_removed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.execute(
                """CREATE TABLE device_inventory (
                     address TEXT PRIMARY KEY,mac TEXT,detected_name TEXT,alias TEXT,
                     device_type TEXT,owner TEXT,location TEXT,notes TEXT,trust_status TEXT,
                     first_seen TEXT,last_seen TEXT,last_scan_id INTEGER)"""
            )
            connection.execute(
                """INSERT INTO device_inventory VALUES
                   ('10.0.0.8','AA:BB','printer','Reception printer','printer','Ops',
                    'Reception','legacy note','authorized','2026-01-01','2026-01-02',NULL)"""
            )
            connection.commit(); connection.close()

            db = DB(path)
            asset = db.list_inventory()[0]
            self.assertEqual(asset["alias"], "Reception printer")
            self.assertEqual(asset["lifecycle_status"], "authorized")
            self.assertTrue(db.list_asset_observations(asset["device_id"]))
            migrated = sqlite3.connect(path)
            try:
                table = migrated.execute(
                    "SELECT name FROM sqlite_master WHERE name='device_inventory'"
                ).fetchone()
            finally:
                migrated.close()
            self.assertIsNone(table)


if __name__ == "__main__":
    unittest.main()
