from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from netpulse.infrastructure.database import DB
from netpulse.services.performance import QualityResult
from netpulse.domain.network_scan import NetworkScan, ScanHost, ScanService
from datetime import datetime, timedelta


class DatabaseTests(unittest.TestCase):
    def test_quality_checks_are_persisted_newest_first(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "quality.db")
            result = QualityResult("10.0.0.1", 4, 4, 5.0, 1.0, 0.0, 8.0, True)
            db.save_quality_check("Ethernet", result)

            rows = db.list_quality_checks()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["gateway"], "10.0.0.1")
            self.assertEqual(rows[0]["internet_reachable"], 1)

    def test_inventory_follows_mac_when_dhcp_changes_address(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "rotation.db")
            first_time = datetime(2026, 1, 1, 10, 0)
            db.save_network_scan(NetworkScan(
                "10.0.0.0/24", "discovery", "nmap",
                first_time, first_time, 1,
                hosts=[ScanHost("10.0.0.10", hostname="laptop", mac="AA:BB:CC:DD:EE:FF")],
            ))
            db.update_inventory_device(
                "10.0.0.10", alias="Notebook de Carlos", owner="Carlos",
                trust_status="authorized",
            )
            second_time = first_time + timedelta(hours=1)
            db.save_network_scan(NetworkScan(
                "10.0.0.0/24", "discovery", "nmap",
                second_time, second_time, 1,
                hosts=[ScanHost("10.0.0.27", hostname="laptop", mac="aa:bb:cc:dd:ee:ff")],
            ))

            inventory = db.list_inventory()
            self.assertEqual(len(inventory), 1)
            self.assertEqual(inventory[0]["address"], "10.0.0.27")
            self.assertEqual(inventory[0]["alias"], "Notebook de Carlos")
            self.assertEqual(inventory[0]["trust_status"], "authorized")
            self.assertEqual(inventory[0]["identity_source"], "mac")
            history = db.list_device_ip_history("10.0.0.27")
            self.assertEqual({item["address"] for item in history},
                             {"10.0.0.10", "10.0.0.27"})

    def test_session_stats_and_batch_ip_upsert(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "nested" / "test.db")
            session_id = db.new_session("Ethernet")
            db.save_stat(session_id, {"bytes_in": 10, "TCP": 1})
            db.upsert_ips(session_id, [("1.1.1.1", 100, 1), ("1.1.1.1", 50, 2)])
            db.close_session(session_id, 3, 10, 0)

            self.assertEqual(db.get_stats(session_id)[0]["bytes_in"], 10)
            top_ip = db.get_top_ips(session_id)[0]
            self.assertEqual(top_ip["total_bytes"], 150)
            self.assertEqual(top_ip["total_pkts"], 3)
            self.assertEqual(db.list_sessions()[0]["total_pkts"], 3)

    def test_inventory_is_created_by_scan_and_preserves_user_metadata(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "inventory.db")
            now = datetime(2026, 1, 1)
            first = NetworkScan("10.0.0.0/24", "discovery", "nmap", now, now, 1,
                                hosts=[ScanHost("10.0.0.10", hostname="printer", mac="AA:BB",
                                                services=[ScanService(9100, "tcp", "open", "jetdirect")])])
            db.save_network_scan(first)
            db.update_inventory_device(
                "10.0.0.10", alias="Impresora recepción", device_type="printer",
                owner="Administración", location="Recepción", notes="Tóner 85A",
                trust_status="authorized",
            )
            second = NetworkScan("10.0.0.0/24", "discovery", "nmap", now, now, 1,
                                 hosts=[ScanHost("10.0.0.10", hostname="printer-new", mac="AA:BB")])
            db.save_network_scan(second)

            device = db.get_inventory_device("10.0.0.10")
            self.assertEqual(device["alias"], "Impresora recepción")
            self.assertEqual(device["trust_status"], "authorized")
            self.assertEqual(device["detected_name"], "printer-new")
            self.assertEqual(len(db.list_inventory()), 1)

            by_alias = db.search_global("Impresora")
            self.assertEqual(by_alias[0]["category"], "inventory")
            self.assertEqual(by_alias[0]["value"], "10.0.0.10")
            by_host = db.search_global("printer-new")
            self.assertTrue(any(item["value"] == "10.0.0.10" for item in by_host))
            by_port = db.search_global("9100")
            self.assertTrue(any(item["category"] == "service" for item in by_port))

    def test_custom_profiles_and_schedules_persist_and_advance(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "schedules.db")
            profile_id = db.save_scan_profile(
                "Red administrativa", "172.26.3.0/24, 172.26.4.0/24", "quick"
            )
            now = datetime(2026, 1, 1, 10, 0)
            schedule_id = db.save_scan_schedule(profile_id, 30, True, now)

            self.assertEqual(db.list_scan_profiles()[0]["name"], "Red administrativa")
            self.assertEqual(db.list_due_schedules(now + timedelta(minutes=29)), [])
            due = db.list_due_schedules(now + timedelta(minutes=30))
            self.assertEqual(due[0]["target"], "172.26.3.0/24, 172.26.4.0/24")
            self.assertEqual(due[0]["notify_changes_only"], 1)

            ran_at = now + timedelta(minutes=30)
            db.mark_schedule_run(schedule_id, True, now=ran_at)
            schedule = db.list_scan_schedules()[0]
            self.assertEqual(schedule["last_status"], "completed")
            self.assertEqual(schedule["next_run"], (ran_at + timedelta(minutes=30)).isoformat())
            db.set_schedule_enabled(schedule_id, False)
            self.assertEqual(db.list_due_schedules(ran_at + timedelta(days=1)), [])


if __name__ == "__main__":
    unittest.main()
