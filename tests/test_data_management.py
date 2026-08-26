from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import flet as ft

from netpulse.domain.network_scan import NetworkScan, ScanHost, ScanService
from netpulse.domain.state import AppState
from netpulse.infrastructure.database import DB
from netpulse.presentation.data_management import DataManagementView
from netpulse.presentation.theme import appearance_palette, set_active_palette


class SavedDataDatabaseTests(unittest.TestCase):
    def test_capture_session_deletion_removes_its_samples_and_endpoints(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            session_id = db.new_session("Ethernet")
            db.save_stat(session_id, {"bytes_in": 40, "TCP": 1})
            db.upsert_ips(session_id, [("192.168.1.20", 40, 1)])

            removed = db.delete_saved_records("sessions", [session_id])

            self.assertEqual(removed, 1)
            self.assertEqual(db.list_sessions(), [])
            self.assertEqual(db.get_stats(session_id), [])
            self.assertEqual(db.get_top_ips(session_id), [])

    def test_scan_deletion_preserves_inventory_and_clears_evidence_links(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            now = datetime(2026, 1, 1)
            scan = NetworkScan(
                "192.168.1.0/24", "quick", "nmap", now, now, 1,
                hosts=[ScanHost("192.168.1.20", mac="AA:BB:CC:DD:EE:FF",
                                services=[ScanService(443, "tcp", "open", "https")])],
            )
            scan_id = db.save_network_scan(scan)
            device_id = db.list_inventory()[0]["device_id"]

            removed = db.delete_saved_records("scans", [scan_id])

            self.assertEqual(removed, 1)
            self.assertIsNone(db.get_network_scan(scan_id))
            asset = db.get_inventory_device(device_id=device_id)
            self.assertIsNotNone(asset)
            self.assertIsNone(asset["last_scan_id"])

    def test_asset_deletion_detaches_historical_scan_host(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            now = datetime(2026, 1, 1)
            scan = NetworkScan("10.0.0.0/24", "quick", "nmap", now, now, 1,
                               hosts=[ScanHost("10.0.0.5")])
            scan_id = db.save_network_scan(scan)
            device_id = db.list_inventory()[0]["device_id"]

            self.assertEqual(db.delete_saved_records("assets", [device_id]), 1)

            self.assertEqual(db.list_inventory(), [])
            self.assertIsNone(db.get_network_scan(scan_id).hosts[0].device_id)

    def test_unknown_category_is_rejected(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            with self.assertRaises(ValueError):
                db.delete_saved_records("arbitrary_table", [1])

    def test_profiles_schedules_quality_and_events_can_be_managed(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            profile_id = db.save_scan_profile("Office", "192.168.1.0/24", "quick")
            schedule_id = db.save_scan_schedule(profile_id, 60)
            session_id = db.new_session("All")
            event_id = db.save_session_event(
                session_id, "capture_started", "Started", fingerprint="start"
            )

            self.assertEqual(db.delete_saved_records("schedules", [schedule_id]), 1)
            self.assertEqual(db.delete_saved_records("events", [event_id]), 1)
            self.assertEqual(db.delete_saved_records("profiles", [profile_id]), 1)
            self.assertEqual(db.list_scan_schedules(), [])
            self.assertEqual(db.list_scan_profiles(), [])
            self.assertEqual(db.list_session_events(session_id), [])


class DataManagementViewTests(unittest.TestCase):
    def tearDown(self):
        set_active_palette(appearance_palette("netpulse", "cyan"))

    def test_active_capture_session_cannot_be_selected_or_deleted(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            active_id = db.new_session("Wi-Fi")
            state = AppState()
            state.capturing = True
            state.session_id = active_id
            view = DataManagementView(db, [None], state)

            view.build()

            row = view._records_column.controls[0]
            checkbox = row.content.controls[0]
            delete_button = row.content.controls[-1]
            self.assertIsInstance(checkbox, ft.Checkbox)
            self.assertTrue(checkbox.disabled)
            self.assertTrue(delete_button.disabled)

    def test_manual_deletion_refreshes_counts_and_visible_records(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            first = db.new_session("Ethernet")
            second = db.new_session("Wi-Fi")
            view = DataManagementView(db, [None], AppState())
            view.build()

            removed = view._perform_delete({first})

            self.assertEqual(removed, 1)
            self.assertEqual([item["id"] for item in db.list_sessions()], [second])
            self.assertEqual(view._summary_values["sessions"].value, "1")
            self.assertEqual(len(view._records_column.controls), 1)

    def test_rows_rebuilt_in_light_theme_use_dark_readable_ink(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            db.new_session("Ethernet")
            set_active_palette(appearance_palette("daylight", "cyan"))
            view = DataManagementView(db, [None], AppState())

            view.build()
            row = view._records_column.controls[0]
            title = row.content.controls[2].controls[0].controls[0]

            self.assertEqual(title.color, appearance_palette("daylight", "cyan")["text"])

    def test_backup_restore_controls_refresh_available_copies(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "data.db")
            original = db.new_session("Ethernet")
            view = DataManagementView(db, [None], AppState())
            view.build()

            backup = view._create_backup()
            db.new_session("Wi-Fi")
            safety = view._perform_restore(backup)

            self.assertTrue(backup.exists())
            self.assertTrue(safety.exists())
            self.assertEqual([row["id"] for row in db.list_sessions()], [original])
            self.assertGreaterEqual(len(view._backup_dropdown.options), 2)


if __name__ == "__main__":
    unittest.main()
