from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import sqlite3
import unittest
import zipfile

from netpulse.infrastructure.database import DB, SCHEMA_VERSION
from netpulse.presentation.views import HistoryView


class BackupRestoreTests(unittest.TestCase):
    def test_backup_is_consistent_and_restore_creates_safety_copy(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            live = DB(root / "live.db")
            original = live.new_session("Ethernet")
            backup = live.backup(root / "backups" / "known-good.db")
            extra = live.new_session("Wi-Fi")

            safety = live.restore(backup)

            self.assertTrue(safety.exists())
            self.assertEqual([row["id"] for row in live.list_sessions()], [original])
            safety_db = DB(safety)
            self.assertEqual({row["id"] for row in safety_db.list_sessions()}, {original, extra})

    def test_restore_rejects_non_netpulse_database_without_touching_live_data(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            live = DB(root / "live.db")
            session_id = live.new_session("All")
            invalid = root / "invalid.db"
            sqlite3.connect(invalid).close()

            with self.assertRaises(ValueError):
                live.restore(invalid)

            self.assertEqual(live.list_sessions()[0]["id"], session_id)

    def test_export_contains_database_json_csv_manifest_and_runtime_files(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            db = DB(root / "live.db")
            db.new_session("All")
            settings = root / "settings.json"
            settings.write_text('{"language":"es"}', encoding="utf-8")

            archive = db.export_all_data(root / "all.zip", [settings])

            with zipfile.ZipFile(archive) as exported:
                names = set(exported.namelist())
                manifest = json.loads(exported.read("manifest.json"))
            self.assertIn("netpulse.db", names)
            self.assertIn("sessions.json", names)
            self.assertIn("sessions.csv", names)
            self.assertIn("settings.json", names)
            self.assertEqual(manifest["schema_version"], SCHEMA_VERSION)
            self.assertEqual(manifest["tables"]["sessions"], 1)

    def test_v1_sessions_table_is_migrated_without_losing_rows(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    """CREATE TABLE sessions (
                    id INTEGER PRIMARY KEY, start_time TEXT NOT NULL, end_time TEXT,
                    interface TEXT NOT NULL DEFAULT 'All', total_pkts INTEGER DEFAULT 0,
                    total_bytes_in INTEGER DEFAULT 0, total_bytes_out INTEGER DEFAULT 0)"""
                )
                connection.execute(
                    "INSERT INTO sessions (id,start_time,interface) VALUES (1,?,?)",
                    (datetime.now().isoformat(), "All"),
                )
                connection.execute("PRAGMA user_version=1")
                connection.commit()
            finally:
                connection.close()

            db = DB(path)

            self.assertEqual(db.list_sessions()[0]["dropped_packets"], 0)
            with db._cx() as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)


class HistoricalTelemetryTests(unittest.TestCase):
    def test_applications_events_trends_and_session_export_round_trip(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            db = DB(root / "history.db")
            sid = db.new_session("Ethernet")
            now = datetime.now()
            db.save_session_applications(sid, {
                "42:browser": {
                    "pid": 42, "name": "Browser", "bytes_in": 5000,
                    "bytes_out": 700, "packets_in": 5, "packets_out": 2,
                    "peak_rate": 80.5, "average_rate": 20.0,
                    "first_seen": now, "last_seen": now,
                    "protocols": {"HTTPS": 7},
                    "destinations": {"1.1.1.1": {
                        "ip": "1.1.1.1", "bytes_in": 5000, "bytes_out": 700,
                        "packets": 7, "ports": {443}, "protocols": {"HTTPS"},
                        "first_seen": now, "last_seen": now,
                    }},
                }
            })
            event_id = db.save_session_event(
                sid, "threshold_alert", "High traffic", "Exceeded threshold",
                "warning", fingerprint="one",
            )
            self.assertEqual(event_id, db.save_session_event(
                sid, "threshold_alert", "High traffic", "Exceeded threshold",
                "warning", fingerprint="one",
            ))
            db.close_session(sid, 7, 5000, 700, 3)

            apps = db.get_session_applications(sid)
            events = db.list_session_events(sid)
            trends = db.session_trends(30)
            weekly = db.session_trends(84, "week")
            exported = db.export_session(sid, root / "session.json")
            payload = json.loads(exported.read_text(encoding="utf-8"))

            self.assertEqual(apps[0]["process_name"], "Browser")
            self.assertEqual(apps[0]["destinations"][0]["ports"], [443])
            self.assertEqual(len(events), 1)
            self.assertEqual(trends[-1]["dropped"], 3)
            self.assertRegex(weekly[-1]["period"], r"^\d{4}-W\d{2}$")
            self.assertEqual(payload["applications"][0]["pid"], 42)
            self.assertEqual(payload["events"][0]["severity"], "warning")

    def test_history_view_renders_comparison_apps_events_and_export(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            db = DB(root / "history.db")
            older = db.new_session("Wi-Fi")
            db.close_session(older, 10, 1000, 100, 0)
            current = db.new_session("Ethernet")
            db.save_session_applications(current, {"7:test": {
                "pid": 7, "name": "Test App", "bytes_in": 2000,
                "bytes_out": 400, "packets_in": 2, "packets_out": 1,
            }})
            db.save_session_event(current, "capture_started", "Capture started",
                                  fingerprint="start")
            db.close_session(current, 20, 2000, 400, 2)
            view = HistoryView(db)
            view.build()

            view._load(current)
            view._render_comparison(older)
            exported = view._export_selected()

            self.assertIn("Test App", view._apps_column.controls[0].content.controls[1].controls[0].value)
            self.assertIn("Capture started", view._events_column.controls[0].content.controls[0].controls[0].value)
            self.assertIn(f"#{older}", view._comparison_text.value)
            self.assertTrue(exported.exists())


if __name__ == "__main__":
    unittest.main()
