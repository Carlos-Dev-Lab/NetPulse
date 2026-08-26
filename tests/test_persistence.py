"""Capture preferences, retention and drop accounting survive a restart."""

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from netpulse import config
from netpulse.config import (
    load_alerts, load_interface, load_language, load_retention_days,
    save_alerts, save_interface, save_language, save_retention_days,
)
from netpulse.domain.state import AppState
from netpulse.infrastructure.database import DB, SCHEMA_VERSION
from netpulse.infrastructure.sniffer import Sniffer
from netpulse.presentation.views import SettingsView


class SettingsPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._directory = TemporaryDirectory()
        self.settings = Path(self._directory.name) / "settings.json"
        self._patch = patch.object(config, "DEFAULT_SETTINGS_PATH", self.settings)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._directory.cleanup()

    def test_alerts_round_trip(self):
        self.assertEqual(load_alerts(),
                         {"bandwidth_kbps": 0.0, "packets_per_second": 0.0})
        save_alerts(1500, 4200)
        self.assertEqual(load_alerts(),
                         {"bandwidth_kbps": 1500.0, "packets_per_second": 4200.0})

    def test_alerts_reject_negative_and_malformed_values(self):
        save_alerts(-10, "abc")
        self.assertEqual(load_alerts(),
                         {"bandwidth_kbps": 0.0, "packets_per_second": 0.0})

    def test_interface_round_trip_and_default(self):
        self.assertEqual(load_interface(), "All")
        save_interface("  Wi-Fi  ")
        self.assertEqual(load_interface(), "Wi-Fi")
        save_interface("")
        self.assertEqual(load_interface(), "All")

    def test_retention_round_trip_and_clamping(self):
        self.assertEqual(load_retention_days(), 0)
        save_retention_days(30)
        self.assertEqual(load_retention_days(), 30)
        save_retention_days(-5)
        self.assertEqual(load_retention_days(), 0)

    def test_unrelated_keys_are_preserved(self):
        save_language("es")
        save_alerts(100, 200)
        save_interface("Ethernet")
        save_retention_days(7)
        stored = json.loads(self.settings.read_text(encoding="utf-8"))
        self.assertEqual(stored["language"], "es")
        self.assertEqual(stored["interface"], "Ethernet")
        self.assertEqual(stored["retention_days"], 7)
        self.assertEqual(load_language(), "es")

    def test_corrupt_settings_file_falls_back_to_defaults(self):
        self.settings.parent.mkdir(parents=True, exist_ok=True)
        self.settings.write_text("{not json", encoding="utf-8")
        self.assertEqual(load_interface(), "All")
        self.assertEqual(load_retention_days(), 0)
        self.assertEqual(load_alerts()["bandwidth_kbps"], 0.0)

    def test_settings_view_restores_and_saves_thresholds(self):
        save_alerts(900, 3000)
        state = AppState()
        view = SettingsView(state)
        self.assertEqual(state.alert_bw_thresh, 900.0)
        self.assertEqual(state.alert_pps_thresh, 3000.0)

        view.build()
        self.assertEqual(view.r_bw_thresh.current.value, "900")
        self.assertEqual(view.r_pps_thresh.current.value, "3000")
        self.assertIn("900", view.r_alert_status.current.value)

        view.r_bw_thresh.current.value = "1234"
        view.r_pps_thresh.current.value = "0"
        view._alert_button.on_click(None)

        self.assertEqual(load_alerts(),
                         {"bandwidth_kbps": 1234.0, "packets_per_second": 0.0})
        self.assertEqual(state.alert_bw_thresh, 1234.0)
        self.assertIn("1234", view.r_alert_status.current.value)

    def test_settings_view_persists_retention_choice(self):
        state = AppState()
        view = SettingsView(state)
        view.build()
        self.assertEqual(view.retention_days, 0)

        class _Control:
            value = "30"

        class _Event:
            control = _Control()

        view._retention_dropdown.on_select(_Event())
        self.assertEqual(load_retention_days(), 30)
        self.assertEqual(view.retention_days, 30)
        self.assertIn("30", view.r_retention_status.current.value)


class RetentionTests(unittest.TestCase):
    def _session(self, db, start: datetime) -> int:
        with db._cx() as connection:
            return connection.execute(
                "INSERT INTO sessions (start_time, interface) VALUES (?,?)",
                (start.isoformat(), "All"),
            ).lastrowid

    def test_purge_removes_only_sessions_beyond_the_window(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "retention.db")
            now = datetime(2026, 8, 25)
            old_id = self._session(db, now - timedelta(days=40))
            fresh_id = self._session(db, now - timedelta(days=2))
            db.save_stat(old_id, {"bytes_in": 10})
            db.save_stat(fresh_id, {"bytes_in": 20})
            db.upsert_ips(old_id, [("1.1.1.1", 10, 1)])
            db.upsert_ips(fresh_id, [("8.8.8.8", 20, 2)])

            self.assertEqual(db.purge_old_sessions(30, now=now), 1)

            remaining = {session["id"] for session in db.list_sessions()}
            self.assertEqual(remaining, {fresh_id})
            self.assertEqual(db.get_stats(old_id), [])
            self.assertEqual(len(db.get_stats(fresh_id)), 1)
            self.assertEqual(db.get_top_ips(old_id), [])
            self.assertEqual(len(db.get_top_ips(fresh_id)), 1)

    def test_zero_retention_keeps_everything(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "keep.db")
            now = datetime(2026, 8, 25)
            self._session(db, now - timedelta(days=900))
            self.assertEqual(db.purge_old_sessions(0, now=now), 0)
            self.assertEqual(len(db.list_sessions()), 1)

    def test_purge_is_idempotent(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "idempotent.db")
            now = datetime(2026, 8, 25)
            self._session(db, now - timedelta(days=40))
            self.assertEqual(db.purge_old_sessions(30, now=now), 1)
            self.assertEqual(db.purge_old_sessions(30, now=now), 0)

    def test_storage_summary_reports_counts(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "summary.db")
            session_id = db.new_session("All")
            db.save_stat(session_id, {"bytes_in": 5})
            summary = db.storage_summary()
            self.assertEqual(summary["sessions"], 1)
            self.assertEqual(summary["samples"], 1)
            self.assertEqual(summary["scans"], 0)
            self.assertGreater(summary["bytes"], 0)


class SchemaVersionTests(unittest.TestCase):
    def test_one_time_migrations_are_stamped_and_not_repeated(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "versioned.db"
            db = DB(path)
            with db._cx() as connection:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
            with patch.object(DB, "_seed_asset_observations") as seed:
                DB(path)
                seed.assert_not_called()

    def test_foreign_keys_are_enforced_on_every_connection(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "fk.db")
            with db._cx() as connection:
                self.assertEqual(
                    connection.execute("PRAGMA foreign_keys").fetchone()[0], 1
                )
                self.assertEqual(
                    connection.execute("PRAGMA foreign_key_check").fetchall(), []
                )


class DroppedPacketTests(unittest.TestCase):
    def test_counter_starts_at_zero_and_tracks_drops(self):
        sniffer = Sniffer()
        self.assertEqual(sniffer.dropped, 0)
        sniffer._count_drop()
        sniffer._count_drop()
        self.assertEqual(sniffer.dropped, 2)

    def test_raw_queue_overflow_is_counted(self):
        sniffer = Sniffer()
        sniffer._raw_q.maxsize = 1
        sniffer._cb(object())
        sniffer._cb(object())
        sniffer._cb(object())
        self.assertEqual(sniffer.dropped, 2)
        self.assertEqual(sniffer._raw_q.qsize(), 1)


if __name__ == "__main__":
    unittest.main()
