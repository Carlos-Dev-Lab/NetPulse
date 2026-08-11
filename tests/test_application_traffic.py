from datetime import datetime
import unittest

import flet as ft

from netpulse.domain.models import Packet
from netpulse.domain.state import AppState
from netpulse.presentation.views import ProcessView


class _Page:
    def __init__(self):
        self.dialog = None
        self.updates = 0

    def show_dialog(self, dialog):
        self.dialog = dialog
        dialog.open = True

    def pop_dialog(self):
        self.dialog.open = False

    def update(self):
        self.updates += 1


class ApplicationTrafficTests(unittest.TestCase):
    def _state(self):
        state = AppState()
        now = datetime.now()
        state.process([
            Packet(now, "OUT", "HTTPS", "10.0.0.2", "1.1.1.1",
                   51000, 443, 400, "1.1.1.1", 55, "browser.exe"),
            Packet(now, "IN", "HTTPS", "1.1.1.1", "10.0.0.2",
                   443, 51000, 1600, "1.1.1.1", 55, "browser.exe"),
        ], 1.0)
        return state

    def test_view_summarizes_application_directions_and_destinations(self):
        state = self._state()
        view = ProcessView(state)
        view.build()

        view.refresh()

        self.assertEqual(view.r_active.current.value, "1")
        self.assertEqual(view.r_download.current.value, "1.6 KB")
        self.assertEqual(view.r_upload.current.value, "400 B")
        self.assertEqual(view.r_destinations.current.value, "1")
        self.assertEqual(view.r_top.current.value, "browser.exe")
        self.assertEqual(len(view.r_table.current.controls), 1)

    def test_application_row_opens_destination_and_packet_details(self):
        page = _Page()
        view = ProcessView(self._state(), [page])
        view.build()
        view.refresh()

        row = view.r_table.current.controls[0]
        row.on_click(None)

        self.assertIsInstance(page.dialog, ft.AlertDialog)
        self.assertTrue(page.dialog.open)
        self.assertIn("APPLICATION NETWORK ACTIVITY", page.dialog.title.value)

    def test_detail_explains_encryption_and_remote_connections(self):
        page = _Page()
        view = ProcessView(self._state(), [page])
        view.build(); view.refresh()
        view.r_table.current.controls[0].on_click(None)

        content = page.dialog.content.content
        texts = []
        def walk(control):
            if isinstance(control, ft.Text):
                texts.append(control.value)
            for name in ("content", "controls"):
                value = getattr(control, name, None)
                children = value if isinstance(value, list) else [value]
                for child in children:
                    if isinstance(child, ft.Control):
                        walk(child)
        walk(content)
        joined = " ".join(texts)
        self.assertIn("WHAT CAN BE SEEN", joined)
        self.assertIn("encrypted traffic", joined.lower())
        self.assertIn("REMOTE CONNECTIONS", joined)

    def test_search_can_match_a_destination_ip(self):
        view = ProcessView(self._state())
        view.build()
        view.r_search.current.value = "1.1.1.1"

        view.refresh()

        self.assertEqual(len(view.r_table.current.controls), 1)

    def test_multiple_pids_are_grouped_under_one_application(self):
        state = AppState()
        now = datetime.now()
        state.process([
            Packet(now, "OUT", "HTTPS", "10.0.0.2", "1.1.1.1",
                   50001, 443, 400, "1.1.1.1", 101, "svchost.exe"),
            Packet(now, "OUT", "DNS", "10.0.0.2", "8.8.8.8",
                   50002, 53, 200, "8.8.8.8", 202, "svchost.exe"),
        ], 1.0)
        view = ProcessView(state)
        view.build()

        view.refresh()
        grouped = view._apps()

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["instance_count"], 2)
        self.assertEqual(grouped[0]["pids"], [101, 202])
        self.assertEqual(grouped[0]["bytes_out"], 600)
        self.assertEqual(set(grouped[0]["destinations"]), {"1.1.1.1", "8.8.8.8"})
        self.assertEqual(len(view.r_table.current.controls), 1)
        self.assertEqual(view.r_procs.current.value, "1 applications · 2 processes")


if __name__ == "__main__":
    unittest.main()
