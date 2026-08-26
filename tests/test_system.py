import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch
from datetime import datetime

import flet
import psutil
import scapy

from netpulse.domain.state import AppState
from netpulse.domain.network_scan import NetworkScan, ScanHost, ScanService
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import NmapScanner
from netpulse.presentation.charts import (
    BarChartCanvas,
    LineChartCanvas,
    PieChartCanvas,
    SparklineCanvas,
)
from netpulse.presentation.views import (
    ChartsView,
    DashboardView,
    HistoryView,
    LocalPortsView,
    NetworkView,
    PacketsView,
    ProcessView,
    SettingsView,
)
from netpulse.presentation.app import DATABASE_FLUSH_TICKS, UPDATE_INTERVAL_SECONDS
from netpulse.services.local_ports import LocalListener


class SystemSmokeTests(unittest.TestCase):
    def test_performance_metrics_use_available_desktop_width(self):
        view = ChartsView(AppState())
        view.build()

        view.set_viewport(1400, 1100)

        self.assertEqual(len(view._cards), 4)
        self.assertTrue(all(card.width == 334.0 for card in view._cards))
        self.assertEqual(view._history_card.width, 1372.0)
        self.assertEqual(
            view.r_history.current.horizontal_alignment,
            flet.CrossAxisAlignment.STRETCH,
        )

    def test_performance_history_rows_are_active_styled_cards(self):
        from netpulse.services.performance import QualityResult

        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "quality-style.db")
            db.save_quality_check(
                "Ethernet", QualityResult("10.0.0.1", 4, 4, 4.0, 1.0, 0.0, 3.0, True)
            )
            view = ChartsView(AppState(), [None], db)
            view.build()
            history = view.r_history.current
            self.assertIsNotNone(history)
            view._refresh_evidence()

            row = history.controls[0]
            self.assertIsInstance(row, flet.Container)
            self.assertIsNotNone(row.bgcolor)
            self.assertEqual(row.content.controls[1].color, "#00D4FF")

    def test_capacity_layout_avoids_expanded_columns_inside_wrapped_row(self):
        view = ChartsView(AppState())
        view.build()

        self.assertIsInstance(view._capacity_grid, flet.ResponsiveRow)
        self.assertEqual(len(view._capacity_grid.controls), 4)
        for metric in view._capacity_grid.controls:
            self.assertIsNone(metric.content.expand)
            self.assertEqual(metric.height, 72)

    def test_network_opens_new_scan_mode_without_loading_history(self):
        class PageStub:
            def update(self):
                pass

        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "network-tabs.db")
            now = datetime(2026, 1, 1)
            db.save_network_scan(NetworkScan(
                "192.168.1.0/24", "quick", "nmap", now, now, 1,
                hosts=[ScanHost("192.168.1.10")],
            ))
            view = NetworkView(db, NmapScanner(), [PageStub()])
            view.build()
            view.on_mount()

            tab_bar = view._network_tabs.content.controls[0]
            self.assertEqual(view._network_tabs.length, 5)
            self.assertFalse(tab_bar.scrollable)
            self.assertEqual(tab_bar.tab_alignment, flet.TabAlignment.FILL)
            self.assertIs(view._scan_mode_content.content, view._scan_card)
            self.assertIsNone(view._current_scan)
            self.assertEqual(view.r_devices.current.value, "0")
            self.assertEqual(len(view.r_history.current.options), 1)
            self.assertIsNone(view.r_history.current.value)
            self.assertTrue(view.r_history.current.editable)
            self.assertTrue(view.r_history.current.enable_filter)
            self.assertTrue(view.r_history.current.enable_search)
            self.assertEqual(view.r_history.current.menu_height, 320)

            view._render_scan(db.get_latest_network_scan())
            self.assertEqual(view.r_devices.current.value, "1")
            view._new_scan_button.on_click(None)
            self.assertIsNone(view._current_scan)
            self.assertEqual(view.r_devices.current.value, "0")

    def test_local_ports_refresh_shows_completion_and_requeries(self):
        class PageStub:
            def __init__(self):
                self.update_count = 0

            def update(self):
                self.update_count += 1

        listener = LocalListener(
            "0.0.0.0", 445, "TCP", "IPv4", 10, "servicio.exe", "smb",
            "all_interfaces", "high", "Servicio SMB",
        )
        page = PageStub()
        view = LocalPortsView([page])
        view.build()
        with patch("netpulse.presentation.views.list_local_listeners",
                   return_value=[listener]) as inspect_ports:
            view.refresh()

        inspect_ports.assert_called_once_with()
        self.assertEqual(view.r_total.current.value, "1")
        self.assertIn("Updated at", view.r_refresh_status.current.value)
        self.assertIn("1 listening ports found", view.r_refresh_status.current.value)
        self.assertFalse(view._refresh_button.disabled)
        self.assertGreaterEqual(page.update_count, 2)

    def test_local_ports_refresh_ignores_repeated_click_while_busy(self):
        view = LocalPortsView([None])
        view.build()
        calls = []

        def nested_refresh_attempt():
            calls.append("inspection")
            view.refresh()
            self.assertTrue(view._refreshing)
            self.assertTrue(view._refresh_button.disabled)
            self.assertEqual(view._refresh_button.content, "UPDATING...")
            self.assertTrue(view._refresh_spinner.visible)
            return []

        with patch("netpulse.presentation.views.list_local_listeners",
                   side_effect=nested_refresh_attempt):
            view.refresh()

        self.assertEqual(calls, ["inspection"])
        self.assertFalse(view._refreshing)
        self.assertFalse(view._refresh_button.disabled)
        self.assertEqual(view._refresh_button.content, "REFRESH")
        self.assertFalse(view._refresh_spinner.visible)

    def test_local_ports_desktop_refresh_yields_with_visible_spinner(self):
        class DesktopPageStub:
            def __init__(self):
                self.update_count = 0

            def update(self):
                self.update_count += 1

        page = DesktopPageStub()
        view = LocalPortsView([page])
        view.build()
        view._minimum_refresh_indicator_seconds = 0

        async def scenario():
            entered = asyncio.Event()
            release = asyncio.Event()

            def inspect_ports():
                entered_loop.call_soon_threadsafe(entered.set)
                entered_loop.run_until_complete if False else None
                while not release.is_set():
                    threading.Event().wait(0.001)
                return []

            nonlocal_scope = {"inspect": inspect_ports}
            with patch("netpulse.presentation.views.list_local_listeners",
                       side_effect=lambda: nonlocal_scope["inspect"]()):
                task = asyncio.create_task(view.refresh_async())
                await entered.wait()
                await asyncio.sleep(0)

                self.assertTrue(view._refreshing)
                self.assertTrue(view._refresh_button.disabled)
                self.assertEqual(view._refresh_button.content, "UPDATING...")
                self.assertTrue(view._refresh_spinner.visible)
                self.assertEqual(page.update_count, 1)

                release.set()
                await task

        entered_loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(entered_loop)
            entered_loop.run_until_complete(scenario())
        finally:
            entered_loop.close()
            asyncio.set_event_loop(None)

        self.assertFalse(view._refreshing)
        self.assertFalse(view._refresh_button.disabled)
        self.assertFalse(view._refresh_spinner.visible)
        self.assertEqual(page.update_count, 2)

    def test_history_selector_is_styled_and_selects_latest_session(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "history.db")
            first = db.new_session("Ethernet")
            db.close_session(first, 20, 1024, 512)
            second = db.new_session("Wi-Fi")
            db.save_stat(second, {
                "bytes_in": 2048, "bytes_out": 1024,
                "pkts_in": 30, "pkts_out": 10,
                "TCP": 30, "HTTPS": 20, "DNS": 4,
            })
            db.upsert_ips(second, [("1.1.1.1", 3072, 40)])
            db.close_session(second, 40, 2048, 1024)
            view = HistoryView(db)
            view.build()

            view._reload_sessions()

            self.assertTrue(view._session_dropdown.filled)
            self.assertEqual(view._session_dropdown.value, str(second))
            self.assertEqual(len(view._session_dropdown.options), 2)
            self.assertEqual(view.r_session_count.current.value, "2 sessions")
            self.assertIn("Completed", view.r_info.current.value)
            self.assertIn("Wi-Fi", view.r_info.current.value)
            self.assertEqual(view._metric_values["volume"][0].value, "3.0 KB")
            self.assertEqual(view._metric_values["endpoints"][0].value, "1")
            self.assertGreater(len(view._protocol_rows.controls), 0)
            self.assertEqual(len(view.r_table.current.rows), 1)
            self.assertIn("1.1.1.1", view._insight_text.value)

    def test_inventory_editor_opens_and_persists_device_metadata(self):
        class PageStub:
            def __init__(self):
                self.dialog = None

            def show_dialog(self, dialog):
                dialog.open = True
                self.dialog = dialog

            def pop_dialog(self):
                if self.dialog:
                    self.dialog.open = False

            def update(self):
                pass

        with TemporaryDirectory() as directory:
            page = PageStub()
            db = DB(Path(directory) / "inventory.db")
            now = datetime(2026, 1, 1)
            db.save_network_scan(NetworkScan(
                "172.26.3.0/24", "quick", "nmap", now, now, 1,
                hosts=[ScanHost("172.26.3.10", hostname="equipo")],
            ))
            view = NetworkView(db, NmapScanner(), [page])

            view._edit_inventory("172.26.3.10")

            self.assertIsInstance(page.dialog, flet.AlertDialog)
            fields = page.dialog.content.content.controls
            fields[2].value = "Servidor principal"
            fields[4].value = "Infraestructura"
            fields[5].value = "Oficina"
            fields[7].value = "authorized"
            page.dialog.actions[1].on_click(None)

            device = db.get_inventory_device("172.26.3.10")
            self.assertEqual(device["alias"], "Servidor principal")
            self.assertEqual(device["owner"], "Infraestructura")
            self.assertEqual(device["location"], "Oficina")
            self.assertEqual(device["trust_status"], "authorized")
            self.assertFalse(page.dialog.open)

            view._edit_inventory("172.26.3.10")
            page.dialog.actions[0].on_click(None)
            self.assertFalse(page.dialog.open)

    def test_global_search_finds_saved_device_and_opens_dialog(self):
        class PageStub:
            def __init__(self):
                self.dialog = None

            def show_dialog(self, dialog):
                dialog.open = True
                self.dialog = dialog

            def pop_dialog(self):
                if self.dialog:
                    self.dialog.open = False

        with TemporaryDirectory() as directory:
            page = PageStub()
            db = DB(Path(directory) / "search.db")
            now = datetime(2026, 1, 1)
            db.save_network_scan(NetworkScan(
                "172.26.3.0/24", "quick", "nmap", now, now, 1,
                hosts=[ScanHost("172.26.3.10", hostname="servidor", services=[
                    ScanService(445, "tcp", "open", "microsoft-ds")
                ])],
            ))
            view = NetworkView(db, NmapScanner(), [page])

            view._show_global_search("172.26.3.10")

            self.assertIsInstance(page.dialog, flet.AlertDialog)
            self.assertTrue(page.dialog.open)
            self.assertIn("172.26.3.10", page.dialog.title.value)
            self.assertIsInstance(page.dialog.content, flet.SelectionArea)
            self.assertGreaterEqual(len(page.dialog.content.content.content.controls), 1)

    def test_profile_and_schedule_dialogs_save_and_refresh(self):
        class PageStub:
            def __init__(self):
                self.dialog = None
                self.update_count = 0

            def show_dialog(self, dialog):
                dialog.open = True
                self.dialog = dialog

            def pop_dialog(self):
                if self.dialog:
                    self.dialog.open = False

            def update(self):
                self.update_count += 1

        class ControlStub:
            def __init__(self, **values):
                self.__dict__.update(values)

        with TemporaryDirectory() as directory:
            page = PageStub()
            db = DB(Path(directory) / "profiles.db")
            view = NetworkView(db, NmapScanner(), [page])
            controls = [
                ControlStub(value="172.26.3.0/24"),
                ControlStub(value="quick"),
                ControlStub(value=None, options=[]),
                flet.Column(),
                ControlStub(value="", color=""),
            ]
            view.r_target.current = controls[0]
            view.r_profile.current = controls[1]
            view.r_saved_profile.current = controls[2]
            view.r_schedule_list.current = controls[3]
            view.r_status.current = controls[4]

            view._show_save_profile_dialog()
            page.dialog.content.value = "Red administrativa"
            page.dialog.actions[1].on_click(None)

            self.assertEqual(len(db.list_scan_profiles()), 1)
            self.assertEqual(view.r_saved_profile.current.value, "1")

            view._show_schedule_dialog()
            page.dialog.actions[1].on_click(None)

            self.assertEqual(len(db.list_scan_schedules()), 1)
            self.assertIn("Scheduled", view.r_status.current.value)

    def test_network_alert_modal_uses_page_from_shared_reference(self):
        class PageStub:
            def __init__(self):
                self.dialog = None

            def show_dialog(self, dialog):
                dialog.open = True
                self.dialog = dialog

            def pop_dialog(self):
                if self.dialog:
                    self.dialog.open = False

        with TemporaryDirectory() as directory:
            page = PageStub()
            view = NetworkView(DB(Path(directory) / "alerts.db"), NmapScanner(), [page])
            now = datetime(2026, 1, 1)
            view._current_scan = NetworkScan(
                "172.26.3.0/24", "quick", "nmap", now, now, 1,
                hosts=[ScanHost("172.26.3.10")],
            )

            view._select_host("172.26.3.10")

            self.assertIsInstance(page.dialog, flet.AlertDialog)
            self.assertTrue(page.dialog.open)

    def test_desktop_app_view_is_available(self):
        self.assertEqual(flet.AppView.FLET_APP.value, "flet_app")

    def test_dependencies_and_all_ui_components_load(self):
        self.assertTrue(flet.__version__)
        self.assertTrue(scapy.__version__)
        self.assertTrue(psutil.__version__)

        state = AppState()
        charts = [
            LineChartCanvas(),
            SparklineCanvas(),
            BarChartCanvas(["TCP"], ["#00D4FF"]),
            PieChartCanvas(),
        ]
        charts[0].update_data([0, 1, 2], [2, 1, 0])
        charts[1].update_data([0, 1, 2])
        charts[2].update_data([3])
        charts[3].update_data([("HTTPS", 100.0, "#3B82F6")])
        charts[0].resize(720, 240)
        charts[2].resize(480, 190)
        charts[3].resize(160)
        views = [
            DashboardView(state).build(),
            PacketsView(state, [None]).build(),
            ChartsView(state).build(),
            SettingsView(state).build(),
            ProcessView(state).build(),
            LocalPortsView([None]).build(),
        ]

        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "smoke.db")
            views.append(HistoryView(db).build())
            views.append(NetworkView(db, NmapScanner(), [None]).build())

        self.assertEqual(len(charts), 4)
        self.assertEqual(charts[0].W, 720.0)
        self.assertEqual(charts[2].H, 190.0)
        self.assertEqual(charts[3].SIZE, 160.0)
        self.assertEqual(len(views), 8)
        self.assertEqual(UPDATE_INTERVAL_SECONDS, 0.2)
        self.assertEqual(DATABASE_FLUSH_TICKS, 5)

    def test_dashboard_detail_cards_keep_the_same_size(self):
        view = DashboardView(AppState())
        view.build()

        view.set_viewport(1200, 800)

        self.assertEqual(view._detail_cards[0].width, view._detail_cards[1].width)
        self.assertEqual(view._detail_cards[0].height, view._detail_cards[1].height)
        self.assertGreaterEqual(view._detail_cards[0].height, 210)

    def test_network_scan_cancellation_does_not_update_destroyed_page(self):
        class ClosingPage:
            def __init__(self):
                self.destroyed = False
                self.update_count = 0

            def update(self):
                if self.destroyed:
                    raise RuntimeError("An attempt to fetch destroyed session.")
                self.update_count += 1

        class ControlStub:
            def __init__(self, **values):
                self.__dict__.update(values)

        class BlockingScanner:
            available = True

            def __init__(self):
                self.started = threading.Event()
                self.cancelled = threading.Event()

            @staticmethod
            def default_target():
                return "127.0.0.1"

            def scan(self, target, profile, cancel_event):
                self.started.set()
                while not cancel_event.wait(0.01):
                    pass
                self.cancelled.set()
                return None

            def cancel(self):
                self.cancelled.set()

        async def exercise():
            with TemporaryDirectory() as directory:
                page = ClosingPage()
                scanner = BlockingScanner()
                view = NetworkView(
                    DB(Path(directory) / "cancel.db"), scanner, [page]
                )
                controls = [
                    ControlStub(value="127.0.0.1"),
                    ControlStub(value="quick"),
                    ControlStub(disabled=False),
                    ControlStub(visible=False),
                    ControlStub(value="", color=""),
                ]
                view.r_target.current = controls[0]
                view.r_profile.current = controls[1]
                view.r_scan.current = controls[2]
                view.r_progress.current = controls[3]
                view.r_status.current = controls[4]
                task = asyncio.create_task(view._run_scan())
                await asyncio.to_thread(scanner.started.wait, 1)
                page.destroyed = True
                task.cancel()
                await task
                await asyncio.to_thread(scanner.cancelled.wait, 1)
                self.assertTrue(view._disposed)
                self.assertEqual(page.update_count, 1)

        asyncio.run(exercise())

    def test_process_refresh_does_not_update_unmounted_table(self):
        state = AppState()
        view = ProcessView(state)
        empty = flet.Text("empty")
        table = flet.Column()
        total = flet.Text()
        procs = flet.Text()
        view._empty_control = empty
        view.r_table.current = table
        view.r_total.current = total
        view.r_procs.current = procs

        view.refresh()

        self.assertEqual(total.value, "0 KB total")
        self.assertEqual(procs.value, "0 processes")
        self.assertEqual(table.controls, [empty])

    def test_scheduled_scan_executes_persists_and_notifies_relevant_change(self):
        class PageStub:
            def __init__(self):
                self.update_count = 0

            def update(self):
                self.update_count += 1

        class ScheduledScanner:
            available = True

            @staticmethod
            def default_target():
                return "10.0.0.0/24"

            def scan(self, target, profile, cancel_event):
                now = datetime(2026, 1, 1, 10, 30)
                return NetworkScan(
                    target, profile, "nmap", now, now, 1,
                    hosts=[ScanHost("10.0.0.2", services=[
                        ScanService(23, "tcp", "open", "telnet", risk_level="high")
                    ], risk_score=75, risk_level="high")],
                    nmap_version="7.99",
                )

            def cancel(self):
                pass

        async def exercise():
            with TemporaryDirectory() as directory:
                db = DB(Path(directory) / "scheduled.db")
                baseline_time = datetime(2026, 1, 1, 10, 0)
                db.save_network_scan(NetworkScan(
                    "10.0.0.0/24", "quick", "nmap", baseline_time, baseline_time, 1,
                    hosts=[ScanHost("10.0.0.2")],
                ))
                profile_id = db.save_scan_profile("Servidores", "10.0.0.0/24", "quick")
                schedule_id = db.save_scan_schedule(profile_id, 30, True, baseline_time)
                notifications = []
                page = PageStub()
                view = NetworkView(
                    db, ScheduledScanner(), [page], AppState(),
                    notification_sink=lambda title, message: notifications.append((title, message)),
                )
                view.build()
                schedule = next(item for item in db.list_scan_schedules()
                                if item["id"] == schedule_id)

                await view._run_scheduled_scan(schedule)

                self.assertEqual(db.list_scan_schedules()[0]["last_status"], "completed")
                self.assertEqual(len(db.list_network_scans()), 2)
                self.assertEqual(len(notifications), 1)
                self.assertIn("23/tcp", notifications[0][1])
                self.assertFalse(view._running)

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
