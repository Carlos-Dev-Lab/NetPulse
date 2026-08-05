import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest

import flet
import psutil
import scapy

from netpulse.domain.state import AppState
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
    NetworkView,
    PacketsView,
    ProcessView,
    SettingsView,
)
from netpulse.presentation.app import DATABASE_FLUSH_TICKS, UPDATE_INTERVAL_SECONDS


class SystemSmokeTests(unittest.TestCase):
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
        ]

        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "smoke.db")
            views.append(HistoryView(db).build())
            views.append(NetworkView(db, NmapScanner(), [None]).build())

        self.assertEqual(len(charts), 4)
        self.assertEqual(charts[0].W, 720.0)
        self.assertEqual(charts[2].H, 190.0)
        self.assertEqual(charts[3].SIZE, 160.0)
        self.assertEqual(len(views), 7)
        self.assertEqual(UPDATE_INTERVAL_SECONDS, 0.2)
        self.assertEqual(DATABASE_FLUSH_TICKS, 5)

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


if __name__ == "__main__":
    unittest.main()
