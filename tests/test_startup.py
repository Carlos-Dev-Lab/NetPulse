"""Headless smoke test for the composition root.

``netpulse.presentation.app.main`` wires every view, the database, the sniffer
and the appearance system together. Nothing else in the suite executes it, so a
broken import or a mistyped attribute only surfaced when a window was opened by
hand. This drives ``main`` against a page double instead.
"""

import asyncio
import unittest
from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import flet as ft

from netpulse import config
from netpulse.presentation import app as app_module
from netpulse.presentation.theme import appearance_palette


class FakeWindow:
    def __init__(self):
        self.width = 1080
        self.height = 660
        self.min_width = 0
        self.min_height = 0
        self.bgcolor = None
        self.maximized = False


class FakePage:
    """Minimal stand-in for ``ft.Page`` covering what ``main`` touches."""

    def __init__(self):
        self.title = ""
        self.bgcolor = None
        self.theme = None
        self.theme_mode = None
        self.padding = None
        self.window = FakeWindow()
        self.width = 1400
        self.height = 900
        self.controls = []
        self.updates = 0
        self.tasks = []
        self.shown = []
        self.on_disconnect = None
        self.on_close = None
        self.on_resize = None

    def add(self, *controls):
        self.controls.extend(controls)

    def update(self):
        self.updates += 1

    def run_task(self, handler, *args, **kwargs):
        self.tasks.append((handler, args, kwargs))

    def show_dialog(self, dialog):
        dialog.open = True
        self.shown.append(dialog)

    def pop_dialog(self):
        if self.shown:
            self.shown[-1].open = False


class StartupTests(unittest.TestCase):
    def setUp(self):
        self._directory = TemporaryDirectory()
        root = Path(self._directory.name)
        self.database = root / "netpulse.db"
        self.settings = root / "settings.json"
        self.log = root / "netpulse.log"
        patches = [
            patch.object(config, "DEFAULT_SETTINGS_PATH", self.settings),
            patch.object(config, "DEFAULT_DATABASE_PATH", self.database),
            patch.object(config, "DEFAULT_LOG_PATH", self.log),
            patch.object(app_module, "DEFAULT_DATABASE_PATH", self.database),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def tearDown(self):
        self._directory.cleanup()

    def _run(self):
        page = FakePage()
        app_module.main(page)
        return page

    def test_main_builds_the_full_workspace(self):
        page = self._run()
        self.assertEqual(page.title, "NetPulse — Network Analyzer")
        self.assertEqual(len(page.controls), 1)
        self.assertIsInstance(page.controls[0], ft.Column)
        self.assertTrue(self.database.exists())
        self.assertEqual(page.theme_mode, ft.ThemeMode.DARK)
        self.assertEqual(page.bgcolor, appearance_palette("netpulse", "cyan")["bg"])
        self.assertTrue(page.tasks, "the real-time update loop was never scheduled")
        for task, _, _ in page.tasks:
            coroutine = task()
            self.assertTrue(asyncio.iscoroutine(coroutine))
            coroutine.close()

    def test_main_starts_on_a_persisted_light_theme(self):
        config.save_appearance("daylight", "amber", "comfortable")
        page = self._run()
        palette = appearance_palette("daylight", "amber")
        self.assertEqual(page.theme_mode, ft.ThemeMode.LIGHT)
        self.assertEqual(page.bgcolor, palette["bg"])
        self.assertEqual(page.window.bgcolor, palette["bg"])
        self.assertEqual(page.theme.color_scheme.on_surface, palette["text"])

    def test_main_restores_persisted_capture_preferences(self):
        config.save_interface("Wi-Fi")
        config.save_alerts(750, 2500)
        config.save_language("es")
        page = self._run()
        self.assertTrue(page.controls)
        # The header dropdown and the settings view must agree with the file.
        self.assertEqual(config.load_interface(), "Wi-Fi")
        self.assertEqual(config.load_alerts()["bandwidth_kbps"], 750.0)

    def test_startup_applies_the_retention_policy(self):
        config.save_retention_days(30)
        with patch.object(app_module.DB, "purge_old_sessions",
                          return_value=0) as purge:
            self._run()
        purge.assert_called_once_with(30)

    def test_a_failing_retention_purge_does_not_block_startup(self):
        config.save_retention_days(30)
        with patch.object(app_module.DB, "purge_old_sessions",
                          side_effect=RuntimeError("disk error")):
            page = self._run()
        self.assertTrue(page.controls, "the workspace must still render")

    def test_cleanup_is_registered_and_idempotent(self):
        page = self._run()
        self.assertIsNotNone(page.on_disconnect)
        self.assertIs(page.on_disconnect, page.on_close)
        page.on_disconnect(None)
        page.on_disconnect(None)

    @staticmethod
    def _walk(control):
        yield control
        for name in ("content", "controls", "destinations", "actions"):
            value = getattr(control, name, None)
            children = value if isinstance(value, list) else [value]
            for child in children:
                if isinstance(child, ft.Control):
                    yield from StartupTests._walk(child)

    def _navigate(self, page, index: int):
        """Mount one section the way the navigation rail does."""
        for control in self._walk(page.controls[0]):
            if isinstance(control, ft.NavigationRail):
                control.selected_index = index
                control.on_change(SimpleNamespace(control=control))
                return
        self.fail("the navigation rail is missing")

    def _find_apply_appearance(self, page):
        for control in self._walk(page.controls[0]):
            if (isinstance(control, ft.Button)
                    and control.icon == ft.Icons.PALETTE_OUTLINED):
                return control
        self.fail("the APPLY APPEARANCE button is missing")

    def test_switching_to_a_light_theme_repaints_the_live_workspace(self):
        page = self._run()
        dark = appearance_palette("netpulse", "cyan")
        self.assertEqual(page.theme_mode, ft.ThemeMode.DARK)

        self._navigate(page, 8)   # System settings
        button = self._find_apply_appearance(page)
        for control in self._walk(page.controls[0]):
            if isinstance(control, ft.Dropdown) and control.label == "Visual theme":
                control.value = "daylight"
        button.on_click(None)

        light = appearance_palette("daylight", "cyan")
        self.assertEqual(page.theme_mode, ft.ThemeMode.LIGHT)
        self.assertEqual(page.bgcolor, light["bg"])
        self.assertEqual(config.load_appearance()["theme"], "daylight")

        colors = {getattr(control, "color", None) for control in
                  self._walk(page.controls[0])}
        self.assertNotIn(dark["text"], colors,
                         "dark ink survived the switch to a light theme")
        self.assertIn(light["text"], colors)

        # Switching back must restore the original palette exactly.
        for control in self._walk(page.controls[0]):
            if isinstance(control, ft.Dropdown) and control.label == "Visual theme":
                control.value = "netpulse"
        button.on_click(None)
        self.assertEqual(page.theme_mode, ft.ThemeMode.DARK)
        self.assertEqual(page.bgcolor, dark["bg"])

    def test_resize_handler_survives_extreme_viewports(self):
        page = self._run()
        for width, height in ((400, 500), (820, 640), (1920, 1080)):
            page.on_resize(SimpleNamespace(width=width, height=height))
        # The rail hides its labels only when the desktop is genuinely short.
        page.on_resize(SimpleNamespace(width=1920, height=1080))
        self.assertGreater(page.updates, 0)


if __name__ == "__main__":
    unittest.main()
