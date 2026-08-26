"""Guards against the Flet 0.85 dialog API regression.

Flet 0.85 removed ``Page.dialog``. Assigning it produces a stray attribute and
the dialog never becomes visible, which previously hid capture errors, traffic
alerts, service explanations and export confirmations. These tests fail if any
call site returns to the removed API, and they exercise the helpers against a
stub that behaves like the real page instead of tolerating the old attribute.
"""

import ast
import unittest
from datetime import datetime
from pathlib import Path

import flet as ft

from netpulse.domain.network_scan import NetworkScan, ScanHost, ScanService
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import NmapScanner
from netpulse.presentation.dialogs import (
    close_dialog, open_dialog, supports_modern_dialog_api,
)
from netpulse.presentation.views import NetworkView

PRESENTATION = Path(__file__).resolve().parent.parent / "netpulse" / "presentation"


class StrictPage:
    """Page double that mirrors Flet 0.85: no ``dialog`` attribute allowed."""

    __slots__ = ("shown", "updates")

    def __init__(self):
        self.shown = []
        self.updates = 0

    def show_dialog(self, dialog):
        dialog.open = True
        self.shown.append(dialog)

    def pop_dialog(self):
        if self.shown:
            self.shown[-1].open = False

    def update(self):
        self.updates += 1

    @property
    def current_dialog(self):
        return self.shown[-1] if self.shown else None


class LegacyPage:
    """Page double for older embeddings that only expose ``dialog``."""

    def __init__(self):
        self.dialog = None
        self.updates = 0

    def update(self):
        self.updates += 1


class DialogApiTests(unittest.TestCase):
    def test_installed_flet_page_uses_the_modern_dialog_api(self):
        self.assertTrue(hasattr(ft.Page, "show_dialog"))
        self.assertTrue(hasattr(ft.Page, "pop_dialog"))
        self.assertFalse(
            hasattr(ft.Page, "dialog"),
            "Page.dialog reappeared; revisit netpulse.presentation.dialogs",
        )

    def test_helpers_detect_the_modern_api(self):
        self.assertTrue(supports_modern_dialog_api(StrictPage()))
        self.assertFalse(supports_modern_dialog_api(LegacyPage()))

    def test_open_and_close_on_a_strict_page(self):
        page = StrictPage()
        dialog = ft.AlertDialog(title=ft.Text("hello"))
        open_dialog(page, dialog)
        self.assertIs(page.current_dialog, dialog)
        self.assertTrue(dialog.open)
        close_dialog(page)
        self.assertFalse(dialog.open)

    def test_open_and_close_on_a_legacy_page(self):
        page = LegacyPage()
        dialog = ft.AlertDialog(title=ft.Text("hello"))
        open_dialog(page, dialog)
        self.assertIs(page.dialog, dialog)
        self.assertTrue(dialog.open)
        close_dialog(page)
        self.assertFalse(dialog.open)

    def test_helpers_ignore_missing_page_or_dialog(self):
        open_dialog(None, ft.AlertDialog())
        open_dialog(StrictPage(), None)
        close_dialog(None)


class NoLegacyDialogAssignmentTests(unittest.TestCase):
    """Static guard: only ``dialogs.py`` may touch the legacy attribute."""

    def test_presentation_modules_never_assign_page_dialog(self):
        offenders = []
        for module in sorted(PRESENTATION.glob("*.py")):
            if module.name == "dialogs.py":
                continue
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    targets = [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and target.attr == "dialog":
                        offenders.append(f"{module.name}:{node.lineno}")
        self.assertEqual(offenders, [], f"legacy page.dialog assignment: {offenders}")

    def test_presentation_modules_call_dialogs_through_the_helpers(self):
        offenders = []
        for module in sorted(PRESENTATION.glob("*.py")):
            if module.name == "dialogs.py":
                continue
            source = module.read_text(encoding="utf-8")
            for name in (".show_dialog(", ".pop_dialog("):
                if name in source:
                    offenders.append(f"{module.name}{name}")
        self.assertEqual(offenders, [], f"bypasses the dialog helpers: {offenders}")


class ServiceExplanationDialogTests(unittest.TestCase):
    def test_service_explanation_reaches_a_strict_page(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            page = StrictPage()
            db = DB(Path(directory) / "explain.db")
            now = datetime(2026, 1, 1)
            service = ScanService(23, "tcp", "open", "telnet", risk_level="high")
            view = NetworkView(db, NmapScanner(), [page])
            view._current_scan = NetworkScan(
                "172.26.3.0/24", "quick", "nmap", now, now, 1,
                hosts=[ScanHost("172.26.3.10", services=[service])],
            )

            view._show_service_explanation("172.26.3.10", service)

            dialog = page.current_dialog
            self.assertIsInstance(dialog, ft.AlertDialog)
            self.assertTrue(dialog.open)
            self.assertIn("23/tcp", dialog.title.controls[1].value)


if __name__ == "__main__":
    unittest.main()
