import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import flet as ft

from netpulse.config import load_appearance, save_appearance
from netpulse.domain.state import AppState
from netpulse.presentation.theme import appearance_palette, recolor_tree
from netpulse.presentation.views import SettingsView


def walk(control):
    yield control
    for name in ("content", "controls"):
        value = getattr(control, name, None)
        children = value if isinstance(value, list) else [value]
        for child in children:
            if isinstance(child, ft.Control):
                yield from walk(child)


class AppearanceTests(unittest.TestCase):
    def test_settings_balances_cards_without_forced_height(self):
        view = SettingsView(AppState())
        view.build()
        view.set_viewport(1400, 900)

        left, right = view._settings_columns
        database_card = view._cards[4]
        appearance_card = view._cards[2]
        self.assertIn(database_card, left.controls)
        self.assertIn(appearance_card, right.controls)
        self.assertEqual(database_card.width, left.width)
        self.assertEqual(appearance_card.width, right.width)
        self.assertIsNone(left.height)
        self.assertIsNone(right.height)
        self.assertFalse(appearance_card.expand)

    def test_appearance_preferences_persist_and_are_validated(self):
        with TemporaryDirectory() as directory:
            settings = Path(directory) / "settings.json"
            settings.write_text('{"language": "es"}', encoding="utf-8")
            with patch("netpulse.config.DEFAULT_SETTINGS_PATH", settings):
                save_appearance("graphite", "purple", "compact")
                self.assertEqual(load_appearance(), {
                    "theme": "graphite", "accent": "purple", "density": "compact",
                })
                data = json.loads(settings.read_text(encoding="utf-8"))
                self.assertEqual(data["language"], "es")

                save_appearance("invalid", "invalid", "invalid")
                self.assertEqual(load_appearance(), {
                    "theme": "netpulse", "accent": "cyan", "density": "standard",
                })

    def test_recolor_tree_updates_backgrounds_and_accent(self):
        old = appearance_palette("netpulse", "cyan")
        new = appearance_palette("black", "amber")
        icon = ft.Icon(ft.Icons.PALETTE, color=old["accent"])
        control = ft.Container(icon, bgcolor=old["card"])

        recolor_tree(control, old, new)

        self.assertEqual(control.bgcolor, new["card"])
        self.assertEqual(icon.color, new["accent"])

    def test_settings_apply_button_emits_selected_appearance(self):
        changes = []
        view = SettingsView(
            AppState(), appearance={
                "theme": "midnight", "accent": "green", "density": "comfortable",
            }, on_appearance_change=lambda *values: changes.append(values),
        )
        root = view.build()
        buttons = [item for item in walk(root) if isinstance(item, ft.Button)]
        apply_button = next(item for item in buttons if item.content == "APPLY APPEARANCE")

        apply_button.on_click(None)

        self.assertEqual(changes, [("midnight", "green", "comfortable")])

    def test_settings_interface_change_updates_state_and_notifies_header(self):
        state = AppState()
        changes = []
        view = SettingsView(
            state,
            on_interface_change=lambda value: changes.append(value),
        )
        view.build()

        view._interface_dropdown.on_select(
            SimpleNamespace(control=SimpleNamespace(value="Wi-Fi 2"))
        )

        self.assertEqual(state.interface, "Wi-Fi 2")
        self.assertEqual(changes, ["Wi-Fi 2"])


if __name__ == "__main__":
    unittest.main()
