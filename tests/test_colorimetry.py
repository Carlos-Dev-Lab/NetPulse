"""Colorimetric contract for every theme, measured on the real control trees.

Palette-level checks are not enough: a view can hardcode a colour, and only the
section Flet has mounted gets repainted unless every wrapper is walked. These
tests build all eight sections for all six themes, composite each control's
background the way the renderer does, and assert the WCAG floor on what is
actually on screen.
"""

import colorsys
import itertools
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import flet as ft

from netpulse import config
from netpulse.presentation import app as app_module
from netpulse.presentation.charts import apply_palette as apply_chart_palette
from netpulse.config import ACCENTS
from netpulse.presentation.theme import (
    AMBER, APPEARANCE_THEMES, BORDER, CYAN, MUTED, PALETTE_ROLES, PROTO_ROLES,
    RED, appearance_palette, apply_accent, card, clear_accent_registry,
    proto_color, recolor_tree, set_active_palette, view_heading,
)
from netpulse.presentation.views import NetworkView

VIEW_NAMES = ["Overview", "Network", "Apps", "Packets",
              "Analytics", "History", "Local ports", "Data", "Settings"]
CHILD_ATTRS = ("content", "controls", "actions", "destinations", "leading",
               "trailing", "title", "subtitle", "rows", "cells", "icon")

# Contrast floors.
BODY_TEXT = 4.5          # WCAG AA for text below 18pt (or below 14pt bold)
LARGE_TEXT = 3.0         # WCAG AA for large text
NON_TEXT = 3.0           # WCAG 1.4.11 for meaningful icons
BORDER_VISIBLE = 1.5     # a card edge has to separate the card from its ground
ELEVATION_STEP = 1.09    # bg -> surface -> card
ELEVATION_TOTAL = 1.19   # bg -> card


# ── colour maths ─────────────────────────────────────────────────────────────
def parse(color):
    if not isinstance(color, str) or not color.startswith("#"):
        return None
    body = color[1:]
    if len(body) == 6:
        alpha, offset = 255, 0
    elif len(body) == 8:
        alpha, offset = int(body[0:2], 16), 2
    else:
        return None
    channels = [int(body[offset + i:offset + i + 2], 16) / 255 for i in (0, 2, 4)]
    return (*channels, alpha / 255)


def composite(front, back):
    alpha = front[3]
    return tuple(front[i] * alpha + back[i] * (1 - alpha) for i in range(3)) + (1.0,)


def luminance(color):
    def channel(value):
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4
    return (0.2126 * channel(color[0]) + 0.7152 * channel(color[1])
            + 0.0722 * channel(color[2]))


def contrast(first, second):
    light, dark = luminance(first), luminance(second)
    if light < dark:
        light, dark = dark, light
    return (light + 0.05) / (dark + 0.05)


def ratio(first, second):
    return contrast(parse(first), parse(second))


def hue(color):
    red, green, blue = parse(color)[:3]
    return colorsys.rgb_to_hls(red, green, blue)[0] * 360


def saturation(color):
    red, green, blue = parse(color)[:3]
    return colorsys.rgb_to_hls(red, green, blue)[2] * 100


def hue_distance(first, second):
    delta = abs(hue(first) - hue(second)) % 360
    return min(delta, 360 - delta)


def text_floor(control):
    size = getattr(control, "size", None) or 14
    weight = getattr(control, "weight", None)
    bold = weight in (ft.FontWeight.BOLD, ft.FontWeight.W_600, ft.FontWeight.W_700,
                      ft.FontWeight.W_800, ft.FontWeight.W_900)
    if size >= 18 or (size >= 14 and bold):
        return LARGE_TEXT
    return BODY_TEXT


# ── tree walk ────────────────────────────────────────────────────────────────
def collect(control, background, findings, seen):
    if control is None or isinstance(control, (str, int, float, bool)):
        return
    if id(control) in seen:
        return
    seen.add(id(control))

    own = parse(getattr(control, "bgcolor", None))
    if own is not None:
        background = composite(own, background)

    if isinstance(control, (ft.Text, ft.Icon)):
        foreground = parse(getattr(control, "color", None))
        if foreground is not None:
            effective = composite(foreground, background)
            need = NON_TEXT if isinstance(control, ft.Icon) else text_floor(control)
            findings.append({
                "kind": type(control).__name__,
                "label": getattr(control, "value", "") or "",
                "ratio": contrast(effective, background),
                "need": need,
                "size": getattr(control, "size", None),
            })

    border = getattr(control, "border", None)
    if border is not None:
        for side_name in ("top", "right", "bottom", "left"):
            side = getattr(border, side_name, None)
            color = parse(getattr(side, "color", None)) if side else None
            if color is not None:
                effective = composite(color, background)
                findings.append({
                    "kind": "Border", "label": "", "size": None,
                    "ratio": contrast(effective, background), "need": 1.0,
                })

    for attr in CHILD_ATTRS:
        child = getattr(control, attr, None)
        if isinstance(child, (list, tuple)):
            for item in child:
                collect(item, background, findings, seen)
        elif child is not None:
            collect(child, background, findings, seen)


class FakeWindow:
    width = height = min_width = min_height = 0
    bgcolor = None
    maximized = False


class FakePage:
    def __init__(self):
        self.title = self.bgcolor = self.theme = self.theme_mode = None
        self.padding = None
        self.window = FakeWindow()
        self.width, self.height = 1600, 1000
        self.controls, self.tasks, self.shown = [], [], []
        self.on_disconnect = self.on_close = self.on_resize = None

    def add(self, *controls):
        self.controls.extend(controls)

    def update(self):
        pass

    def run_task(self, handler, *args, **kwargs):
        self.tasks.append(handler)

    def show_dialog(self, dialog):
        self.shown.append(dialog)

    def pop_dialog(self):
        pass


def find_rail(root):
    stack, seen = [root], set()
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, ft.NavigationRail):
            return node
        for attr in CHILD_ATTRS:
            child = getattr(node, attr, None)
            if isinstance(child, (list, tuple)):
                stack.extend(item for item in child if isinstance(item, ft.Control))
            elif isinstance(child, ft.Control):
                stack.append(child)
    return None


def audit_theme(theme, accent="cyan"):
    """Build every section for one theme and measure what is on screen."""
    findings = []
    with TemporaryDirectory() as directory:
        root = Path(directory)
        with patch.object(config, "DEFAULT_SETTINGS_PATH", root / "settings.json"), \
             patch.object(config, "DEFAULT_DATABASE_PATH", root / "netpulse.db"), \
             patch.object(config, "DEFAULT_LOG_PATH", root / "netpulse.log"), \
             patch.object(app_module, "DEFAULT_DATABASE_PATH", root / "netpulse.db"):
            config.save_appearance(theme, accent, "standard")
            page = FakePage()
            app_module.main(page)
            layout = page.controls[0]
            rail = find_rail(layout)
            palette = appearance_palette(theme, accent)
            page_bg = parse(palette["bg"])
            for index, name in enumerate(VIEW_NAMES):
                if rail is not None:
                    rail.selected_index = index
                    rail.on_change(SimpleNamespace(control=rail))
                found = []
                collect(layout, page_bg, found, set())
                for item in found:
                    item["view"] = name
                findings.extend(found)
    return findings


class RenderedContrastTests(unittest.TestCase):
    """The audit that catches hardcoded colours and unrepainted sections."""

    @classmethod
    def setUpClass(cls):
        cls.results = {theme: audit_theme(theme) for theme in APPEARANCE_THEMES}

    @classmethod
    def tearDownClass(cls):
        default = appearance_palette("netpulse", "cyan")
        set_active_palette(default)
        apply_chart_palette(default)

    def test_every_label_meets_its_wcag_floor_in_every_theme(self):
        problems = []
        for theme, findings in self.results.items():
            for item in findings:
                if item["kind"] == "Border":
                    continue
                if item["ratio"] < item["need"]:
                    problems.append(
                        f"{theme}/{item['view']}: {item['ratio']:.2f}:1 "
                        f"(needs {item['need']}) size={item['size']} "
                        f"{item['label'][:40]!r}"
                    )
        unique = sorted(set(problems))
        self.assertEqual(unique, [], "\n".join(unique[:25]))

    def test_the_audit_actually_inspected_every_section(self):
        for theme, findings in self.results.items():
            views = {item["view"] for item in findings}
            self.assertEqual(views, set(VIEW_NAMES), theme)
            self.assertGreater(len(findings), 200, theme)


class PaletteStructureTests(unittest.TestCase):
    def test_surfaces_form_a_visible_elevation_ladder(self):
        for name in APPEARANCE_THEMES:
            palette = appearance_palette(name, "cyan")
            self.assertGreaterEqual(
                ratio(palette["bg"], palette["surface"]), ELEVATION_STEP,
                f"{name}: background and surface are indistinguishable")
            self.assertGreaterEqual(
                ratio(palette["surface"], palette["card"]), 1.02,
                f"{name}: surface and card are indistinguishable")
            self.assertGreaterEqual(
                ratio(palette["bg"], palette["card"]), ELEVATION_TOTAL,
                f"{name}: cards do not lift off the background")

    def test_borders_separate_every_surface(self):
        for name in APPEARANCE_THEMES:
            palette = appearance_palette(name, "cyan")
            for surface in ("bg", "surface", "card"):
                self.assertGreaterEqual(
                    ratio(palette["border"], palette[surface]), BORDER_VISIBLE,
                    f"{name}: the border vanishes on {surface}")

    def test_ink_and_status_clear_the_body_text_floor_on_every_surface(self):
        for name in APPEARANCE_THEMES:
            palette = appearance_palette(name, "cyan")
            roles = ("text", "dim", "muted", "cyan", "green",
                     "red", "amber", "purple", "blue")
            for role in roles:
                for surface in ("bg", "surface", "card"):
                    self.assertGreaterEqual(
                        ratio(palette[role], palette[surface]), BODY_TEXT,
                        f"{name}: {role} on {surface} is below AA for small text")

    def test_primary_text_reaches_aaa_on_cards(self):
        for name in APPEARANCE_THEMES:
            palette = appearance_palette(name, "cyan")
            self.assertGreaterEqual(ratio(palette["text"], palette["card"]), 7.0, name)

    def test_muted_is_a_neutral_not_a_third_blue(self):
        """MUTED is the OTHER chip; saturation is what keeps it out of the blues."""
        for name in APPEARANCE_THEMES:
            palette = appearance_palette(name, "cyan")
            self.assertLessEqual(
                saturation(palette["muted"]), 20.0,
                f"{name}: the neutral reads as a colour, not as 'no category'")


class ProtocolLegibilityTests(unittest.TestCase):
    """Protocol chips sit side by side in the packet table and the donut."""

    def _chips(self, theme):
        palette = appearance_palette(theme, "cyan")
        return {name: palette[role] for name, role in PROTO_ROLES.items()}

    def test_no_two_chips_are_confusable(self):
        for name in APPEARANCE_THEMES:
            chips = self._chips(name)
            for (first, one), (second, two) in itertools.combinations(chips.items(), 2):
                close_hue = hue_distance(one, two) < 25
                close_lightness = ratio(one, two) < 1.7
                close_saturation = abs(saturation(one) - saturation(two)) < 25
                self.assertFalse(
                    close_hue and close_lightness and close_saturation,
                    f"{name}: {first} {one} and {second} {two} are too alike "
                    f"(hue {hue_distance(one, two):.0f} deg, "
                    f"contrast {ratio(one, two):.2f}, "
                    f"saturation gap {abs(saturation(one)-saturation(two)):.0f})")

    def test_https_clears_the_tcp_cyan(self):
        """The regression that motivated moving BLUE from 217 to 232 degrees."""
        for name in APPEARANCE_THEMES:
            chips = self._chips(name)
            self.assertGreaterEqual(
                hue_distance(chips["TCP"], chips["HTTPS"]), 38.0, name)

    def test_a_theme_keeps_protocol_identity_across_light_and_dark(self):
        dark = self._chips("netpulse")
        light = self._chips("daylight")
        for protocol in dark:
            self.assertLessEqual(
                hue_distance(dark[protocol], light[protocol]), 12.0,
                f"{protocol} changes identity between light and dark")


class ColourDisciplineTests(unittest.TestCase):
    """Colour has to earn its place: chrome, state and data stay separate."""

    def test_no_accent_reuses_a_state_colour(self):
        for theme in APPEARANCE_THEMES:
            for accent in ACCENTS:
                palette = appearance_palette(theme, accent)
                for role in ("green", "amber", "red"):
                    self.assertNotEqual(
                        palette["accent"].upper(), palette[role].upper(),
                        f"{theme}/{accent}: the chrome would read as {role}")

    def test_every_accent_is_legible_as_chrome(self):
        for theme in APPEARANCE_THEMES:
            for accent in ACCENTS:
                palette = appearance_palette(theme, accent)
                for surface in ("bg", "surface", "card"):
                    self.assertGreaterEqual(
                        ratio(palette["accent"], palette[surface]), BODY_TEXT,
                        f"{theme}/{accent} on {surface}")

    def test_card_frames_are_structural_not_chromatic(self):
        """One screen used to show five or six different frame colours."""
        frame = card(ft.Text("x"))
        self.assertEqual(frame.border.top.color, BORDER)
        with self.assertRaises(TypeError):
            card(ft.Text("x"), glow=CYAN)

    def test_the_benign_risk_level_is_neutral(self):
        """Ninety uneventful ports must not out-shout the two that matter."""
        self.assertEqual(NetworkView._risk_color("low"), MUTED)
        self.assertEqual(NetworkView._risk_color("high"), RED)
        self.assertEqual(NetworkView._risk_color("medium"), AMBER)


class AccentIsolationTests(unittest.TestCase):
    """Changing the accent must not touch a single data colour."""

    def setUp(self):
        clear_accent_registry()
        self.addCleanup(clear_accent_registry)
        self.addCleanup(set_active_palette, appearance_palette("netpulse", "cyan"))

    def test_registered_chrome_moves_and_data_stays(self):
        base = appearance_palette("netpulse", "cyan")
        heading = view_heading("Overview", "sub", ft.Icons.HUB_ROUNDED)
        plate = heading.content.controls[0]
        chip = ft.Text("TCP", color=base["cyan"])
        series = ft.Text("IN", color=base["cyan"])

        target = appearance_palette("netpulse", "magenta")
        recolor_tree(ft.Column([heading, chip, series]), base, target)
        apply_accent(target["accent"])

        self.assertEqual(plate.content.color, target["accent"])
        self.assertEqual(chip.color, base["cyan"])
        self.assertEqual(series.color, base["cyan"])

    def test_a_rendered_chip_matches_one_already_on_screen(self):
        """The bug: existing chips were repainted, later ones were not."""
        base = appearance_palette("netpulse", "cyan")
        chip = ft.Text("TCP", color=base["cyan"])
        target = appearance_palette("netpulse", "violet")

        recolor_tree(chip, base, target)
        set_active_palette(target)

        self.assertEqual(chip.color, proto_color("TCP"),
                         "two colours for one meaning on the same screen")


class RepaintCoverageTests(unittest.TestCase):
    """Only the mounted wrapper used to be recoloured; the rest kept the old palette."""

    def test_switching_theme_repaints_sections_that_were_never_mounted(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(config, "DEFAULT_SETTINGS_PATH", root / "settings.json"), \
                 patch.object(config, "DEFAULT_DATABASE_PATH", root / "netpulse.db"), \
                 patch.object(config, "DEFAULT_LOG_PATH", root / "netpulse.log"), \
                 patch.object(app_module, "DEFAULT_DATABASE_PATH", root / "netpulse.db"):
                config.save_appearance("netpulse", "cyan", "standard")
                page = FakePage()
                app_module.main(page)
                layout = page.controls[0]
                rail = find_rail(layout)
                default = appearance_palette("netpulse", "cyan")
                self.addCleanup(set_active_palette, default)
                self.addCleanup(apply_chart_palette, default)

                # Switch the theme while sitting on Overview.
                apply_button = None
                theme_dropdown = None
                rail.selected_index = 8
                rail.on_change(SimpleNamespace(control=rail))
                stack, seen = [layout], set()
                while stack:
                    node = stack.pop()
                    if id(node) in seen:
                        continue
                    seen.add(id(node))
                    if isinstance(node, ft.Button) and node.icon == ft.Icons.PALETTE_OUTLINED:
                        apply_button = node
                    if isinstance(node, ft.Dropdown) and node.label == "Visual theme":
                        theme_dropdown = node
                    for attr in CHILD_ATTRS:
                        child = getattr(node, attr, None)
                        if isinstance(child, (list, tuple)):
                            stack.extend(i for i in child if isinstance(i, ft.Control))
                        elif isinstance(child, ft.Control):
                            stack.append(child)
                self.assertIsNotNone(apply_button)
                theme_dropdown.value = "daylight"
                rail.selected_index = 0
                rail.on_change(SimpleNamespace(control=rail))
                apply_button.on_click(None)

                dark = appearance_palette("netpulse", "cyan")
                light = appearance_palette("daylight", "cyan")
                # Every section, including the seven that were never mounted at
                # the moment of the switch, must now be on the light palette.
                for index in range(len(VIEW_NAMES)):
                    rail.selected_index = index
                    rail.on_change(SimpleNamespace(control=rail))
                    found = []
                    collect(layout, parse(light["bg"]), found, set())
                    self.assertTrue(found)
                stale = set()
                stack, seen = [layout], set()
                while stack:
                    node = stack.pop()
                    if id(node) in seen:
                        continue
                    seen.add(id(node))
                    for attr in ("bgcolor", "color"):
                        value = getattr(node, attr, None)
                        if isinstance(value, str):
                            for role in PALETTE_ROLES:
                                if value.upper() == dark[role].upper():
                                    stale.add(f"{type(node).__name__}.{attr}={role}")
                    for attr in CHILD_ATTRS:
                        child = getattr(node, attr, None)
                        if isinstance(child, (list, tuple)):
                            stack.extend(i for i in child if isinstance(i, ft.Control))
                        elif isinstance(child, ft.Control):
                            stack.append(child)
                self.assertEqual(stale, set(),
                                 f"dark palette survived the switch: {sorted(stale)}")


if __name__ == "__main__":
    unittest.main()
