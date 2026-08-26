"""The light themes must repaint text, status colour and the canvases too.

A theme that only swaps backgrounds leaves the dark ink and neon status palette
in place, which renders the workspace unreadable on a bright surface. These
tests pin the contrast contract and the paths that keep charts in sync.
"""

import unittest

import flet as ft

from netpulse.config import LIGHT_THEMES, THEMES, is_light_theme
from netpulse.presentation import charts as charts_module
from netpulse.presentation.charts import (
    BarChartCanvas, LineChartCanvas, PieChartCanvas, SparklineCanvas,
    active_palette, apply_palette,
)
from netpulse.presentation.theme import (
    APPEARANCE_THEMES, CYAN, GREEN, PALETTE_ROLES, appearance_palette, make_theme,
    proto_color, recolor_tree, set_active_palette, theme_mode,
)


def _relative_luminance(color: str) -> float:
    value = color.lstrip("#")
    channels = []
    for index in (0, 2, 4):
        channel = int(value[index:index + 2], 16) / 255
        channels.append(
            channel / 12.92 if channel <= 0.03928
            else ((channel + 0.055) / 1.055) ** 2.4
        )
    red, green, blue = channels
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(foreground: str, background: str) -> float:
    light = _relative_luminance(foreground)
    dark = _relative_luminance(background)
    if light < dark:
        light, dark = dark, light
    return (light + 0.05) / (dark + 0.05)


class PaletteContractTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(set_active_palette, appearance_palette("netpulse", "cyan"))
        self.addCleanup(apply_palette, appearance_palette("netpulse", "cyan"))

    def test_every_theme_defines_every_role(self):
        for name in APPEARANCE_THEMES:
            palette = appearance_palette(name, "cyan")
            for role in PALETTE_ROLES + ("accent",):
                self.assertIn(role, palette, f"{name} is missing {role}")
                self.assertRegex(palette[role], r"^#[0-9A-Fa-f]{6}$",
                                 f"{name}.{role} is not a solid hex colour")

    def test_roles_stay_distinct_so_recoloring_cannot_collide(self):
        for name in APPEARANCE_THEMES:
            for accent in ("cyan", "blue", "green", "purple", "amber"):
                palette = appearance_palette(name, accent)
                values = [palette[role] for role in PALETTE_ROLES]
                self.assertEqual(len(values), len(set(values)),
                                 f"{name}/{accent} reuses a colour across roles")

    def test_config_and_theme_agree_on_which_themes_exist(self):
        self.assertEqual(set(THEMES), set(APPEARANCE_THEMES))
        self.assertEqual(
            set(LIGHT_THEMES),
            {name for name, theme in APPEARANCE_THEMES.items() if theme["light"]},
        )
        for name in LIGHT_THEMES:
            self.assertTrue(is_light_theme(name))
        self.assertFalse(is_light_theme("netpulse"))

    def test_light_themes_keep_readable_text_contrast(self):
        for name in LIGHT_THEMES:
            palette = appearance_palette(name, "cyan")
            for surface in ("bg", "surface", "card"):
                self.assertGreaterEqual(
                    _contrast(palette["text"], palette[surface]), 7.0,
                    f"{name}: body text on {surface} fails AAA",
                )
                self.assertGreaterEqual(
                    _contrast(palette["dim"], palette[surface]), 4.5,
                    f"{name}: dim text on {surface} fails AA",
                )
                self.assertGreaterEqual(
                    _contrast(palette["muted"], palette[surface]), 3.0,
                    f"{name}: muted text on {surface} fails large-text AA",
                )

    def test_light_themes_keep_readable_status_colours(self):
        for name in LIGHT_THEMES:
            palette = appearance_palette(name, "cyan")
            for role in ("cyan", "green", "red", "amber", "purple", "blue"):
                self.assertGreaterEqual(
                    _contrast(palette[role], palette["card"]), 3.0,
                    f"{name}: {role} is not legible on a card",
                )

    def test_dark_themes_keep_readable_text_contrast(self):
        dark = [name for name, theme in APPEARANCE_THEMES.items() if not theme["light"]]
        for name in dark:
            palette = appearance_palette(name, "cyan")
            self.assertGreaterEqual(
                _contrast(palette["text"], palette["card"]), 7.0, name,
            )

    def test_theme_mode_follows_the_palette(self):
        self.assertEqual(theme_mode(appearance_palette("daylight", "cyan")),
                         ft.ThemeMode.LIGHT)
        self.assertEqual(theme_mode(appearance_palette("netpulse", "cyan")),
                         ft.ThemeMode.DARK)
        self.assertEqual(theme_mode(None), ft.ThemeMode.DARK)

    def test_button_labels_flip_on_light_themes(self):
        light = make_theme(palette=appearance_palette("daylight", "cyan"))
        dark = make_theme(palette=appearance_palette("netpulse", "cyan"))
        self.assertEqual(light.color_scheme.on_primary, "#FFFFFF")
        self.assertEqual(dark.color_scheme.on_primary, "#000000")
        self.assertEqual(light.color_scheme.on_surface,
                         appearance_palette("daylight", "cyan")["text"])

    def test_protocol_colours_follow_the_active_palette(self):
        set_active_palette(appearance_palette("netpulse", "cyan"))
        self.assertEqual(proto_color("TCP"), CYAN)
        light = appearance_palette("daylight", "cyan")
        set_active_palette(light)
        self.assertEqual(proto_color("TCP"), light["cyan"])
        self.assertEqual(proto_color("DNS"), light["green"])
        self.assertEqual(proto_color("OTHER"), light["muted"])
        self.assertEqual(proto_color("UNKNOWN"), light["muted"])


class RecolorTreeTests(unittest.TestCase):
    def test_text_and_status_colours_are_swapped(self):
        dark = appearance_palette("netpulse", "cyan")
        light = appearance_palette("daylight", "cyan")
        tree = ft.Column([
            ft.Container(
                bgcolor=dark["card"],
                border=ft.Border.all(1, dark["border"]),
                content=ft.Text("hello", color=dark["text"]),
            ),
            ft.Text("muted", color=dark["muted"]),
            ft.Icon(ft.Icons.WARNING, color=dark["red"]),
        ])

        recolor_tree(tree, dark, light)

        container = tree.controls[0]
        self.assertEqual(container.bgcolor, light["card"])
        self.assertEqual(container.content.color, light["text"])
        self.assertEqual(tree.controls[1].color, light["muted"])
        self.assertEqual(tree.controls[2].color, light["red"])

    def test_translucent_colours_keep_their_alpha_channel(self):
        dark = appearance_palette("netpulse", "cyan")
        light = appearance_palette("daylight", "cyan")
        translucent = "#33" + dark["cyan"].lstrip("#")
        control = ft.Container(bgcolor=translucent)

        recolor_tree(control, dark, light)

        self.assertEqual(control.bgcolor.upper(),
                         ("#33" + light["cyan"].lstrip("#")).upper())

    def test_recoloring_back_and_forth_is_lossless(self):
        dark = appearance_palette("netpulse", "cyan")
        light = appearance_palette("paper", "cyan")
        control = ft.Container(bgcolor=dark["card"],
                               content=ft.Text("x", color=dark["dim"]))

        recolor_tree(control, dark, light)
        recolor_tree(control, light, dark)

        self.assertEqual(control.bgcolor, dark["card"])
        self.assertEqual(control.content.color, dark["dim"])


class ChartPaletteTests(unittest.TestCase):
    def setUp(self):
        self.dark = appearance_palette("netpulse", "cyan")
        self.light = appearance_palette("daylight", "cyan")
        # The chart palette is process-wide state; pin a known baseline instead
        # of inheriting whatever the previous test class left behind.
        apply_palette(self.dark)
        self.addCleanup(apply_palette, self.dark)

    def test_apply_palette_moves_canvas_chrome(self):
        apply_palette(self.light)
        palette = active_palette()
        self.assertEqual(palette["border"], self.light["border"])
        self.assertEqual(palette["muted"], self.light["muted"])
        self.assertEqual(palette["card"], self.light["card"])

    def test_apply_palette_ignores_missing_roles(self):
        apply_palette({"border": self.light["border"]})
        self.assertEqual(active_palette()["border"], self.light["border"])
        self.assertEqual(active_palette()["muted"], self.dark["muted"])

    def test_every_canvas_exposes_recolor(self):
        mapping = {self.dark[role].upper(): self.light[role]
                   for role in PALETTE_ROLES}

        line = LineChartCanvas(CYAN, GREEN)
        line.recolor(mapping)
        self.assertEqual(line._color_a, self.light["cyan"])
        self.assertEqual(line._color_b, self.light["green"])

        spark = SparklineCanvas(CYAN)
        spark.recolor(mapping)
        self.assertEqual(spark._color, self.light["cyan"])

        bar = BarChartCanvas(["TCP", "UDP"], [CYAN, GREEN])
        bar.recolor(mapping)
        self.assertEqual(bar._colors, [self.light["cyan"], self.light["green"]])

        pie = PieChartCanvas()
        pie.update_data([("TCP", 3.0, CYAN)])
        pie.recolor(mapping)
        self.assertEqual(pie._sections[0][2], self.light["cyan"])

    def test_recolor_leaves_unknown_colours_untouched(self):
        line = LineChartCanvas("#123456", GREEN)
        line.recolor({self.dark["green"].upper(): self.light["green"]})
        self.assertEqual(line._color_a, "#123456")
        self.assertEqual(line._color_b, self.light["green"])

    def test_shapes_are_rebuilt_after_recoloring(self):
        chart = LineChartCanvas(CYAN, GREEN)
        chart.update_data([1.0] * 60, [2.0] * 60)
        before = list(chart._canvas.shapes)
        chart.recolor({self.dark["cyan"].upper(): self.light["cyan"]})
        self.assertIsNot(chart._canvas.shapes, before)
        self.assertTrue(chart._canvas.shapes)

    def test_canvas_chrome_reads_the_active_palette_at_draw_time(self):
        apply_palette(self.light)
        chart = LineChartCanvas(CYAN, GREEN)
        chart.update_data([1.0] * 60, [2.0] * 60)
        self.assertIn(charts_module.active_palette()["muted"], repr(chart._canvas.shapes))


if __name__ == "__main__":
    unittest.main()
