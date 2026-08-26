"""Regressions for the interactive network map.

Three defects lived here at once and all three were invisible to the existing
suite: the module was never rebound to a new appearance palette, so a map
redrawn after a theme change came back in the dark preset; half its strings
were literal Spanish and the other half untranslated English; and its fixed
two-ring layout put device labels on top of each other from nine devices on.
"""

import ast
import pathlib
import re
import unittest
import flet as ft

from netpulse.domain.network_scan import ScanHost, ScanService
from netpulse.domain.topology import TopologyNode, TopologySegment
from netpulse.presentation import topology_map as tmap
from netpulse.presentation.i18n import ES
from netpulse.presentation.theme import (
    PALETTE_CONSTANTS, PALETTE_CONSUMERS, appearance_palette, set_active_palette,
)

MODULE = "netpulse.presentation.topology_map"
SOURCE = pathlib.Path(tmap.__file__).read_text(encoding="utf-8")


def build_map(count: int) -> tmap.NetworkTopologyMap:
    nodes = [
        TopologyNode(f"10.0.0.{index + 1}", f"device-{index:02d}",
                     "router" if index == 0 else "device", "low", "new")
        for index in range(count)
    ]
    hosts = {
        node.address: ScanHost(
            address=node.address,
            services=[ScanService(443, "tcp", "open", "https")],
        )
        for node in nodes
    }
    noop = lambda *args, **kwargs: None            # noqa: E731
    return tmap.NetworkTopologyMap([TopologySegment("10.0.0.0/24", nodes)], hosts,
                                   on_select=noop, on_edit=noop, on_explain=noop)


class LayoutTests(unittest.TestCase):
    def test_compact_rebuild_uses_a_real_column_without_expanded_children(self):
        view = build_map(21)
        view.resize(620.0)

        view.select("10.0.0.2")
        layout = view.control.controls[1]
        self.assertIsInstance(layout, ft.Column)
        self.assertTrue(all(not control.expand for control in layout.controls))
        self.assertEqual([control.width for control in layout.controls], [620.0, 620.0])
        self.assertIsNotNone(view._map_frame.bgcolor)

    def test_compact_map_projects_every_node_inside_the_native_stack(self):
        view = build_map(21)
        view.resize(680.0)
        scale, offset_x, offset_y, frame_width = view._display_geometry()
        for device in view._devices:
            left = offset_x + device.x * scale - tmap.NODE_WIDTH * scale / 2
            top = offset_y + device.y * scale - tmap.NODE_TOP * scale
            self.assertGreaterEqual(left, 0)
            self.assertGreaterEqual(top, 0)
            self.assertLessEqual(left + tmap.NODE_WIDTH * scale, frame_width)
            self.assertLessEqual(top + tmap.NODE_HEIGHT * scale, tmap.PANEL_HEIGHT)

    def test_map_uses_native_controls_instead_of_the_grey_desktop_canvas(self):
        view = build_map(5)
        background = view._map_stack.controls[0]

        self.assertIsInstance(background, ft.Container)
        self.assertEqual(background.bgcolor, tmap.BG)
        self.assertFalse(any(type(control).__name__ == "Canvas"
                             for control in view._map_stack.controls))
        self.assertGreater(len(view._map_stack.controls), len(view._devices))

    def test_device_labels_never_overlap(self):
        """No two node boxes may share screen space, at any scan size.

        The old layout used two fixed rings inside a fixed 920x500 canvas. From
        nine devices upwards the 124x126 boxes intersected, so hostnames were
        painted over neighbouring icons and, past a dozen devices, over other
        hostnames.
        """
        for count in list(range(1, 41)) + [60, 100, 254]:
            offsets = tmap.NetworkTopologyMap.satellite_offsets(count)
            self.assertEqual(len(offsets), count, f"{count} devices lost a node")
            self.assertFalse(
                tmap.NetworkTopologyMap._collides(offsets),
                f"node boxes overlap with {count} devices",
            )

    def test_a_small_scan_is_shown_at_full_size(self):
        for count in (3, 5, 8, 10, 12):
            view = build_map(count)
            view.resize(1665.0)
            self.assertGreaterEqual(
                view.zoom, .95,
                f"{count} devices had to shrink to {view.zoom:.2f}")

    def test_a_typical_subnet_stays_legible(self):
        """Up to a couple of dozen devices the labels must still be readable."""
        for count in range(13, 27):
            view = build_map(count)
            view.resize(1665.0)
            self.assertGreaterEqual(
                view.zoom, .6,
                f"{count} devices shrank to {view.zoom:.2f}")

    def test_a_dense_scan_shrinks_instead_of_hiding_devices(self):
        view = build_map(30)
        view.resize(1665.0)
        self.assertLess(view.zoom, 1.0)
        self.assertGreaterEqual(view.zoom, tmap.MIN_FIT_ZOOM)

    def test_zooming_by_hand_survives_a_window_resize(self):
        view = build_map(6)
        view.resize(1665.0)
        view._zoom(.15)
        chosen = view.zoom
        view.resize(1200.0)
        self.assertEqual(view.zoom, chosen)

    def test_the_canvas_covers_every_node_box(self):
        for count in (3, 12, 24):
            view = build_map(count)
            for device in view._devices:
                self.assertGreaterEqual(device.x - tmap.NODE_WIDTH / 2, 0)
                self.assertGreaterEqual(device.y - tmap.NODE_TOP, 0)
                self.assertLessEqual(device.x + tmap.NODE_WIDTH / 2,
                                     view.canvas_width)
                self.assertLessEqual(device.y + tmap.NODE_BOTTOM,
                                     view.canvas_height)


class ThemeTests(unittest.TestCase):
    def test_the_map_follows_a_theme_change(self):
        """The map rebuilds itself, so its colour names have to be rebound.

        ``recolor_tree`` can only reach controls that already exist. Selecting a
        node or changing the protocol filter rebuilds the whole surface from the
        module constants, and those were frozen at the dark preset because the
        module was missing from ``PALETTE_CONSUMERS``.
        """
        self.assertIn(MODULE, PALETTE_CONSUMERS)
        dark = appearance_palette("netpulse", "cyan")
        light = appearance_palette("daylight", "blue")
        try:
            set_active_palette(light)
            for constant, role in PALETTE_CONSTANTS.items():
                self.assertEqual(getattr(tmap, constant), light[role], constant)
        finally:
            set_active_palette(dark)

    def test_no_colour_literal_is_hardcoded(self):
        literals = re.findall(r"[\"'](#[0-9A-Fa-f]{3,8})[\"']", SOURCE)
        self.assertEqual(literals, [],
                         "the map must take its colours from the palette")


class LanguageTests(unittest.TestCase):
    def test_every_translated_string_has_a_spanish_entry(self):
        missing = sorted({
            node.args[0].value
            for node in ast.walk(ast.parse(SOURCE))
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", "") == "tr"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and node.args[0].value not in ES
        })
        self.assertEqual(missing, [], f"untranslated map strings: {missing}")

    def test_no_literal_spanish_reaches_a_control(self):
        """Source strings are English; the catalog is what makes them Spanish."""
        spanish = {"Vista", "Activo", "Riesgo", "Origen", "Destino", "Estado",
                   "Servicio", "Abierto", "Puerto", "Protocolo"}
        for node in ast.walk(ast.parse(SOURCE)):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", "") not in {"Text", "Button"}:
                continue
            for value in list(node.args) + [kw.value for kw in node.keywords]:
                if isinstance(value, ast.Constant) and value.value in spanish:
                    self.fail(f"{value.value!r} is a translation, "
                              f"not a source string")


if __name__ == "__main__":
    unittest.main()
