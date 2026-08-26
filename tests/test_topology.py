from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import flet as ft
import flet.canvas as cv

from netpulse.domain.network_scan import NetworkScan, ScanHost
from netpulse.domain.topology import build_topology
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import NmapScanner
from netpulse.presentation.views import NetworkView
from netpulse.presentation.theme import appearance_palette, recolor_tree
from netpulse.presentation.topology_map import MIN_FIT_ZOOM


class TopologyTests(unittest.TestCase):
    def test_network_map_uses_available_width_at_scaled_desktop_size(self):
        content_width = 1370.0
        available = content_width - 48.0
        card_width = NetworkView._topology_card_width(content_width)
        columns = round((available + 8.0) / (card_width + 8.0))

        # Regression for 125–150% Windows scaling: six columns left a visible
        # empty strip although a seventh readable card fitted in the panel.
        self.assertEqual(columns, 7)
        self.assertGreaterEqual(card_width, 180.0)
        self.assertAlmostEqual(
            columns * card_width + (columns - 1) * 8.0,
            available,
        )

    def test_network_view_uses_interactive_radial_map_for_rendered_nodes(self):
        with TemporaryDirectory() as directory:
            view = NetworkView(
                DB(Path(directory) / "topology.db"), NmapScanner(), [None]
            )
            view.build()
            now = datetime(2026, 1, 1)
            scan = NetworkScan(
                "172.26.4.0/24", "quick", "nmap", now, now, 14,
                hosts=[ScanHost(f"172.26.4.{index}") for index in range(1, 15)],
            )

            view._render_topology(scan)

            topology = view._interactive_topology
            self.assertIsNotNone(topology)
            self.assertEqual(len(topology._devices), 14)
            self.assertIsInstance(topology.control, ft.Column)
            self.assertIsInstance(topology.control.controls[1], ft.Row)

    def test_protocol_filter_and_node_selection_update_the_map(self):
        with TemporaryDirectory() as directory:
            view = NetworkView(DB(Path(directory) / "topology.db"), NmapScanner(), [None])
            view.build()
            now = datetime(2026, 1, 1)
            from netpulse.domain.network_scan import ScanService
            scan = NetworkScan(
                "192.168.1.0/24", "quick", "nmap", now, now, 2,
                hosts=[
                    ScanHost("192.168.1.1"),
                    ScanHost("192.168.1.10", services=[
                        ScanService(443, "tcp", "open", "https")]),
                    ScanHost("192.168.1.20", services=[
                        ScanService(53, "udp", "open", "dns")]),
                ],
            )
            view._render_topology(scan)
            topology = view._interactive_topology

            topology.set_protocol("UDP")
            self.assertEqual([d.node.address for d in topology._visible_devices()],
                             ["192.168.1.20"])
            topology.select("192.168.1.20")
            self.assertEqual(topology.selected_address, "192.168.1.20")
            selected = next(device for device in topology._devices
                            if device.node.address == "192.168.1.20")
            selected_control = topology._node_control(selected)
            self.assertIsNotNone(selected_control.bgcolor)
            self.assertIsNotNone(selected_control.border)
            self.assertTrue(selected_control.content.controls[1].visible)
            topology._zoom(10)
            self.assertEqual(topology.zoom, 1.65)
            topology._zoom(-10)
            # The floor is the same one the automatic fit uses: a dense scan
            # has to be visible whole before it has to be readable.
            self.assertEqual(topology.zoom, MIN_FIT_ZOOM)
            self.assertEqual(topology._table.scroll, ft.ScrollMode.ALWAYS)
            self.assertEqual(topology._table.height, 184)

    def test_groups_nodes_by_segment_and_assigns_roles_and_aliases(self):
        now = datetime(2026, 1, 1)
        scan = NetworkScan(
            "172.26.3.0/24, 172.26.4.0/24", "discovery", "nmap", now, now, 1,
            hosts=[
                ScanHost("172.26.4.20", risk_level="medium"),
                ScanHost("172.26.3.10"),
                ScanHost("172.26.3.1"),
            ],
        )
        inventory = [{"address": "172.26.4.20", "alias": "Servidor",
                      "trust_status": "authorized"}]

        topology = build_topology(scan, inventory, {"172.26.3.10"})

        self.assertEqual([item.network for item in topology],
                         ["172.26.3.0/24", "172.26.4.0/24"])
        self.assertEqual(topology[0].nodes[0].role, "router")
        self.assertEqual(topology[0].nodes[1].role, "local")
        self.assertEqual(topology[1].nodes[0].label, "Servidor")
        self.assertEqual(topology[1].nodes[0].trust_status, "authorized")

    def test_canvas_connections_follow_light_and_dark_themes(self):
        dark = appearance_palette("netpulse", "cyan")
        light = appearance_palette("daylight", "cyan")
        canvas = cv.Canvas(shapes=[
            cv.Rect(0, 0, 20, 20, paint=ft.Paint(color=dark["bg"])),
            cv.Line(0, 0, 20, 20, paint=ft.Paint(color=dark["cyan"])),
        ])

        recolor_tree(canvas, dark, light)

        self.assertEqual(canvas.shapes[0].paint.color, light["bg"])
        self.assertEqual(canvas.shapes[1].paint.color, light["cyan"])


if __name__ == "__main__":
    unittest.main()
