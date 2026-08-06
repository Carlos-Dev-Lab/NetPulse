from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import flet as ft

from netpulse.domain.network_scan import NetworkScan, ScanHost
from netpulse.domain.topology import build_topology
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import NmapScanner
from netpulse.presentation.views import NetworkView


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

    def test_network_view_uses_native_responsive_grid_for_rendered_nodes(self):
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

            self.assertEqual(len(view._topology_grids), 1)
            grid, node_count = view._topology_grids[0]
            self.assertIsInstance(grid, ft.GridView)
            self.assertEqual(node_count, 14)
            self.assertEqual(grid.max_extent, 210)
            self.assertTrue(all(node.width is None for node in grid.controls))

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


if __name__ == "__main__":
    unittest.main()
