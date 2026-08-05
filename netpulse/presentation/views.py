"""Flet views for dashboards, packets, history, processes and settings."""

import asyncio
import csv
import io
import threading
from datetime import datetime
from typing import Dict

import flet as ft

from netpulse.domain.state import AppState
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import (
    NmapCancelledError,
    NmapScanner,
    SCAN_PROFILES,
    compare_scans,
)
from netpulse.infrastructure.sniffer import list_interfaces
from netpulse.services.ip_info import geo_cache
from .charts import BarChartCanvas, LineChartCanvas, PieChartCanvas, SparklineCanvas
from .i18n import get_language, tr, translate_tree
from .theme import (
    AMBER, BLUE, BORDER, CARD, CYAN, DIM, GREEN, MUTED, PROTO_COLORS,
    PROTO_LIST, PURPLE, RED, SURFACE, TEXT, badge, card, proto_color,
    section_title, tint, view_heading,
)

class DashboardView:
    def __init__(self, state: AppState):
        self.s = state
        # stat refs — network
        self.r_pkts  = ft.Ref[ft.Text]()
        self.r_pps   = ft.Ref[ft.Text]()
        self.r_bin   = ft.Ref[ft.Text]()
        self.r_kbin  = ft.Ref[ft.Text]()
        self.r_bout  = ft.Ref[ft.Text]()
        self.r_kbout = ft.Ref[ft.Text]()
        self.r_peak  = ft.Ref[ft.Text]()
        # stat refs — system
        self.r_cpu   = ft.Ref[ft.Text]()
        self.r_ram   = ft.Ref[ft.Text]()
        self.r_ram_sub = ft.Ref[ft.Text]()
        # dynamic cols
        self.r_ips  = ft.Ref[ft.Column]()
        self.r_feed = ft.Ref[ft.Column]()
        # custom charts
        self.line_chart = LineChartCanvas(CYAN, GREEN, "IN", "OUT", 60, 180)
        self.pie_chart  = PieChartCanvas()
        # system sparklines
        self.spark_cpu = SparklineCanvas(AMBER, 30)
        self.spark_ram = SparklineCanvas(PURPLE, 30)
        self._metric_cards = []
        self._system_cards = []
        self._chart_cards = []
        self._detail_cards = []
        self._responsive_rows = []
        self._layout_mode = None

    def _tile(self, title, ref_val, ref_sub, icon, color):
        return card(
            ft.Column([
                ft.Row([
                    ft.Container(ft.Icon(icon, color=color, size=24),
                                 bgcolor=tint(color, .13), border_radius=14, padding=14),
                    ft.Column([
                        ft.Text(title, size=10, color=DIM, weight=ft.FontWeight.W_600),
                        ft.Text(ref=ref_val, value="0", size=26, color=color,
                                weight=ft.FontWeight.BOLD, font_family="monospace"),
                    ], spacing=2),
                ], spacing=12),
                ft.Text(ref=ref_sub, value="", size=11, color=MUTED),
            ], spacing=8),
            glow=color,
        )

    def _sys_tile(self, title, ref_val, ref_bar, ref_sub, spark_widget, color, icon):
        """Tile for CPU/RAM with mini progress bar and sparkline."""
        return card(
            ft.Column([
                ft.Row([
                    ft.Container(ft.Icon(icon, color=color, size=24),
                                 bgcolor=tint(color, .13), border_radius=14, padding=14),
                    ft.Column([
                        ft.Text(title, size=10, color=DIM, weight=ft.FontWeight.W_600),
                        ft.Text(ref=ref_val, value="0 %", size=22, color=color,
                                weight=ft.FontWeight.BOLD, font_family="monospace"),
                    ], spacing=2),
                    ft.Container(expand=True),
                    spark_widget,
                ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.ProgressBar(ref=ref_bar, value=0, color=color,
                               bgcolor=tint(color, .13), height=4, border_radius=2),
                ft.Text(ref=ref_sub, value="", size=10, color=MUTED),
            ], spacing=6),
            glow=color,
        )

    def build(self):
        # Extra refs for progress bars inside sys tiles
        self.r_cpu_bar = ft.Ref[ft.ProgressBar]()
        self.r_ram_bar = ft.Ref[ft.ProgressBar]()

        metric_row = ft.Row([
                self._tile("TOTAL PACKETS", self.r_pkts, self.r_pps,
                           ft.Icons.HUB_ROUNDED, CYAN),
                self._tile("MB RECEIVED ↓", self.r_bin, self.r_kbin,
                           ft.Icons.DOWNLOAD_ROUNDED, CYAN),
                self._tile("MB SENT ↑",     self.r_bout, self.r_kbout,
                           ft.Icons.UPLOAD_ROUNDED, GREEN),
                card(ft.Column([
                    ft.Row([
                        ft.Container(ft.Icon(ft.Icons.TRENDING_UP_ROUNDED, color=AMBER, size=24),
                                     bgcolor=tint(AMBER, .13), border_radius=14, padding=14),
                        ft.Column([
                            ft.Text("PEAK BW", size=10, color=DIM, weight=ft.FontWeight.W_600),
                            ft.Text(ref=self.r_peak, value="0 KB/s", size=18, color=AMBER,
                                    weight=ft.FontWeight.BOLD, font_family="monospace"),
                        ], spacing=2),
                    ], spacing=12),
                    ft.Text("↓ in  /  ↑ out peak", size=11, color=MUTED),
                ], spacing=8), glow=AMBER),
            ], spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START)
        self._metric_cards = metric_row.controls

        system_row = ft.Row([
                self._sys_tile("CPU USAGE", self.r_cpu, self.r_cpu_bar,
                               ft.Ref[ft.Text](), self.spark_cpu.widget,
                               AMBER, ft.Icons.MEMORY_ROUNDED),
                self._sys_tile("RAM USAGE", self.r_ram, self.r_ram_bar,
                               self.r_ram_sub, self.spark_ram.widget,
                               PURPLE, ft.Icons.STORAGE_ROUNDED),
            ], spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START)
        self._system_cards = system_row.controls

        chart_row = ft.Row([
                card(ft.Column([
                    ft.Row([
                        section_title("LIVE TRAFFIC  ( KB/s )"),
                        ft.Container(expand=True),
                        ft.Row([
                            ft.Container(width=9, height=9, bgcolor=CYAN,  border_radius=3),
                            ft.Text("IN",  size=10, color=DIM),
                            ft.Container(width=9, height=9, bgcolor=GREEN, border_radius=3),
                            ft.Text("OUT", size=10, color=DIM),
                        ], spacing=5),
                    ]),
                    self.line_chart.widget,
                ], spacing=12, expand=True)),

                card(ft.Column([
                    section_title("PROTOCOL MIX"),
                    ft.Container(
                        content=ft.Row([self.pie_chart.widget],
                                       alignment=ft.MainAxisAlignment.CENTER),
                        expand=True,
                    ),
                ], spacing=12, expand=True)),
            ], spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START)
        self._chart_cards = chart_row.controls

        detail_row = ft.Row([
                card(ft.Column([
                    section_title("🌐  TOP CONNECTIONS"),
                    ft.Divider(color=BORDER, height=6),
                    ft.Column(ref=self.r_ips, spacing=6,
                              controls=[ft.Text("Waiting...", color=MUTED, size=12)]),
                ], spacing=10, expand=True)),

                card(ft.Column([
                    section_title("⚡  LIVE PACKET FEED"),
                    ft.Divider(color=BORDER, height=6),
                    ft.Column(ref=self.r_feed, spacing=4,
                              controls=[ft.Text("Waiting for packets...", color=MUTED, size=12)]),
                ], spacing=10, expand=True)),
            ], spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START)
        self._detail_cards = detail_row.controls
        self._responsive_rows = [metric_row, system_row, chart_row, detail_row]

        return ft.Column([
            view_heading("Network overview", "Live traffic, system health and active connections",
                         ft.Icons.SPACE_DASHBOARD_ROUNDED, CYAN),
            metric_row,
            system_row,
            chart_row,
            detail_row,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        """Reflow using the central viewport measured by Flutter Desktop."""
        content_width = max(280.0, width - 28.0)
        content_height = max(420.0, height - 28.0)
        # Two metric columns remain readable down to a 900 px physical window
        # at common Windows DPI settings; a single column wastes height and
        # makes the dashboard appear overflowed.
        mode = "wide" if content_width >= 820 else "compact" if content_width >= 380 else "narrow"
        layout_key = (mode, round(content_width), round(content_height))
        if layout_key == self._layout_mode or not self._metric_cards:
            return
        self._layout_mode = layout_key
        for row in self._responsive_rows:
            row.width = content_width

        metric_count = 4 if mode == "wide" else 2 if mode == "compact" else 1
        metric_width = (content_width - 12 * (metric_count - 1)) / metric_count
        for control in self._metric_cards:
            control.width = metric_width

        system_count = 2 if mode != "narrow" else 1
        system_width = (content_width - 12 * (system_count - 1)) / system_count
        for control in self._system_cards:
            control.width = system_width
        if mode == "wide":
            self._chart_cards[0].width = content_width * 0.62 - 6
            self._chart_cards[1].width = content_width * 0.38 - 6
            detail_width = (content_width - 12) / 2
        else:
            self._chart_cards[0].width = self._chart_cards[1].width = content_width
            detail_width = content_width
        for control in self._detail_cards:
            control.width = detail_width

        # Use the vertical room left after metrics, system cards, section
        # headings and the detail row. This keeps fullscreen layouts from
        # collapsing into the upper half while preserving a compact canvas in
        # short windows.
        chart_height = max(145.0, min(360.0, content_height - 410.0))
        chart_card_height = chart_height + 58.0
        for control in self._chart_cards:
            control.height = chart_card_height
        line_width = max(240.0, self._chart_cards[0].width - 28.0)
        pie_size = min(220.0, chart_height, self._chart_cards[1].width - 28.0)
        self.line_chart.resize(line_width, chart_height)
        self.pie_chart.resize(pie_size)

    def refresh(self):
        s = self.s
        if not self.r_pkts.current:
            return

        self.r_pkts.current.value  = f"{s.total_pkts:,}"
        self.r_pps.current.value   = f"↕ {s.cur_pps:.0f} pkt/s"
        self.r_bin.current.value   = f"{s.bytes_in  / 1_048_576:.2f}"
        self.r_kbin.current.value  = f"↓ {s.cur_kbps_in:.1f} KB/s"
        self.r_bout.current.value  = f"{s.bytes_out / 1_048_576:.2f}"
        self.r_kbout.current.value = f"↑ {s.cur_kbps_out:.1f} KB/s"
        if self.r_peak.current:
            self.r_peak.current.value = (
                f"↓ {s.peak_kbps_in:.0f}  ↑ {s.peak_kbps_out:.0f} KB/s"
            )

        # Line chart
        self.line_chart.update_data(list(s.hist_in), list(s.hist_out))

        # Pie chart
        if s.proto:
            total = sum(s.proto.values()) or 1
            secs = sorted(s.proto.items(), key=lambda x: -x[1])[:6]
            self.pie_chart.update_data(
                [(pr, cnt / total * 100, proto_color(pr)) for pr, cnt in secs]
            )

        # Top IPs
        if self.r_ips.current:
            top = sorted(s.top_ips.items(), key=lambda x: -x[1]["b"])[:5]
            if top:
                mx = top[0][1]["b"] or 1
                rows = []
                for ip, d in top:
                    label = geo_cache.get_label(ip)
                    details = [
                        ft.Row([
                            ft.Text(ip, size=11, color=TEXT, font_family="monospace",
                                    no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS,
                                    expand=True),
                            ft.Text(f"{d['b']/1024:.1f} KB", size=10, color=CYAN),
                            ft.Text(f"{d['p']} pkt", size=10, color=MUTED),
                        ]),
                    ]
                    if label:
                        details.append(ft.Text(
                            label, size=9, color=PURPLE, italic=True,
                            no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS,
                        ))
                    details.append(
                        ft.ProgressBar(value=d["b"] / mx, color=CYAN,
                                       bgcolor=BORDER, height=3, border_radius=2)
                    )
                    rows.append(ft.Container(
                        content=ft.Column(details, spacing=3),
                        padding=ft.padding.Padding.symmetric(horizontal=4, vertical=2),
                    ))
                self.r_ips.current.controls = rows

        # Packet feed
        if self.r_feed.current:
            rows = []
            for pkt in reversed(list(s.live)[-14:]):
                c = CYAN if pkt.direction == "IN" else GREEN
                rows.append(ft.Container(
                    content=ft.Row([
                        badge(pkt.protocol, proto_color(pkt.protocol)),
                        ft.Icon(
                            ft.Icons.SOUTH_ROUNDED if pkt.direction == "IN"
                            else ft.Icons.NORTH_ROUNDED, color=c, size=12),
                        ft.Text(f"{pkt.src}  →  {pkt.dst}", size=10, color=DIM,
                                expand=True, no_wrap=True,
                                overflow=ft.TextOverflow.ELLIPSIS),
                        ft.Text(f"{pkt.size}B", size=10, color=MUTED),
                    ], spacing=6),
                    padding=ft.padding.Padding.symmetric(horizontal=8, vertical=5),
                    bgcolor=tint(c, .07), border_radius=6,
                    border=ft.Border.all(1, tint(c, .16)),
                ))
            self.r_feed.current.controls = rows

        # System metrics — CPU
        if self.r_cpu.current:
            cpu = s.sys_cpu
            self.r_cpu.current.value = f"{cpu:.0f} %"
            if hasattr(self, "r_cpu_bar") and self.r_cpu_bar.current:
                self.r_cpu_bar.current.value = cpu / 100
            self.spark_cpu.update_data(list(s.spark_cpu))

        # System metrics — RAM
        if self.r_ram.current:
            ram = s.sys_ram
            self.r_ram.current.value = f"{ram:.0f} %"
            if hasattr(self, "r_ram_bar") and self.r_ram_bar.current:
                self.r_ram_bar.current.value = ram / 100
            if self.r_ram_sub.current:
                try:
                    import psutil as _ps
                    vm = _ps.virtual_memory()
                    used_gb = vm.used / 1_073_741_824
                    total_gb = vm.total / 1_073_741_824
                    self.r_ram_sub.current.value = f"{used_gb:.1f} / {total_gb:.1f} GB"
                except Exception:
                    pass
            self.spark_ram.update_data(list(s.spark_ram))


# ── 2. ACTIVE NETWORK DISCOVERY ────────────────────────────────────────

class NetworkView:
    """Active Nmap discovery, risk overview and scan history."""

    def __init__(self, db: DB, scanner: NmapScanner, page_ref):
        self.db = db
        self.scanner = scanner
        self._page = page_ref
        self.r_target = ft.Ref[ft.TextField]()
        self.r_profile = ft.Ref[ft.Dropdown]()
        self.r_scan = ft.Ref[ft.Button]()
        self.r_progress = ft.Ref[ft.ProgressRing]()
        self.r_status = ft.Ref[ft.Text]()
        self.r_devices = ft.Ref[ft.Text]()
        self.r_ports = ft.Ref[ft.Text]()
        self.r_risk = ft.Ref[ft.Text]()
        self.r_changes = ft.Ref[ft.Text]()
        self.r_device_list = ft.Ref[ft.Column]()
        self.r_alert_list = ft.Ref[ft.Column]()
        self.r_history = ft.Ref[ft.Dropdown]()
        self.r_metadata = ft.Ref[ft.Text]()
        self._running = False
        self._scan_row = None
        self._summary_row = None
        self._summary_cards = []
        self._content_row = None
        self._content_cards = []
        self._scan_card = None
        self._history_card = None
        self._layout_key = None
        self._disposed = False
        self._cancel_event = threading.Event()

    @staticmethod
    def _risk_color(level: str) -> str:
        return RED if level == "high" else AMBER if level == "medium" else GREEN

    def build(self):
        def on_scan(e):
            if not self._running:
                self._page[0].run_task(self._run_scan)

        def on_history(e):
            if e.control.value:
                scan = self.db.get_network_scan(int(e.control.value))
                if scan:
                    self._render_scan(scan)

        def summary(label, ref, color, icon):
            return card(
                ft.Row([
                    ft.Container(
                        ft.Icon(icon, color=color, size=28),
                        bgcolor=tint(color, .09),
                        border_radius=14,
                        padding=10,
                    ),
                    ft.Column([
                        ft.Text(label, size=10, color=DIM,
                                weight=ft.FontWeight.W_600),
                        ft.Text(ref=ref, value="0", size=24, color=color,
                                weight=ft.FontWeight.BOLD, font_family="monospace"),
                    ], spacing=2),
                ], spacing=10),
                glow=color, padding=14,
            )

        profile_options = [
            ft.DropdownOption(key=key, text=value["label"])
            for key, value in SCAN_PROFILES.items()
        ]
        self._scan_row = ft.Row([
            ft.TextField(
                ref=self.r_target, label="Target networks",
                value=self.scanner.default_target(), width=300,
                hint_text="172.26.4.0/24, 172.26.3.0/24", bgcolor=SURFACE, color=TEXT,
                border_color=BORDER, focused_border_color=CYAN,
                prefix_icon=ft.Icons.ROUTER_ROUNDED, text_size=12,
                multiline=True, min_lines=1, max_lines=3,
            ),
            ft.Dropdown(
                ref=self.r_profile, label="Scan method", value="quick",
                options=profile_options, width=180, bgcolor=SURFACE,
                color=TEXT, border_color=BORDER,
                focused_border_color=CYAN, text_size=12,
            ),
            ft.Button(
                ref=self.r_scan, content="SCAN NETWORK", on_click=on_scan,
                width=150, bgcolor=tint(CYAN, .19), color=CYAN,
                style=ft.ButtonStyle(
                    shape=ft.RoundedRectangleBorder(radius=8),
                    padding=ft.padding.Padding.symmetric(horizontal=14, vertical=12),
                ),
            ),
            ft.ProgressRing(
                ref=self.r_progress, width=18, height=18, stroke_width=2,
                color=CYAN, visible=False,
            ),
        ], spacing=10, scroll=ft.ScrollMode.AUTO,
           vertical_alignment=ft.CrossAxisAlignment.CENTER)

        self._summary_cards = [
            summary("DEVICES ONLINE", self.r_devices, CYAN, ft.Icons.DEVICES_ROUNDED),
            summary("OPEN PORTS", self.r_ports, GREEN, ft.Icons.LOCK_OPEN_ROUNDED),
            summary("RISK LEVEL", self.r_risk, AMBER, ft.Icons.SECURITY_ROUNDED),
            summary("CHANGES", self.r_changes, PURPLE, ft.Icons.COMPARE_ARROWS_ROUNDED),
        ]
        self._summary_row = ft.Row(
            self._summary_cards, spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START,
        )
        self._content_cards = [
            card(ft.Column([
                section_title("DEVICES AND SERVICES"),
                ft.Divider(color=BORDER, height=6),
                ft.Column(
                    ref=self.r_device_list, spacing=8,
                    controls=[ft.Text("Run a scan to build the inventory.", color=MUTED)],
                    scroll=ft.ScrollMode.AUTO, expand=True,
                ),
            ], spacing=8, expand=True)),
            card(ft.Column([
                section_title("ALERTS AND CHANGES"),
                ft.Divider(color=BORDER, height=6),
                ft.Column(
                    ref=self.r_alert_list, spacing=8,
                    controls=[ft.Text("No alerts.", color=MUTED)],
                    scroll=ft.ScrollMode.AUTO, expand=True,
                ),
            ], spacing=8, expand=True)),
        ]
        self._content_row = ft.Row(
            self._content_cards, spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START,
        )

        self._scan_card = card(ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.LAN_ROUNDED, color=CYAN, size=24),
                    ft.Column([
                        ft.Text("ACTIVE NETWORK DISCOVERY", size=13, color=TEXT,
                                weight=ft.FontWeight.W_700),
                        ft.Text(
                            "Nmap inventory, exposed services, changes and risk indicators",
                            size=11, color=MUTED,
                        ),
                    ], spacing=2),
                    ft.Container(expand=True),
                    ft.Text(
                        "Nmap ready" if self.scanner.available else "Nmap not found",
                        color=GREEN if self.scanner.available else RED, size=11,
                    ),
                ], spacing=10),
                self._scan_row,
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.HELP_OUTLINE_ROUNDED, color=CYAN, size=17),
                            ft.Text("HOW TO USE ACTIVE DISCOVERY", size=11, color=TEXT,
                                    weight=ft.FontWeight.W_700),
                        ], spacing=7),
                        ft.Text(
                            "1. Enter one or more authorized IPs, hostnames or CIDR networks. "
                            "Separate them with commas, spaces or new lines.",
                            size=10, color=MUTED,
                        ),
                        ft.Text(
                            "2. Choose Device discovery for online hosts, Quick ports for a fast "
                            "inventory, or deeper methods for detailed analysis.",
                            size=10, color=MUTED,
                        ),
                        ft.Text(
                            "Example: 172.26.4.0/24, 172.26.3.0/24  •  Scan only networks you own "
                            "or are authorized to assess.",
                            size=10, color=AMBER,
                        ),
                    ], spacing=4),
                    bgcolor=tint(CYAN, .045), border=ft.Border.all(1, tint(CYAN, .16)),
                    border_radius=8, padding=10,
                ),
                ft.Text(ref=self.r_status, value="Ready", size=11, color=MUTED),
            ], spacing=12), padding=14)
        self._history_card = card(ft.Row([
            ft.Dropdown(
                ref=self.r_history, label="Scan history", options=[],
                on_select=on_history, width=300, bgcolor=SURFACE, color=TEXT,
                border_color=BORDER, focused_border_color=CYAN, text_size=12,
            ),
            ft.Text(ref=self.r_metadata, value="No scans yet", size=11, color=MUTED),
        ], spacing=12, wrap=True, run_spacing=8), padding=12)

        return ft.Column([
            view_heading("Network discovery", "Inventory devices, exposed services and topology changes",
                         ft.Icons.HUB_ROUNDED, CYAN),
            self._scan_card,

            self._summary_row,

            self._history_card,

            self._content_row,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = max(300.0, width - 28.0)
        content_height = max(420.0, height - 28.0)
        mode = "wide" if content_width >= 760 else "compact" if content_width >= 380 else "narrow"
        key = (mode, round(content_width), round(content_height))
        if key == self._layout_key or not self._summary_cards:
            return
        self._layout_key = key
        self._scan_row.width = content_width
        self._summary_row.width = content_width
        self._content_row.width = content_width
        self._scan_card.width = content_width
        self._history_card.width = content_width

        summary_count = 4 if mode == "wide" else 2 if mode == "compact" else 1
        summary_width = (content_width - 12 * (summary_count - 1)) / summary_count
        for control in self._summary_cards:
            control.width = summary_width
        if mode == "wide":
            self._content_cards[0].width = content_width * 0.60 - 6
            self._content_cards[1].width = content_width * 0.40 - 6
            content_card_height = max(220.0, content_height - 410.0)
            for control in self._content_cards:
                control.height = content_card_height
        else:
            for control in self._content_cards:
                control.width = content_width
                control.height = None

        if mode == "narrow":
            self.r_target.current.width = 240
            self.r_profile.current.width = 150
            self.r_scan.current.width = 135
        elif mode == "compact":
            self.r_target.current.width = 260
            self.r_profile.current.width = 150
            self.r_scan.current.width = 150
        else:
            self.r_target.current.width = 300
            self.r_profile.current.width = 180
            self.r_scan.current.width = 150

    async def _run_scan(self):
        if self._running or self._disposed:
            return
        self._running = True
        self._cancel_event = threading.Event()
        target = (self.r_target.current.value or "").strip()
        profile = self.r_profile.current.value or "quick"
        self.r_scan.current.disabled = True
        self.r_progress.current.visible = True
        self.r_status.current.value = tr("Running ") + f"{SCAN_PROFILES[profile]['label']}..."
        self.r_status.current.color = CYAN
        if not self._safe_page_update():
            self._running = False
            return
        try:
            previous = self.db.get_latest_network_scan(target)
            scan = await asyncio.to_thread(
                self.scanner.scan,
                target,
                profile,
                self._cancel_event,
            )
            if self._disposed:
                return
            scan.findings.extend(compare_scans(previous, scan))
            self.db.save_network_scan(scan)
            self._render_scan(scan)
            self._reload_history(selected=scan.scan_id)
            self.r_status.current.value = tr(
                f"Completed in {scan.duration_seconds:.1f}s · {len(scan.hosts)} devices"
            )
            self.r_status.current.color = GREEN
        except asyncio.CancelledError:
            self.dispose()
            return
        except NmapCancelledError:
            if not self._disposed:
                self.r_status.current.value = tr("Scan cancelled.")
                self.r_status.current.color = MUTED
        except Exception as exc:
            if not self._disposed:
                self.r_status.current.value = str(exc)
                self.r_status.current.color = RED
        finally:
            self._running = False
            if not self._disposed:
                self.r_scan.current.disabled = False
                self.r_progress.current.visible = False
                self._safe_page_update()

    def _safe_page_update(self) -> bool:
        """Update Flet only while its session is still available."""
        if self._disposed or not self._page or self._page[0] is None:
            return False
        try:
            self._page[0].update()
            return True
        except RuntimeError as exc:
            if "destroyed session" not in str(exc).lower():
                raise
            self.dispose()
            return False

    def dispose(self) -> None:
        """Cancel background work before Flet destroys the page session."""
        if self._disposed:
            return
        self._disposed = True
        self._cancel_event.set()
        self.scanner.cancel()

    def _render_scan(self, scan):
        self.r_devices.current.value = str(len(scan.hosts))
        self.r_ports.current.value = str(scan.open_port_count)
        self.r_risk.current.value = scan.risk_level.upper()
        self.r_risk.current.color = self._risk_color(scan.risk_level)
        changes = sum(1 for finding in scan.findings if finding.kind != "exposed_service")
        self.r_changes.current.value = str(changes)
        self.r_metadata.current.value = (
            f"#{scan.scan_id or '-'} · {scan.target} · {scan.profile} · "
            f"{scan.started_at:%Y-%m-%d %H:%M} · Nmap {scan.nmap_version or '?'}"
        )

        device_controls = []
        for host in sorted(scan.hosts, key=lambda item: item.address):
            color = self._risk_color(host.risk_level)
            service_controls = []
            for service in host.open_ports:
                service_color = self._risk_color(service.risk_level)
                label = f"{service.port}/{service.protocol} {service.name}"
                if service.fingerprint:
                    label += f" · {service.fingerprint}"
                service_controls.append(ft.Container(
                    content=ft.Text(label, size=10, color=service_color),
                    bgcolor=tint(service_color, .09), border_radius=6,
                    border=ft.Border.all(1, tint(service_color, .21)),
                    padding=ft.padding.Padding.symmetric(horizontal=8, vertical=4),
                ))
            if not service_controls:
                service_controls = [ft.Text("No open ports in this scan profile", size=10, color=MUTED)]
            subtitle = " · ".join(
                value for value in (host.hostname, host.vendor, host.os_name) if value
            ) or "Unidentified device"
            device_controls.append(ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.DEVICES_OTHER_ROUNDED, color=color, size=18),
                        ft.Text(host.address, color=TEXT, size=12,
                                weight=ft.FontWeight.W_700, font_family="monospace"),
                        ft.Text(host.status.upper(), color=GREEN, size=9),
                        ft.Container(expand=True),
                        ft.Text(f"{host.risk_level.upper()} {host.risk_score}",
                                color=color, size=10, weight=ft.FontWeight.W_700),
                    ], spacing=8),
                    ft.Text(subtitle, size=10, color=DIM,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Row(service_controls, spacing=6, wrap=True, run_spacing=6),
                ], spacing=6),
                bgcolor=SURFACE, border=ft.Border.all(1, tint(color, .21)),
                border_radius=10, padding=10,
            ))
        self.r_device_list.current.controls = device_controls or [
            ft.Text("No responding devices were found.", color=MUTED)
        ]

        alert_controls = []
        severity_order = {"high": 0, "medium": 1, "low": 2}
        for finding in sorted(
            scan.findings, key=lambda item: severity_order.get(item.severity, 3)
        ):
            color = self._risk_color(finding.severity)
            alert_controls.append(ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=color, size=15),
                        ft.Text(finding.title, color=TEXT, size=11,
                                weight=ft.FontWeight.W_600, expand=True),
                        ft.Text(finding.host, color=color, size=9,
                                font_family="monospace"),
                    ], spacing=6),
                    ft.Text(finding.detail, size=10, color=MUTED),
                ], spacing=4),
                bgcolor=tint(color, .06), border=ft.Border.all(1, tint(color, .19)),
                border_radius=8, padding=9,
            ))
        self.r_alert_list.current.controls = alert_controls or [
            ft.Text("No relevant changes or exposed high-risk services.", color=GREEN, size=11)
        ]
        translate_tree(self.r_device_list.current, get_language())
        translate_tree(self.r_alert_list.current, get_language())

    def _reload_history(self, selected=None):
        if not self.r_history.current:
            return
        scans = self.db.list_network_scans()
        self.r_history.current.options = [
            ft.DropdownOption(
                key=str(scan["id"]),
                text=(f"#{scan['id']} {scan['started_at'][:16]} · {scan['target']} · "
                      f"{scan['host_count']} hosts · {scan['risk_level']}")
            )
            for scan in scans
        ]
        if selected:
            self.r_history.current.value = str(selected)

    def on_mount(self):
        self._reload_history()
        latest = self.db.get_latest_network_scan()
        if latest:
            self._render_scan(latest)


# ── 3. LIVE PACKETS ────────────────────────────────────────────────────

class PacketsView:
    def __init__(self, state: AppState, page_ref):
        self.s = state
        self._page = page_ref
        self.paused   = False
        self._f_proto = "All"
        self._f_dir   = "All"
        self._f_ip    = ""
        self.r_table     = ft.Ref[ft.DataTable]()
        self.r_count     = ft.Ref[ft.Text]()
        self.r_pause_btn = ft.Ref[ft.Button]()
        self.r_empty = ft.Ref[ft.Container]()
        self._toolbar_card = None
        self._toolbar_row = None
        self._table_container = None
        self._proto_filter = None
        self._direction_filter = None
        self._ip_filter = None
        self._layout_key = None

    def build(self):
        def on_proto(e): self._f_proto = e.control.value
        def on_dir(e):   self._f_dir   = e.control.value
        def on_ip(e):    self._f_ip    = (e.control.value or "").strip()
        def on_pause(e):
            self.paused = not self.paused
            if self.r_pause_btn.current:
                self.r_pause_btn.current.content = "Resume" if self.paused else "Pause"
                self.r_pause_btn.current.bgcolor = tint(AMBER, .19) if self.paused else BORDER
                self.r_pause_btn.current.update()

        def on_export(e):
            self._export_csv()

        def dd(label, opts, cb, w=130):
            return ft.Dropdown(
                label=label, value="All",
                options=[ft.DropdownOption(x) for x in opts],
                on_select=cb, width=w,
                bgcolor=SURFACE, color=TEXT,
                border_color=BORDER, focused_border_color=CYAN,
                text_size=12,
            )

        table = ft.DataTable(
            ref=self.r_table,
            columns=[
                ft.DataColumn(ft.Text("Time",     color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Dir",      color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Protocol", color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Src IP",   color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Dst IP",   color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Port",     color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Bytes",    color=DIM, size=11, weight=ft.FontWeight.W_600),
                              numeric=True),
                ft.DataColumn(ft.Text("Geo",      color=DIM, size=11, weight=ft.FontWeight.W_600)),
            ],
            rows=[],
            bgcolor=CARD,
            border=ft.Border.all(1, BORDER),
            border_radius=12,
            column_spacing=18,
            heading_row_color=SURFACE,
            heading_row_height=38,
            data_row_min_height=28,
            data_row_max_height=34,
            divider_thickness=0.4,
        )

        self._proto_filter = dd(
            "Protocol", ["All"] + list(PROTO_COLORS), on_proto, 140
        )
        self._direction_filter = dd(
            "Direction", ["All", "IN", "OUT"], on_dir, 110
        )
        self._ip_filter = ft.TextField(
            label="Filter IP", hint_text="e.g. 8.8.8.8",
            on_change=on_ip, width=200,
            bgcolor=SURFACE, color=TEXT,
            border_color=BORDER, focused_border_color=CYAN,
            cursor_color=CYAN, text_size=12,
            prefix_icon=ft.Icons.SEARCH_ROUNDED,
        )
        self._toolbar_row = ft.Row([
                    self._proto_filter,
                    self._direction_filter,
                    self._ip_filter,
                    ft.Text(ref=self.r_count, value="0 packets", size=12, color=MUTED),
                    ft.Button(
                        ref=self.r_pause_btn,
                        content="⏸ Pause", on_click=on_pause,
                        bgcolor=BORDER, color=TEXT,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                    ),
                    ft.Button(
                        content="📥 Export CSV", on_click=on_export,
            bgcolor=tint(PURPLE, .19), color=PURPLE,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                    ),
                ], spacing=10, wrap=True, run_spacing=10)
        self._toolbar_card = card(
            self._toolbar_row,
            padding=ft.padding.Padding.symmetric(horizontal=14, vertical=10),
        )
        self._table_container = ft.Container(
            content=ft.Stack([
                ft.Column(
                    [ft.Row([table], scroll=ft.ScrollMode.ALWAYS)],
                    scroll=ft.ScrollMode.ALWAYS, expand=True,
                ),
                ft.Container(
                    ref=self.r_empty,
                    content=ft.Column([
                        ft.Icon(ft.Icons.WIFI_TETHERING_ROUNDED, color=MUTED, size=34),
                        ft.Text("No packets captured yet", color=DIM, size=13,
                                weight=ft.FontWeight.W_600),
                        ft.Text("Start capture or generate network traffic.",
                                color=MUTED, size=11),
                    ], spacing=6, horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                       alignment=ft.MainAxisAlignment.CENTER),
                    alignment=ft.Alignment.CENTER,
                    left=0, right=0, top=0, bottom=0,
                ),
            ], expand=True),
            expand=True, border_radius=12,
            clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
        )

        return ft.Column([
            view_heading("Packet explorer", "Inspect, filter and export the live packet stream",
                         ft.Icons.DATA_OBJECT_ROUNDED, GREEN),
            self._toolbar_card,
            self._table_container,
        ], spacing=10, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = max(280.0, width - 28.0)
        content_height = max(360.0, height - 28.0)
        mode = "wide" if content_width >= 900 else "compact" if content_width >= 600 else "narrow"
        key = (mode, round(content_width), round(content_height))
        if key == self._layout_key or not self._toolbar_card:
            return
        self._layout_key = key
        self._toolbar_card.width = content_width
        self._toolbar_row.width = max(250.0, content_width - 28.0)
        self._table_container.width = content_width
        if self.r_table.current:
            self.r_table.current.width = max(820.0, content_width)

        if mode == "narrow":
            self._proto_filter.width = 125
            self._direction_filter.width = 105
            self._ip_filter.width = min(220.0, content_width - 28.0)
        else:
            self._proto_filter.width = 140
            self._direction_filter.width = 110
            self._ip_filter.width = 220 if mode == "wide" else 180

    def _export_csv(self):
        """Export visible packets to CSV and show save path."""
        try:
            pkts = list(self.s.live)
            ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"netpulse_export_{ts_str}.csv"
            with open(fname, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Time", "Direction", "Protocol", "Src IP", "Dst IP",
                             "Sport", "Dport", "Bytes", "Remote", "Domain", "Geo"])
                for p in pkts:
                    domain = geo_cache.get_domain(p.remote)
                    geo    = geo_cache.get_geo(p.remote)
                    w.writerow([
                        p.ts.strftime("%H:%M:%S.%f"),
                        p.direction, p.protocol,
                        p.src, p.dst,
                        p.sport or "", p.dport or "",
                        p.size, p.remote, domain, geo,
                    ])
            # Show success snackbar
            try:
                page = self._page[0]
                page.snack_bar = ft.SnackBar(
                    content=ft.Text(f"{tr('✅ Exported')} {len(pkts)} {tr('packets')} → {fname}",
                                    color=GREEN),
                    bgcolor=CARD,
                    duration=4000,
                )
                page.snack_bar.open = True
                page.update()
            except Exception:
                pass
        except Exception as ex:
            try:
                page = self._page[0]
                page.snack_bar = ft.SnackBar(
                    content=ft.Text(f"{tr('❌ Export failed:')} {ex}", color=RED),
                    bgcolor=CARD,
                )
                page.snack_bar.open = True
                page.update()
            except Exception:
                pass

    def refresh(self):
        if self.paused or not self.r_table.current:
            return
        pkts = list(self.s.live)
        if self._f_proto != "All":
            pkts = [p for p in pkts if p.protocol == self._f_proto]
        if self._f_dir != "All":
            pkts = [p for p in pkts if p.direction == self._f_dir]
        if self._f_ip:
            pkts = [p for p in pkts if self._f_ip in p.src or self._f_ip in p.dst]

        displayed = list(reversed(pkts[-200:]))
        rows = []
        for p in displayed:
            c = CYAN if p.direction == "IN" else GREEN
            label = geo_cache.get_label(p.remote)
            rows.append(ft.DataRow(cells=[
                ft.DataCell(ft.Text(p.ts.strftime("%H:%M:%S"), size=10,
                                    color=MUTED, font_family="monospace")),
                ft.DataCell(ft.Row([
                    ft.Icon(ft.Icons.SOUTH_ROUNDED if p.direction == "IN"
                            else ft.Icons.NORTH_ROUNDED, color=c, size=12),
                    ft.Text(p.direction, size=10, color=c, weight=ft.FontWeight.W_600),
                ], spacing=3)),
                ft.DataCell(badge(p.protocol, proto_color(p.protocol))),
                ft.DataCell(ft.Text(p.src,  size=10, color=TEXT, font_family="monospace")),
                ft.DataCell(ft.Text(p.dst,  size=10, color=TEXT, font_family="monospace")),
                ft.DataCell(ft.Text(str(p.dport) if p.dport else "—",
                                    size=10, color=MUTED, font_family="monospace")),
                ft.DataCell(ft.Text(f"{p.size:,}", size=10, color=DIM,
                                    font_family="monospace")),
                ft.DataCell(ft.Text(label or "—", size=10, color=PURPLE,
                                    font_family="monospace",
                                    overflow=ft.TextOverflow.ELLIPSIS)),
            ]))
        self.r_table.current.rows = rows
        if self.r_empty.current:
            self.r_empty.current.visible = not rows
        try:
            self.r_table.current.update()
        except Exception:
            pass
        if self.r_count.current:
            self.r_count.current.value = f"{len(rows):,} packets"


# ── 3. CHARTS ────────────────────────────────────────────────────────────

class ChartsView:
    def __init__(self, state: AppState):
        self.s = state
        self.r_kbin  = ft.Ref[ft.Text]()
        self.r_kbout = ft.Ref[ft.Text]()
        self.r_pps   = ft.Ref[ft.Text]()
        self.r_peak_in  = ft.Ref[ft.Text]()
        self.r_peak_out = ft.Ref[ft.Text]()
        self.line_chart = LineChartCanvas(CYAN, GREEN, "Download", "Upload", 60, 220)
        proto_colors = [CYAN, PURPLE, BLUE, AMBER, GREEN, RED, MUTED]
        self.bar_chart  = BarChartCanvas(PROTO_LIST, proto_colors, 200)
        self._speed_cards = []
        self._speed_row = None
        self._chart_cards = []
        self._chart_row = None
        self._layout_mode = None

    def build(self):
        def _speed_card(label, ref, color, unit, ref_peak=None):
            peak_row = []
            if ref_peak:
                peak_row = [ft.Row([
                    ft.Text("peak:", size=10, color=MUTED),
                    ft.Text(ref=ref_peak, value="0", size=10, color=color,
                            font_family="monospace"),
                ], spacing=4)]
            return card(
                ft.Column([
                    ft.Text(label, size=10, color=DIM, weight=ft.FontWeight.W_600),
                    ft.Text(ref=ref, value="0.0", size=36, color=color,
                            weight=ft.FontWeight.BOLD, font_family="monospace"),
                    ft.Text(unit, size=12, color=MUTED),
                    *peak_row,
                ], spacing=4, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                glow=color, height=122,
            )

        self._speed_cards = [
            _speed_card("DOWNLOAD", self.r_kbin, CYAN, "KB/s", self.r_peak_in),
            _speed_card("UPLOAD", self.r_kbout, GREEN, "KB/s", self.r_peak_out),
            _speed_card("PACKETS/SEC", self.r_pps, AMBER, "pkt/s"),
        ]
        self._speed_row = ft.Row(
            self._speed_cards, spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START,
        )
        self._chart_cards = [
            card(ft.Column([
                ft.Row([
                    section_title("BANDWIDTH OVER TIME  ( KB/s )"),
                    ft.Container(expand=True),
                    ft.Row([
                        ft.Container(width=10, height=10, bgcolor=CYAN,  border_radius=3),
                        ft.Text("Download", size=11, color=DIM),
                        ft.Container(width=10, height=10, bgcolor=GREEN, border_radius=3),
                        ft.Text("Upload",   size=11, color=DIM),
                    ], spacing=8),
                ]),
                self.line_chart.widget,
            ], spacing=10)),

            card(ft.Column([
                section_title("PROTOCOL DISTRIBUTION"),
                self.bar_chart.widget,
            ], spacing=10)),
        ]
        self._chart_row = ft.Row(
            self._chart_cards, spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START,
        )
        return ft.Column([
            view_heading("Traffic analytics", "Bandwidth trends and protocol distribution in real time",
                         ft.Icons.QUERY_STATS_ROUNDED, PURPLE),
            self._speed_row,
            self._chart_row,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = max(280.0, width - 28.0)
        content_height = max(420.0, height - 28.0)
        mode = "wide" if content_width >= 430 else "compact" if content_width >= 330 else "narrow"
        layout_key = (mode, round(content_width), round(content_height))
        if layout_key == self._layout_mode or not self._speed_cards:
            return
        self._layout_mode = layout_key
        self._speed_row.width = content_width
        self._chart_row.width = content_width
        count = 3 if mode == "wide" else 2 if mode == "compact" else 1
        card_width = (content_width - 12 * (count - 1)) / count
        for control in self._speed_cards:
            control.width = card_width
        if mode == "compact":
            self._speed_cards[2].width = content_width
        if content_width >= 760:
            self._chart_cards[0].width = content_width * 0.62 - 6
            self._chart_cards[1].width = content_width * 0.38 - 6
            chart_height = max(210.0, min(460.0, content_height - 320.0))
        else:
            for control in self._chart_cards:
                control.width = content_width
            chart_height = 210 if content_height >= 620 else 170
        self.line_chart.resize(self._chart_cards[0].width - 28.0, chart_height)
        self.bar_chart.resize(self._chart_cards[1].width - 28.0, chart_height)

    def refresh(self):
        s = self.s
        if not self.r_kbin.current:
            return
        self.r_kbin.current.value  = f"{s.cur_kbps_in:.1f}"
        self.r_kbout.current.value = f"{s.cur_kbps_out:.1f}"
        self.r_pps.current.value   = f"{s.cur_pps:.0f}"
        if self.r_peak_in.current:
            self.r_peak_in.current.value  = f"{s.peak_kbps_in:.1f} KB/s"
        if self.r_peak_out.current:
            self.r_peak_out.current.value = f"{s.peak_kbps_out:.1f} KB/s"
        self.line_chart.update_data(list(s.hist_in), list(s.hist_out))
        if s.proto:
            vals = [float(s.proto.get(pr, 0)) for pr in PROTO_LIST]
            self.bar_chart.update_data(vals)


# ── 4. HISTORY ────────────────────────────────────────────────────────────

class HistoryView:
    def __init__(self, db: DB):
        self.db = db
        self.r_dd    = ft.Ref[ft.Dropdown]()
        self.r_table = ft.Ref[ft.DataTable]()
        self.r_info  = ft.Ref[ft.Text]()
        self.line_chart = LineChartCanvas(CYAN, GREEN, "Received", "Sent", 300, 210)
        self._header_card = None
        self._header_row = None
        self._chart_card = None
        self._table_card = None
        self._session_dropdown = None
        self._top_table = None
        self._layout_key = None

    def build(self):
        def on_session(e):
            if e.control.value:
                self._load(int(e.control.value))
        def on_refresh(e):
            self._reload_sessions()

        top_table = ft.DataTable(
            ref=self.r_table,
            columns=[
                ft.DataColumn(ft.Text("Remote IP",   color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Bytes",        color=DIM, size=11, weight=ft.FontWeight.W_600), numeric=True),
                ft.DataColumn(ft.Text("Packets",      color=DIM, size=11, weight=ft.FontWeight.W_600), numeric=True),
                ft.DataColumn(ft.Text("Last Seen",    color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Domain / Geo", color=DIM, size=11, weight=ft.FontWeight.W_600)),
            ],
            rows=[], bgcolor=CARD, border=ft.Border.all(1, BORDER), border_radius=10,
            column_spacing=20, heading_row_color=SURFACE, heading_row_height=36,
            data_row_min_height=30, divider_thickness=0.4,
        )
        self._top_table = top_table
        self._session_dropdown = ft.Dropdown(
            ref=self.r_dd, label="Session",
            hint_text="Select a captured session…", options=[],
            on_select=on_session, width=440,
            bgcolor=SURFACE, color=TEXT,
            border_color=BORDER, focused_border_color=CYAN, text_size=12,
        )
        self._header_row = ft.Row([
            self._session_dropdown,
            ft.IconButton(ft.Icons.REFRESH_ROUNDED, on_click=on_refresh,
                          icon_color=CYAN, tooltip="Reload sessions"),
            ft.Text(ref=self.r_info, value="← select a session", size=12, color=MUTED),
        ], spacing=10, wrap=True, run_spacing=10)
        self._header_card = card(
            self._header_row,
            padding=ft.padding.Padding.symmetric(horizontal=14, vertical=10),
        )
        self._chart_card = card(ft.Column([
            ft.Row([
                section_title("HISTORICAL TRAFFIC  ( KB/s per second )"),
                ft.Container(expand=True),
                ft.Row([
                    ft.Container(width=9, height=9, bgcolor=CYAN, border_radius=3),
                    ft.Text("Received", size=10, color=DIM),
                    ft.Container(width=9, height=9, bgcolor=GREEN, border_radius=3),
                    ft.Text("Sent", size=10, color=DIM),
                ], spacing=8),
            ]),
            self.line_chart.widget,
        ], spacing=12))
        self._table_card = card(ft.Column([
            section_title("TOP CONNECTIONS  ( this session )"),
            ft.Divider(color=BORDER, height=6),
            ft.Column([ft.Row([top_table], scroll=ft.ScrollMode.ALWAYS)],
                      scroll=ft.ScrollMode.ALWAYS, expand=True),
        ], spacing=10, expand=True))

        return ft.Column([
            view_heading("Session history", "Compare stored captures and review their top endpoints",
                         ft.Icons.HISTORY_ROUNDED, AMBER),
            self._header_card,
            self._chart_card,
            self._table_card,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = max(280.0, width - 28.0)
        content_height = max(420.0, height - 28.0)
        mode = "wide" if content_width >= 900 else "compact" if content_width >= 580 else "narrow"
        key = (mode, round(content_width), round(content_height))
        if key == self._layout_key or not self._header_card:
            return
        self._layout_key = key
        for control in (self._header_card, self._chart_card, self._table_card):
            control.width = content_width
        self._header_row.width = max(240.0, content_width - 28.0)
        self._session_dropdown.width = (
            min(460.0, content_width * 0.48)
            if mode != "narrow"
            else max(220.0, content_width - 84.0)
        )
        chart_height = 190 if content_height >= 720 else 165 if content_height >= 560 else 145
        self.line_chart.resize(content_width - 28.0, chart_height)
        self._table_card.height = max(220.0, content_height - chart_height - 150.0)
        if self._top_table:
            self._top_table.width = max(700.0, content_width - 36.0)

    def on_mount(self):
        self._reload_sessions()

    def _reload_sessions(self):
        if not self.r_dd.current:
            return
        sessions = self.db.list_sessions()
        self.r_dd.current.options = [
            ft.DropdownOption(
                key=str(s["id"]),
                text=(f"#{s['id']}  {str(s['start_time'])[:19]}"
                      f"  [{s['interface']}]  {s.get('total_pkts',0):,} pkts"),
            )
            for s in sessions
        ]
        self.r_dd.current.update()

    def _load(self, sid: int):
        stats = self.db.get_stats(sid)
        if stats:
            da = [r["bytes_in"]  / 1024 for r in stats]
            db2 = [r["bytes_out"] / 1024 for r in stats]
            self.line_chart._n = len(da)
            self.line_chart.update_data(da, db2)

        tops = self.db.get_top_ips(sid, 15)
        if self.r_table.current:
            self.r_table.current.rows = [
                ft.DataRow(cells=[
                    ft.DataCell(ft.Text(t["ip"],   size=11, color=TEXT,  font_family="monospace")),
                    ft.DataCell(ft.Text(f"{t['total_bytes']:,}", size=11, color=CYAN,  font_family="monospace")),
                    ft.DataCell(ft.Text(f"{t['total_pkts']:,}",  size=11, color=DIM,   font_family="monospace")),
                    ft.DataCell(ft.Text(str(t["last_seen"] or "")[:19], size=10, color=MUTED)),
                    ft.DataCell(ft.Text(geo_cache.get_label(t["ip"]) or "…",
                                        size=10, color=PURPLE,
                                        overflow=ft.TextOverflow.ELLIPSIS)),
                ])
                for t in tops
            ]
            self.r_table.current.update()

        sessions = self.db.list_sessions()
        s = next((x for x in sessions if x["id"] == sid), None)
        if s and self.r_info.current:
            status = tr("Active") if not s.get("end_time") else tr("Completed")
            self.r_info.current.value = (
                f"{status}  ·  {s.get('total_pkts',0):,} pkts  ·  "
                f"↓ {s.get('total_bytes_in',0)/1_048_576:.1f} MB  ·  "
                f"↑ {s.get('total_bytes_out',0)/1_048_576:.1f} MB"
            )
            self.r_info.current.update()


# ── 5. SETTINGS ────────────────────────────────────────────────────────────

class SettingsView:
    def __init__(self, state: AppState, language: str = "en", on_language_change=None):
        self.state = state
        self.language = language
        self.on_language_change = on_language_change
        self.r_bw_thresh   = ft.Ref[ft.TextField]()
        self.r_pps_thresh  = ft.Ref[ft.TextField]()
        self.r_alert_status = ft.Ref[ft.Text]()
        self._cards = []
        self._settings_body = None
        self._settings_columns = []
        self._interface_dropdown = None
        self._bw_field = None
        self._pps_field = None
        self._alert_fields_row = None
        self._alert_button = None
        self._layout_key = None

    def build(self):
        ifaces = list_interfaces()
        opts = [ft.DropdownOption("All", "All interfaces")] + [
            ft.DropdownOption(i["name"], f"{i['name']}  —  {i['ip']}")
            for i in ifaces
        ]
        def on_iface(e): self.state.interface = e.control.value

        def on_language(e):
            self.language = e.control.value or "en"
            if self.on_language_change:
                self.on_language_change(self.language)

        def on_save_alerts(e):
            try:
                bw = float((self.r_bw_thresh.current.value or "0").strip())
                pps = float((self.r_pps_thresh.current.value or "0").strip())
                self.state.alert_bw_thresh  = max(0.0, bw)
                self.state.alert_pps_thresh = max(0.0, pps)
                if self.r_alert_status.current:
                    parts = []
                    if self.state.alert_bw_thresh > 0:
                        parts.append(f"BW ≥ {self.state.alert_bw_thresh:.0f} KB/s")
                    if self.state.alert_pps_thresh > 0:
                        parts.append(f"PPS ≥ {self.state.alert_pps_thresh:.0f} pkt/s")
                    self.r_alert_status.current.value = (
                        tr("✅ Alerts active:") + " " + "  |  ".join(parts) if parts
                        else tr("⚠️ Alerts disabled (set threshold > 0)")
                    )
                    self.r_alert_status.current.color = GREEN if parts else AMBER
                    self.r_alert_status.current.update()
            except ValueError:
                if self.r_alert_status.current:
                    self.r_alert_status.current.value = tr("❌ Invalid number")
                    self.r_alert_status.current.color = RED
                    self.r_alert_status.current.update()

        check_row = lambda txt, c=GREEN: ft.Row([
            ft.Icon(ft.Icons.CHECK_CIRCLE_ROUNDED, color=c, size=14),
            ft.Text(txt, size=12, color=TEXT),
        ], spacing=8)

        intro_card = card(ft.Column([
                ft.Row([
                    ft.Container(
                        ft.Icon(ft.Icons.RADAR_ROUNDED, color=CYAN, size=36),
                        bgcolor=tint(CYAN, .09), border_radius=12, padding=12,
                    ),
                    ft.Column([
                        ft.Text("NetPulse", size=22, color=TEXT, weight=ft.FontWeight.BOLD),
                        ft.Text("Real-time Network Analyzer", size=13, color=DIM),
                        ft.Text("Flet 0.85  +  Scapy  +  SQLite  ·  Loop 200ms", size=11, color=MUTED),
                    ], spacing=3),
                ], spacing=14, wrap=True, run_spacing=10),
            ], spacing=10))

        self._interface_dropdown = ft.Dropdown(
            label="Interface", value=self.state.interface or "All",
            options=opts, on_select=on_iface, width=420,
            bgcolor=SURFACE, color=TEXT,
            border_color=BORDER, focused_border_color=CYAN, text_size=12,
        )
        self._language_dropdown = ft.Dropdown(
            label="Language", value=self.language, width=240,
            options=[
                ft.DropdownOption("en", "English"),
                ft.DropdownOption("es", "Spanish"),
            ],
            on_select=on_language, bgcolor=SURFACE, color=TEXT,
            border_color=BORDER, focused_border_color=CYAN, text_size=12,
        )
        capture_card = card(ft.Column([
                section_title("⚙️  CAPTURE SETTINGS"),
                ft.Divider(color=BORDER, height=8),
                self._language_dropdown,
                ft.Text("Network Interface", size=12, color=DIM, weight=ft.FontWeight.W_500),
                self._interface_dropdown,
                ft.Text("Changes take effect on the next capture start.",
                        size=11, color=MUTED, italic=True),
            ], spacing=12))

        self._bw_field = ft.TextField(
            ref=self.r_bw_thresh,
            label="Bandwidth threshold (KB/s)",
            hint_text="e.g. 1000  (0 = disabled)",
            value="0", width=260,
            bgcolor=SURFACE, color=TEXT,
            border_color=BORDER, focused_border_color=AMBER,
            cursor_color=AMBER, text_size=12,
            prefix_icon=ft.Icons.NETWORK_CHECK_ROUNDED,
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self._pps_field = ft.TextField(
            ref=self.r_pps_thresh,
            label="Packet rate threshold (pkt/s)",
            hint_text="e.g. 5000  (0 = disabled)",
            value="0", width=260,
            bgcolor=SURFACE, color=TEXT,
            border_color=BORDER, focused_border_color=AMBER,
            cursor_color=AMBER, text_size=12,
            prefix_icon=ft.Icons.SPEED_ROUNDED,
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self._alert_button = ft.Button(
            "💾 Save Alerts", on_click=on_save_alerts,
            bgcolor=tint(AMBER, .19), color=AMBER,
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
        )
        self._alert_fields_row = ft.Row(
            [self._bw_field, self._pps_field],
            spacing=10, wrap=True, run_spacing=10,
        )
        alerts_card = card(ft.Column([
                section_title("🔔  TRAFFIC ALERTS"),
                ft.Divider(color=BORDER, height=8),
                ft.Text("Set thresholds to trigger notifications during capture.",
                        size=11, color=MUTED),
                self._alert_fields_row,
                self._alert_button,
                ft.Text(ref=self.r_alert_status,
                        value="⚠️ Alerts disabled (set threshold > 0)",
                        size=11, color=AMBER),
            ], spacing=12))

        database_card = card(ft.Column([
                section_title("🗄️  DATABASE  ( SQLite )"),
                ft.Divider(color=BORDER, height=8),
                ft.Row([
                    ft.Icon(ft.Icons.STORAGE_ROUNDED, color=CYAN, size=18),
                    ft.Text("netpulse.db  ·  same folder as main.py",
                            size=12, color=TEXT),
                ], spacing=10),
                ft.Container(
                    ft.Row([
                        ft.Icon(ft.Icons.INFO_OUTLINE_ROUNDED, color=AMBER, size=14),
                        ft.Text(
                            "Only aggregated per-second stats are stored. "
                            "Raw packets are never written to disk.",
                            size=11, color=MUTED, expand=True,
                        ),
                    ], spacing=6),
                    bgcolor=tint(AMBER, .06),
                    border=ft.Border.all(1, tint(AMBER, .19)),
                    border_radius=8, padding=10,
                ),
            ], spacing=12))

        requirements_card = card(ft.Column([
                section_title("⚠️  REQUIREMENTS"),
                ft.Divider(color=BORDER, height=8),
                check_row("Npcap installed  →  npcap.com"),
                check_row("Python 3.10+"),
                check_row("Run as Administrator  →  start_admin.bat", AMBER),
                check_row("Internet access for IP Geo-lookup (ip-api.com)", CYAN),
            ], spacing=10))

        left_column = ft.Column(
            [capture_card, database_card], spacing=12,
        )
        right_column = ft.Column(
            [alerts_card, requirements_card], spacing=12,
        )
        self._settings_columns = [left_column, right_column]
        self._settings_body = ft.Row(
            self._settings_columns, spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START,
        )
        self._cards = [
            intro_card, capture_card, alerts_card, database_card, requirements_card
        ]
        return ft.Column([
            view_heading("System settings", "Capture source, alert thresholds and local storage",
                         ft.Icons.TUNE_ROUNDED, CYAN),
            intro_card,
            self._settings_body,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = max(280.0, width - 28.0)
        content_height = max(420.0, height - 28.0)
        mode = "wide" if content_width >= 600 else "compact" if content_width >= 420 else "narrow"
        key = (mode, round(content_width), round(content_height))
        if key == self._layout_key or not self._cards:
            return
        self._layout_key = key
        self._cards[0].width = content_width
        self._settings_body.width = content_width

        if mode == "wide":
            column_widths = (content_width * 0.44 - 6, content_width * 0.56 - 6)
        elif mode == "compact":
            column_widths = (content_width, content_width)
        else:
            column_widths = (content_width, content_width)

        self._settings_columns[0].width, self._settings_columns[1].width = column_widths
        for control in (self._cards[1], self._cards[3]):
            control.width = column_widths[0]
        for control in (self._cards[2], self._cards[4]):
            control.width = column_widths[1]

        if mode == "wide" and content_height >= 520:
            # Balance both columns so Settings reads as one deliberate grid
            # instead of leaving a large void below the shorter left column.
            body_height = max(430.0, content_height - 160.0)
            self._cards[1].height = body_height * 0.44 - 6.0
            self._cards[3].height = body_height * 0.56 - 6.0
            self._cards[2].height = body_height * 0.64 - 6.0
            self._cards[4].height = body_height * 0.36 - 6.0
        else:
            for control in self._cards[1:]:
                control.height = None
        capture_inner = max(220.0, column_widths[0] - 28.0)
        self._interface_dropdown.width = min(500.0, capture_inner)
        alert_inner = max(220.0, column_widths[1] - 28.0)
        self._alert_fields_row.width = alert_inner
        if mode == "wide":
            field_width = max(160.0, (alert_inner - 10.0) / 2)
        else:
            field_width = alert_inner
        self._bw_field.width = field_width
        self._pps_field.width = field_width



# ── 6. PROCESSES ────────────────────────────────────────────────────────

class ProcessView:
    """Per-process bandwidth usage view."""

    # Process icon map (partial — common names)
    _ICONS: Dict[str, str] = {
        "chrome.exe":   "🌐", "firefox.exe":  "🦊", "msedge.exe":   "🌐",
        "discord.exe":  "💬", "slack.exe":    "💬", "teams.exe":    "💬",
        "steam.exe":    "🎮", "explorer.exe": "🗂️",  "svchost.exe":  "⚙️",
        "python.exe":   "🐍", "pythonw.exe":  "🐍", "node.exe":     "🟩",
        "spotify.exe":  "🎵", "zoom.exe":     "📹", "code.exe":     "💻",
        "OneDrive.exe": "☁️",  "dropbox.exe":  "☁️",  "curl.exe":     "🌐",
    }

    def __init__(self, state: AppState):
        self.s = state
        self.r_table = ft.Ref[ft.Column]()
        self.r_total = ft.Ref[ft.Text]()
        self.r_procs = ft.Ref[ft.Text]()
        self._empty_control = None
        self._root = None
        self._header_row = None
        self._legend_row = None
        self._legend_columns = []
        self._process_width = 200.0
        self._bytes_width = 90.0
        self._packets_width = 70.0
        self._layout_key = None

    def _icon(self, name: str) -> str:
        return self._ICONS.get(name, "📦")

    def build(self):
        self._header_row = ft.Row([
                ft.Icon(ft.Icons.APPS_ROUNDED, color=CYAN, size=20),
                ft.Text("PER-PROCESS BANDWIDTH", size=13, color=TEXT,
                        weight=ft.FontWeight.W_700),
                ft.Container(expand=True),
                ft.Text(ref=self.r_procs, value="0 processes", size=11, color=MUTED),
                ft.Container(width=8),
                ft.Text(ref=self.r_total, value="0 KB total", size=11, color=CYAN,
                        font_family="monospace"),
            ], spacing=10)
        self._legend_columns = [
            ft.Container(width=200, content=ft.Text(
                "Process", size=10, color=DIM, weight=ft.FontWeight.W_600)),
            ft.Container(width=90, content=ft.Text(
                "Bytes", size=10, color=DIM, weight=ft.FontWeight.W_600)),
            ft.Container(width=70, content=ft.Text(
                "Packets", size=10, color=DIM, weight=ft.FontWeight.W_600)),
            ft.Container(expand=True, content=ft.Text(
                "Share", size=10, color=DIM, weight=ft.FontWeight.W_600)),
        ]
        self._legend_row = ft.Row(self._legend_columns, spacing=8)
        empty_content = ft.Column([
            ft.Icon(ft.Icons.APPS_ROUNDED, color=MUTED, size=34),
            ft.Text("No process traffic available", color=DIM, size=13,
                    weight=ft.FontWeight.W_600),
            ft.Text("Start capture to associate connections with applications.",
                    color=MUTED, size=11),
        ], spacing=6, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        self._empty_control = ft.Container(
            content=empty_content,
            alignment=ft.Alignment.CENTER,
            expand=True,
        )
        self._root = ft.Column([
            self._header_row,
            ft.Divider(color=BORDER, height=6),

            # Legend row
            self._legend_row,
            ft.Divider(color=BORDER, height=4),

            ft.Column(ref=self.r_table, spacing=6,
                      scroll=ft.ScrollMode.AUTO, expand=True,
                      controls=[self._empty_control]),
        ], spacing=8, expand=True)
        return ft.Column([
            view_heading("Application traffic", "See which local processes consume network bandwidth",
                         ft.Icons.APPS_ROUNDED, GREEN),
            card(self._root, expand=True),
        ], spacing=12, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = max(280.0, width - 28.0)
        mode = "wide" if content_width >= 900 else "compact" if content_width >= 600 else "narrow"
        key = (mode, round(content_width), round(height))
        if key == self._layout_key or not self._root:
            return
        self._layout_key = key
        if mode == "wide":
            self._process_width, self._bytes_width, self._packets_width = 260, 120, 90
        elif mode == "compact":
            self._process_width, self._bytes_width, self._packets_width = 190, 95, 75
        else:
            self._process_width, self._bytes_width, self._packets_width = 135, 78, 62
        self._legend_columns[0].width = self._process_width
        self._legend_columns[1].width = self._bytes_width
        self._legend_columns[2].width = self._packets_width

    def refresh(self):
        if not self.r_table.current:
            return
        proc = self.s.proc_traffic
        if not proc:
            self.r_table.current.controls = [self._empty_control]
            if self.r_total.current:
                self.r_total.current.value = "0 KB total"
            if self.r_procs.current:
                self.r_procs.current.value = f"0 {tr('processes')}"
            return

        total_b = sum(d["b"] for d in proc.values()) or 1
        top = sorted(proc.items(), key=lambda x: -x[1]["b"])[:20]

        rows = []
        for name, d in top:
            b = d["b"]
            p = d["p"]
            share = b / total_b
            kb = b / 1024
            icon = self._icon(name)

            # Color by share intensity
            if share > 0.5:
                color = RED
            elif share > 0.2:
                color = AMBER
            elif share > 0.05:
                color = CYAN
            else:
                color = GREEN

            rows.append(ft.Column([
                ft.Row([
                    ft.Container(
                        content=ft.Text(f"{icon} {name}", size=11, color=TEXT,
                                        weight=ft.FontWeight.W_500, no_wrap=True,
                                        overflow=ft.TextOverflow.ELLIPSIS),
                        width=self._process_width,
                    ),
                    ft.Container(
                        content=ft.Text(
                            f"{kb:.1f} KB" if kb < 1024 else f"{kb/1024:.2f} MB",
                            size=11, color=color, font_family="monospace"),
                        width=self._bytes_width,
                    ),
                    ft.Container(
                        content=ft.Text(f"{p:,}", size=11, color=DIM,
                                        font_family="monospace"),
                        width=self._packets_width,
                    ),
                    ft.Container(
                        content=ft.Text(f"{share*100:.1f}%", size=10, color=color,
                                        font_family="monospace"),
                        width=46,
                    ),
                    ft.ProgressBar(value=share, color=color,
                                   bgcolor=tint(color, .13), height=6,
                                   border_radius=3, expand=True),
                ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ], spacing=3))

        self.r_table.current.controls = rows

        if self.r_total.current:
            tb = total_b / 1024
            self.r_total.current.value = (
                f"{tb:.1f} KB total" if tb < 1024 else f"{tb/1024:.2f} MB total"
            )
        if self.r_procs.current:
                self.r_procs.current.value = f"{len(proc)} {tr('processes')}"


