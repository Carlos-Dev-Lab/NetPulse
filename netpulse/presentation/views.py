"""Flet views for dashboards, packets, history, processes and settings."""

import asyncio
import csv
import io
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict

import flet as ft

from netpulse.domain.state import AppState
from netpulse.config import (
    DEFAULT_DATABASE_PATH, PROJECT_ROOT, load_alerts, load_retention_days,
    save_alerts, save_retention_days,
)
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import (
    NmapCancelledError,
    NmapScanner,
    SCAN_PROFILES,
    compare_scans,
)
from netpulse.domain.comparison import compare_scan_details
from netpulse.domain.diagnostics import (
    build_diagnostics, explain_service, findings_for_host, scheduled_scan_message,
)
from netpulse.domain.topology import build_topology
from netpulse.domain.health import calculate_network_health
from netpulse.infrastructure.sniffer import list_interfaces
from netpulse.services.ip_info import geo_cache
from netpulse.services.local_ports import list_local_listeners
from netpulse.services.performance import (
    adapter_capacity, checks_needed_for_trend, classify_quality, measure_quality,
    quality_trend,
)
from netpulse.services.reporting import export_scan_reports
from .charts import BarChartCanvas, LineChartCanvas, PieChartCanvas, SparklineCanvas
from .dialogs import close_dialog, open_dialog
from .i18n import get_language, tr, translate_tree
from .topology_map import NetworkTopologyMap
from .theme import (
    AMBER, BLUE, BORDER, CARD, CYAN, DIM, GREEN, MUTED, PROTO_COLORS,
    PROTO_LIST, PURPLE, RED, SURFACE, TEXT, badge, card, proto_color,
    fit, section_title, snap, split, tint, view_heading,
)

def _apply_widths(controls, widths) -> None:
    """Assign one row's column widths to a wrapping set of cards.

    ``widths`` describes a single visual row. When fewer columns than cards are
    shown the cards wrap, so the sequence is repeated: every card in a given
    position keeps the exact width of the card above it.
    """
    if not widths:
        return
    for index, control in enumerate(controls):
        control.width = widths[index % len(widths)]


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

    # The peak tile prints two figures, so its value is set in a smaller face
    # than the single-number tiles. Reserving one line box for all four keeps
    # their captions and values on the same baseline across the row.
    VALUE_LINE_HEIGHT = 34

    def _value_line(self, ref, size):
        return ft.Container(
            content=ft.Text(ref=ref, value="0", size=size, color=None,
                            weight=ft.FontWeight.BOLD, font_family="monospace"),
            height=self.VALUE_LINE_HEIGHT,
            alignment=ft.Alignment.CENTER_LEFT,
        )

    def _tile(self, title, ref_val, ref_sub, icon, color):
        value = self._value_line(ref_val, 26)
        value.content.color = color
        return card(
            ft.Column([
                ft.Row([
                    ft.Container(ft.Icon(icon, color=color, size=24),
                                 bgcolor=tint(color, .13), border_radius=14, padding=14),
                    ft.Column([
                        ft.Text(title, size=10, color=DIM, weight=ft.FontWeight.W_600),
                        value,
                    ], spacing=2),
                ], spacing=12),
                ft.Text(ref=ref_sub, value="", size=11, color=MUTED),
            ], spacing=8)
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
            ], spacing=6)
        )

    def build(self):
        # Extra refs for progress bars inside sys tiles
        self.r_cpu_bar = ft.Ref[ft.ProgressBar]()
        self.r_ram_bar = ft.Ref[ft.ProgressBar]()

        peak_value = self._value_line(self.r_peak, 18)
        peak_value.content.value = "0 KB/s"
        peak_value.content.color = AMBER

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
                            peak_value,
                        ], spacing=2),
                    ], spacing=12),
                    ft.Text("↓ in  /  ↑ out peak", size=11, color=MUTED),
                ], spacing=8)),
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
                    section_title("TOP CONNECTIONS", icon=ft.Icons.PUBLIC_ROUNDED, color=CYAN),
                    ft.Divider(color=BORDER, height=6),
                    ft.Column(ref=self.r_ips, spacing=6, expand=True,
                              scroll=ft.ScrollMode.AUTO,
                              controls=[ft.Text("Waiting...", color=MUTED, size=12)]),
                ], spacing=10, expand=True)),

                card(ft.Column([
                    section_title("LIVE PACKET FEED", icon=ft.Icons.BOLT_ROUNDED, color=AMBER),
                    ft.Divider(color=BORDER, height=6),
                    ft.Column(ref=self.r_feed, spacing=4, expand=True,
                              scroll=ft.ScrollMode.AUTO,
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
        content_width = fit(max(280.0, width - 28.0))
        content_height = fit(max(420.0, height - 28.0))
        # Two metric columns remain readable down to a 900 px physical window
        # at common Windows DPI settings; a single column wastes height and
        # makes the dashboard appear overflowed.
        mode = "wide" if content_width >= 820 else "compact" if content_width >= 380 else "narrow"
        layout_key = (mode, content_width, content_height)
        if layout_key == self._layout_mode or not self._metric_cards:
            return
        self._layout_mode = layout_key
        for row in self._responsive_rows:
            row.width = content_width

        metric_count = 4 if mode == "wide" else 2 if mode == "compact" else 1
        _apply_widths(self._metric_cards, split(content_width, metric_count, 12))

        system_count = 2 if mode != "narrow" else 1
        _apply_widths(self._system_cards, split(content_width, system_count, 12))
        if mode == "wide":
            # 62/38 is the intended emphasis; the pair must still end flush
            # with the metric row above it.
            trend_width = snap(content_width * 0.62 - 6)
            self._chart_cards[0].width = trend_width
            self._chart_cards[1].width = content_width - 12 - trend_width
            detail_width = split(content_width, 2, 12)
        else:
            self._chart_cards[0].width = self._chart_cards[1].width = content_width
            detail_width = [content_width, content_width]
        detail_height = snap(max(210.0, min(300.0, content_height * 0.28)))
        for control, value in zip(self._detail_cards, detail_width):
            control.width = value
            # Both operational lists form one visual pair. Their content can
            # grow independently, so a shared height plus internal scrolling
            # prevents one card from becoming taller than the other.
            control.height = detail_height

        # The dashboard is the at-a-glance view, so the whole stack has to fit
        # the viewport rather than push the two operational lists under the
        # fold — maximized, "Conexiones principales" and "Flujo de paquetes"
        # were cut in half by the status bar. 380 px is what the heading, the
        # metric row, the system row, the chart card chrome and the spacings
        # between them take; whatever the detail row leaves of the rest is the
        # chart canvas.
        chart_height = snap(max(
            145.0, min(360.0, content_height - 380.0 - detail_height)
        ))
        chart_card_height = chart_height + 58.0
        for control in self._chart_cards:
            control.height = chart_card_height
        line_width = snap(max(240.0, self._chart_cards[0].width - 28.0))
        # The donut used to stop growing at 220 px, so on a 1920 desktop it sat
        # as a small ring inside a 670 px card. It now tracks the space it has.
        pie_size = snap(max(150.0, min(chart_height,
                                       self._chart_cards[1].width - 48.0)))
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

    def __init__(self, db: DB, scanner: NmapScanner, page_ref,
                 state: AppState | None = None, notification_sink=None):
        self.db = db
        self.scanner = scanner
        self._page = page_ref
        self._state = state
        self._notification_sink = notification_sink
        self.r_global_search = ft.Ref[ft.TextField]()
        self.r_saved_profile = ft.Ref[ft.Dropdown]()
        self.r_schedule_list = ft.Ref[ft.Column]()
        self.r_target = ft.Ref[ft.TextField]()
        self.r_profile = ft.Ref[ft.Dropdown]()
        self.r_scan = ft.Ref[ft.Button]()
        self.r_progress = ft.Ref[ft.ProgressRing]()
        self.r_status = ft.Ref[ft.Text]()
        self.r_devices = ft.Ref[ft.Text]()
        self.r_ports = ft.Ref[ft.Text]()
        self.r_risk = ft.Ref[ft.Text]()
        self.r_changes = ft.Ref[ft.Text]()
        self.r_health = ft.Ref[ft.Text]()
        self.r_health_summary = ft.Ref[ft.Text]()
        self.r_health_factors = ft.Ref[ft.Column]()
        self.r_device_list = ft.Ref[ft.Column]()
        self.r_alert_list = ft.Ref[ft.Column]()
        self.r_selected_host = ft.Ref[ft.Text]()
        self.r_history = ft.Ref[ft.Dropdown]()
        self.r_metadata = ft.Ref[ft.Text]()
        self.r_diagnostic_summary = ft.Ref[ft.Text]()
        self.r_diagnostic_list = ft.Ref[ft.Column]()
        self.r_topology = ft.Ref[ft.Column]()
        self.r_topology_summary = ft.Ref[ft.Text]()
        self.r_comparison_summary = ft.Ref[ft.Text]()
        self.r_comparison = ft.Ref[ft.Column]()
        self.r_local_ports = ft.Ref[ft.Column]()
        self.r_local_ports_summary = ft.Ref[ft.Text]()
        self.r_asset_summary = ft.Ref[ft.Text]()
        self.r_asset_list = ft.Ref[ft.Column]()
        self._running = False
        self._scan_row = None
        self._summary_row = None
        self._summary_cards = []
        self._content_row = None
        self._content_cards = []
        self._scan_card = None
        self._history_card = None
        self._topology_card = None
        self._comparison_card = None
        self._search_card = None
        self._automation_card = None
        self._health_card = None
        self._local_ports_card = None
        self._asset_card = None
        self._network_tabs = None
        self._scan_mode_content = None
        self._new_scan_button = None
        self._history_scan_button = None
        self._topology_nodes = []
        self._topology_grids = []
        self._interactive_topology = None
        self._viewport_content_width = 1000.0
        self._layout_key = None
        self._disposed = False
        self._cancel_event = threading.Event()
        self._current_scan = None
        self._selected_host = ""
        self._schedule_dispatching = False

    @staticmethod
    def _risk_color(level: str) -> str:
        """Colour a risk level, leaving the benign case neutral.

        "Low" used to be green, so a host with ninety uneventful ports produced
        ninety green rows and the two that needed attention had to compete with
        them. Green is reserved for an outcome someone achieved - a finding
        resolved, a check that passed - not for the absence of a problem.
        """
        return RED if level == "high" else AMBER if level == "medium" else MUTED

    def build(self):
        def on_scan(e):
            if not self._running:
                self._page[0].run_task(self._run_scan)

        def on_history(e):
            if e.control.value:
                scan = self.db.get_network_scan(int(e.control.value))
                if scan:
                    self._render_scan(scan)

        def on_search(e=None):
            self._show_global_search((self.r_global_search.current.value or "").strip())

        def on_export(e=None):
            if self._page and self._page[0]:
                self._page[0].run_task(self._export_current_reports)

        def on_load_profile(e=None):
            self._load_selected_profile()

        def on_save_profile(e=None):
            self._show_save_profile_dialog()

        def on_schedule(e=None):
            self._show_schedule_dialog()

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
                ], spacing=10), padding=14,
            )

        def tab_section(title, subtitle, icon, color, body):
            """Section used inside a network tab; content stays visible."""
            subtitle_control = subtitle if isinstance(subtitle, ft.Control) else ft.Text(
                subtitle, size=10, color=MUTED,
            )
            return card(ft.Column([
                ft.Row([
                    ft.Container(
                        ft.Icon(icon, color=color, size=20),
                        bgcolor=tint(color, .09), border_radius=10, padding=8,
                    ),
                    ft.Column([
                        ft.Text(title, size=11, color=TEXT,
                                weight=ft.FontWeight.W_700),
                        subtitle_control,
                    ], spacing=2, expand=True),
                ], spacing=9),
                ft.Divider(color=BORDER, height=8),
                body,
            ], spacing=7), padding=12)

        profile_options = [
            ft.DropdownOption(key=key, text=tr(value["label"]))
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
            summary("NETWORK HEALTH", self.r_health, BLUE, ft.Icons.FAVORITE_ROUNDED),
        ]
        self._summary_row = ft.Row(
            self._summary_cards, spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START,
        )
        self._content_cards = []

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
        self._search_card = card(ft.Row([
            ft.Icon(ft.Icons.MANAGE_SEARCH_ROUNDED, color=CYAN, size=22),
            ft.TextField(
                ref=self.r_global_search, label="Global search",
                hint_text="IP, MAC, hostname, process, port or application",
                expand=True, bgcolor=SURFACE, border_color=BORDER,
                focused_border_color=CYAN, text_size=11, on_submit=on_search,
            ),
            ft.Button(content="SEARCH", icon=ft.Icons.SEARCH_ROUNDED,
                      on_click=on_search, color=CYAN, bgcolor=tint(CYAN, .13)),
        ], spacing=9, vertical_alignment=ft.CrossAxisAlignment.CENTER), padding=10)
        self._history_card = card(ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.HISTORY_ROUNDED, color=PURPLE, size=20),
                ft.Column([
                    ft.Text("PREVIOUS SCANS", size=11, color=TEXT,
                            weight=ft.FontWeight.W_700),
                    ft.Text("Choose a stored result to load it into the other tabs.",
                            size=10, color=MUTED),
                ], spacing=2),
            ], spacing=8),
            ft.Row([
                ft.Dropdown(
                    ref=self.r_history, label="Choose previous scan", options=[],
                    hint_text="Search by date, target, ID or risk",
                    helper_text="Type to filter the saved scans",
                    editable=True, enable_filter=True, enable_search=True,
                    menu_height=320, menu_width=680,
                    leading_icon=ft.Icons.SEARCH_ROUNDED,
                    on_select=on_history, width=520, bgcolor=SURFACE, color=TEXT,
                    border_color=BORDER, focused_border_color=CYAN, text_size=12,
                ),
                ft.Button(content="EXPORT REPORT", icon=ft.Icons.FILE_DOWNLOAD_ROUNDED,
                          on_click=on_export, color=GREEN, bgcolor=tint(GREEN, .10)),
            ], spacing=12, wrap=True, run_spacing=8),
            ft.Text(ref=self.r_metadata, value="No previous scan selected.",
                    size=11, color=MUTED),
        ], spacing=10), padding=12)
        self._diagnostic_card = tab_section(
            "DIAGNOSTIC CENTER",
            ft.Text(ref=self.r_diagnostic_summary,
                    value="Run two scans to compare changes.", size=10, color=MUTED),
            ft.Icons.HEALTH_AND_SAFETY_ROUNDED, CYAN,
            ft.Column(
                ref=self.r_diagnostic_list,
                controls=[ft.Text("No diagnostic information yet.", color=MUTED, size=11)],
                spacing=8,
            ))
        self._topology_card = tab_section(
            "NETWORK MAP",
            ft.Text(ref=self.r_topology_summary,
                    value="Segments and connections overview", size=10, color=MUTED),
            ft.Icons.ACCOUNT_TREE_ROUNDED, CYAN,
            ft.Column(
                ref=self.r_topology, spacing=10,
                controls=[ft.Text("Run a scan to build the network map.", color=MUTED)],
            ))
        self._comparison_card = tab_section(
            "BEFORE VS NOW",
            ft.Text(ref=self.r_comparison_summary,
                    value="A previous scan is required for comparison.", size=10, color=MUTED),
            ft.Icons.COMPARE_ARROWS_ROUNDED, PURPLE,
            ft.Column(
                ref=self.r_comparison,
                controls=[ft.Text("No comparison available.", color=MUTED, size=11)],
                spacing=8,
            ))
        self._automation_card = tab_section(
            "PROFILES AND SCHEDULES",
            "Save network groups and automate recurring scans",
            ft.Icons.SCHEDULE_ROUNDED, BLUE,
            ft.Column([
                ft.Row([
                    ft.Dropdown(
                        ref=self.r_saved_profile, label="Saved profile", options=[],
                        width=280, bgcolor=SURFACE, color=TEXT,
                        border_color=BORDER, focused_border_color=BLUE,
                    ),
                    ft.Button(content="LOAD", icon=ft.Icons.UPLOAD_ROUNDED,
                              on_click=on_load_profile, color=BLUE,
                              bgcolor=tint(BLUE, .10)),
                    ft.Button(content="SAVE PROFILE", icon=ft.Icons.BOOKMARK_ADD_ROUNDED,
                              on_click=on_save_profile, color=CYAN,
                              bgcolor=tint(CYAN, .10)),
                    ft.Button(content="SCHEDULE", icon=ft.Icons.ADD_ALARM_ROUNDED,
                              on_click=on_schedule, color=GREEN,
                              bgcolor=tint(GREEN, .10)),
                ], spacing=8, wrap=True, run_spacing=8),
                ft.Divider(color=BORDER, height=5),
                ft.Column(
                    ref=self.r_schedule_list,
                    controls=[ft.Text("No scheduled scans.", color=MUTED, size=10)],
                    spacing=6,
                ),
            ], spacing=8))
        self._health_card = tab_section(
            "NETWORK HEALTH DETAILS",
            ft.Text(ref=self.r_health_summary,
                    value="Run a scan to calculate network health.", size=10, color=MUTED),
            ft.Icons.MONITOR_HEART_ROUNDED, BLUE,
            ft.Column(
                ref=self.r_health_factors,
                controls=[ft.Text("No health assessment yet.", color=MUTED, size=10)],
                spacing=7,
            ))
        self._asset_card = tab_section(
            "ENTERPRISE ASSET INVENTORY",
            ft.Text(ref=self.r_asset_summary,
                    value="Run a scan to build the asset inventory.", size=10, color=MUTED),
            ft.Icons.INVENTORY_2_ROUNDED, CYAN,
            ft.Column(
                ref=self.r_asset_list,
                controls=[ft.Text("No assets observed yet.", color=MUTED, size=10)],
                spacing=7,
            ))
        self._local_ports_card = tab_section(
            "LOCAL PORT INSPECTOR",
            ft.Text(
                ref=self.r_local_ports_summary,
                value="Check which ports are listening on this computer.",
                size=10, color=MUTED,
            ),
            ft.Icons.PRIVACY_TIP_OUTLINED, PURPLE,
            ft.Column([
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.INFO_OUTLINE_ROUNDED, color=BLUE, size=16),
                        ft.Text(
                            "A listening port is not automatically dangerous. Review its process and exposure.",
                            color=MUTED, size=9, expand=True,
                        ),
                        ft.Button(
                            content="REFRESH", icon=ft.Icons.REFRESH_ROUNDED,
                            color=PURPLE, bgcolor=tint(PURPLE, .10),
                            on_click=lambda e: self._refresh_local_ports(),
                        ),
                    ], spacing=8),
                    bgcolor=tint(BLUE, .035), border_radius=8, padding=9,
                ),
                ft.Column(
                    ref=self.r_local_ports,
                    controls=[ft.Text("Press Refresh to inspect local ports.",
                                      color=MUTED, size=10)],
                    spacing=6,
                ),
            ], spacing=8))
        self._reload_profiles_and_schedules()

        def select_scan_mode(mode: str):
            showing_history = mode == "history"
            if not showing_history:
                self._reset_scan_results()
            self._scan_mode_content.content = (
                self._history_card if showing_history else self._scan_card
            )
            self._new_scan_button.color = MUTED if showing_history else CYAN
            self._new_scan_button.bgcolor = (
                tint(MUTED, .05) if showing_history else tint(CYAN, .17)
            )
            self._history_scan_button.color = CYAN if showing_history else MUTED
            self._history_scan_button.bgcolor = (
                tint(CYAN, .17) if showing_history else tint(MUTED, .05)
            )
            self._safe_page_update()

        # A bare string label is laid out against the button's intrinsic width,
        # so the Spanish text lost its last characters at mid desktop widths
        # even though the button was 600 px wide. An explicit non-wrapping
        # Text is measured against the space the button actually has.
        self._new_scan_button = ft.Button(
            content=ft.Text("NEW SCAN", size=12, weight=ft.FontWeight.W_600,
                            no_wrap=True, text_align=ft.TextAlign.CENTER),
            icon=ft.Icons.ADD_CHART_ROUNDED, expand=True,
            color=CYAN, bgcolor=tint(CYAN, .17),
            on_click=lambda e: select_scan_mode("new"),
        )
        self._history_scan_button = ft.Button(
            content=ft.Text("VIEW PREVIOUS SCAN", size=12, weight=ft.FontWeight.W_600,
                            no_wrap=True, text_align=ft.TextAlign.CENTER),
            icon=ft.Icons.HISTORY_ROUNDED, expand=True,
            color=MUTED, bgcolor=tint(MUTED, .05),
            on_click=lambda e: select_scan_mode("history"),
        )
        scan_mode_selector = card(ft.Column([
            ft.Text("WHAT DO YOU WANT TO DO?", size=10, color=DIM,
                    weight=ft.FontWeight.W_700),
            ft.Row([self._new_scan_button, self._history_scan_button], spacing=8),
        ], spacing=8), padding=10)
        self._scan_mode_content = ft.Container(content=self._scan_card)
        scan_workspace = ft.Column([
            scan_mode_selector, self._scan_mode_content,
        ], spacing=12)

        def tab_page(*controls):
            return ft.Column(
                list(controls), spacing=12, scroll=ft.ScrollMode.AUTO,
                expand=True,
            )

        def on_network_tab_change(event):
            # The map is an inspection workspace of its own. Giving it the
            # viewport occupied by search and KPI cards matches the focused
            # canvas layout while the other tabs retain their shared context.
            map_active = event.control.selected_index == 3
            self._search_card.visible = not map_active
            self._summary_row.visible = not map_active
            self._safe_page_update()

        try:
            initial_network_tab = max(0, min(4, int(
                os.getenv("NETPULSE_INITIAL_NETWORK_TAB", "0")
            )))
        except ValueError:
            initial_network_tab = 0
        self._network_tabs = ft.Tabs(
            length=5, selected_index=initial_network_tab, expand=True,
            animation_duration=180,
            on_change=on_network_tab_change,
            content=ft.Column([
                ft.TabBar(
                    tabs=[
                        ft.Tab(label=ft.Text("Scan"), icon=ft.Icons.RADAR_ROUNDED),
                        ft.Tab(label=ft.Text("Assets"), icon=ft.Icons.INVENTORY_2_ROUNDED),
                        ft.Tab(label=ft.Text("Diagnostics"), icon=ft.Icons.HEALTH_AND_SAFETY_ROUNDED),
                        ft.Tab(label=ft.Text("Map"), icon=ft.Icons.ACCOUNT_TREE_ROUNDED),
                        ft.Tab(label=ft.Text("Automation"), icon=ft.Icons.SCHEDULE_ROUNDED),
                    ],
                    scrollable=False, tab_alignment=ft.TabAlignment.FILL,
                    indicator_color=CYAN, label_color=CYAN,
                    unselected_label_color=MUTED, divider_color=BORDER,
                    label_text_style=ft.TextStyle(size=11, weight=ft.FontWeight.W_600),
                ),
                ft.TabBarView([
                    tab_page(scan_workspace),
                    tab_page(self._asset_card),
                    tab_page(self._health_card, self._diagnostic_card, self._comparison_card,
                             self._local_ports_card),
                    tab_page(self._topology_card),
                    tab_page(self._automation_card),
                ], expand=True),
            ], spacing=8, expand=True),
        )
        if initial_network_tab == 3:
            self._search_card.visible = False
            self._summary_row.visible = False

        return ft.Column([
            view_heading("Network discovery", "Inventory devices, exposed services and topology changes",
                         ft.Icons.HUB_ROUNDED, CYAN),
            self._search_card,
            self._summary_row,
            self._network_tabs,
        ], spacing=12, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = fit(max(300.0, width - 28.0))
        self._viewport_content_width = content_width
        content_height = fit(max(420.0, height - 28.0))
        mode = "wide" if content_width >= 760 else "compact" if content_width >= 380 else "narrow"
        key = (mode, content_width, content_height)
        if key == self._layout_key or not self._summary_cards:
            return
        self._layout_key = key
        self._scan_row.width = content_width
        self._summary_row.width = content_width
        self._scan_card.width = content_width
        self._history_card.width = content_width
        self._diagnostic_card.width = content_width
        self._topology_card.width = content_width
        self._comparison_card.width = content_width
        self._search_card.width = content_width
        self._automation_card.width = content_width
        self._health_card.width = content_width
        self._asset_card.width = content_width
        self._local_ports_card.width = content_width
        self._network_tabs.width = content_width

        # Five columns need roughly 1120 px before "DISPOSITIVOS EN LÍNEA" stops
        # fitting beside its icon; below that the row drops to three so the
        # caption is never clipped mid-word.
        summary_count = (
            5 if content_width >= 1120
            else 3 if content_width >= 760
            else 2 if content_width >= 380
            else 1
        )
        _apply_widths(self._summary_cards, split(content_width, summary_count, 12))
        for grid, node_count in self._topology_grids:
            columns = max(1, round(
                (content_width - 40.0 + 8.0) /
                (self._topology_card_width(content_width) + 8.0)
            ))
            grid.height = snap(max(156.0, ((node_count + columns - 1) // columns) * 156.0))
        if self._interactive_topology:
            self._interactive_topology.resize(max(280.0, content_width - 28.0))
        if mode == "narrow":
            self.r_target.current.width = 240
            self.r_profile.current.width = 150
            self.r_scan.current.width = 135
        elif mode == "compact":
            self.r_target.current.width = 260
            self.r_profile.current.width = 150
            self.r_scan.current.width = 150
        else:
            self.r_profile.current.width = 180
            self.r_scan.current.width = 150
            # A 300 px target field left the rest of the scan card empty on a
            # wide desktop. It takes the room the method selector, the button
            # and the progress ring do not need.
            self.r_target.current.width = snap(
                max(300.0, content_width - 28.0 - 180 - 150 - 18 - 30)
            )
        # ``_network_tabs`` expands, so the tab region always reaches the
        # bottom of the viewport; the scan form only needs about 270 px of it.
        # On a maximized window that left a third of the section as bare
        # background below the card. The panel now keeps a floor so the empty
        # room sits inside the frame, the way it does on the other four tabs.
        # The floor is only applied where it is comfortably taller than the
        # form itself, so a short window never clips the card contents.
        panel_floor = fit(content_height - 404.0)
        floor = panel_floor if mode == "wide" and panel_floor >= 420.0 else None
        self._scan_card.height = floor
        self._history_card.height = floor

    @staticmethod
    def _topology_card_width(content_width: float) -> float:
        """Fill the map row with equal cards while keeping them readable."""
        available = max(230.0, content_width - 48.0)
        # Flet reports logical pixels after Windows DPI scaling. The node
        # contents remain readable at 180 px because labels ellipsize and
        # service badges wrap; using a larger target leaves a full card-sized
        # strip unused on 125–150% scaled desktop displays.
        columns = max(1, min(9, int((available + 8.0) // 188.0)))
        return float(int((available - 8.0 * (columns - 1)) // columns))

    def _refresh_local_ports(self):
        if not self.r_local_ports.current:
            return
        listeners = list_local_listeners()
        exposure_labels = {
            "local": "This computer only",
            "all_interfaces": "All network interfaces",
            "network_interface": "Specific network interface",
        }
        controls = []
        for listener in listeners:
            color = self._risk_color(listener.risk_level)
            exposure_color = MUTED if listener.exposure == "local" else AMBER
            controls.append(ft.Container(
                content=ft.Row([
                    ft.Container(
                        content=ft.Column([
                            ft.Text(str(listener.port), color=color, size=16,
                                    weight=ft.FontWeight.W_700,
                                    font_family="monospace"),
                            ft.Text(listener.protocol, color=MUTED, size=8,
                                    weight=ft.FontWeight.W_700),
                        ], spacing=0, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                        width=62, padding=7, bgcolor=tint(color, .07),
                        border_radius=8,
                    ),
                    ft.Column([
                        ft.Row([
                            ft.Text(listener.process, color=TEXT, size=10,
                                    weight=ft.FontWeight.W_700),
                            ft.Text(f"PID {listener.pid or '-'}", color=MUTED, size=8,
                                    font_family="monospace"),
                            ft.Text(listener.service, color=CYAN, size=9),
                        ], spacing=7, wrap=True),
                        ft.Text(listener.explanation, color=MUTED, size=9),
                    ], spacing=3, expand=True),
                    ft.Column([
                        ft.Text(tr(listener.risk_level.upper()), color=color, size=8,
                                weight=ft.FontWeight.W_700),
                        ft.Text(tr(exposure_labels[listener.exposure]),
                                color=exposure_color, size=8,
                                weight=ft.FontWeight.W_600),
                        ft.Text(f"{listener.address} · {listener.family}", color=MUTED,
                                size=8, font_family="monospace"),
                    ], spacing=2, horizontal_alignment=ft.CrossAxisAlignment.END),
                ], spacing=9),
                bgcolor=tint(color, .03), border=ft.Border.all(1, tint(color, .14)),
                border_radius=8, padding=8,
            ))
        sensitive = sum(item.risk_level in {"high", "medium"} for item in listeners)
        exposed = sum(item.exposure != "local" for item in listeners)
        self.r_local_ports_summary.current.value = tr(
            f"{len(listeners)} listening ports · {exposed} network-visible · "
            f"{sensitive} require attention"
        )
        self.r_local_ports.current.controls = controls or [ft.Text(
            "No local listening ports were found, or administrator permission is required.",
            color=MUTED, size=10,
        )]
        translate_tree(self.r_local_ports.current, get_language())
        self._safe_page_update()

    def _reload_profiles_and_schedules(self):
        if self.r_saved_profile.current:
            profiles = self.db.list_scan_profiles()
            self.r_saved_profile.current.options = [
                ft.DropdownOption(str(item["id"]), item["name"]) for item in profiles
            ]
            valid = {str(item["id"]) for item in profiles}
            if self.r_saved_profile.current.value not in valid:
                self.r_saved_profile.current.value = next(iter(valid), None)
        if not self.r_schedule_list.current:
            return
        controls = []
        for schedule in self.db.list_scan_schedules():
            next_run = datetime.fromisoformat(schedule["next_run"]).strftime("%Y-%m-%d %H:%M")

            def toggle(e, schedule_id=schedule["id"]):
                self.db.set_schedule_enabled(schedule_id, bool(e.control.value))
                self._reload_profiles_and_schedules()
                self._safe_page_update()

            def remove(e, schedule_id=schedule["id"]):
                self.db.delete_scan_schedule(schedule_id)
                self._reload_profiles_and_schedules()
                self._safe_page_update()

            controls.append(ft.Container(
                content=ft.Row([
                    ft.Switch(value=bool(schedule["enabled"]), on_change=toggle,
                              active_color=GREEN),
                    ft.Column([
                        ft.Text(schedule["name"], color=TEXT, size=10,
                                weight=ft.FontWeight.W_700),
                        ft.Text(
                            tr(f"Every {schedule['interval_minutes']} min · {schedule['profile']} · next {next_run}"),
                            color=MUTED, size=9,
                        ),
                    ], spacing=2, expand=True),
                    ft.Text(tr("CHANGES ONLY" if schedule["notify_changes_only"] else "ALWAYS"),
                            color=CYAN, size=8, weight=ft.FontWeight.W_700),
                    ft.IconButton(icon=ft.Icons.DELETE_OUTLINE_ROUNDED, icon_color=RED,
                                  icon_size=16, tooltip="Delete schedule", on_click=remove),
                ], spacing=7),
                bgcolor=SURFACE, border=ft.Border.all(1, BORDER),
                border_radius=7, padding=7,
            ))
        self.r_schedule_list.current.controls = controls or [
            ft.Text("No scheduled scans.", color=MUTED, size=10)
        ]
        translate_tree(self.r_schedule_list.current, get_language())

    def _load_selected_profile(self):
        value = self.r_saved_profile.current.value if self.r_saved_profile.current else None
        if not value:
            return
        profile = self.db.get_scan_profile(int(value))
        if not profile:
            return
        self.r_target.current.value = profile["target"]
        self.r_profile.current.value = profile["profile"]
        self.r_status.current.value = tr(f"Profile loaded: {profile['name']}")
        self.r_status.current.color = BLUE
        self._safe_page_update()

    def _show_save_profile_dialog(self):
        if not self._page or not self._page[0]:
            return
        name = ft.TextField(label="Profile name", hint_text="Red administrativa")
        page = self._page[0]

        def close(e=None):
            close_dialog(page)

        def save(e=None):
            try:
                target = self.scanner.validate_target(self.r_target.current.value or "")
                profile = self.r_profile.current.value or "quick"
                profile_id = self.db.save_scan_profile(name.value or "", target, profile)
                close()
                self._reload_profiles_and_schedules()
                self.r_saved_profile.current.value = str(profile_id)
                self.r_status.current.value = tr("Scan profile saved.")
                self.r_status.current.color = GREEN
                self._safe_page_update()
            except Exception as exc:
                name.error_text = str(exc)
                page.update()

        dialog = ft.AlertDialog(
            modal=True, title=ft.Text("Save scan profile"), content=name,
            actions=[ft.TextButton("Cancel", on_click=close),
                     ft.Button(content="Save profile", on_click=save)],
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    def _show_schedule_dialog(self):
        if not self._page or not self._page[0]:
            return
        profile_value = self.r_saved_profile.current.value if self.r_saved_profile.current else None
        if not profile_value:
            self.r_status.current.value = tr("Save or select a profile before scheduling.")
            self.r_status.current.color = AMBER
            self._safe_page_update()
            return
        interval = ft.Dropdown(
            label="Interval", value="60",
            options=[ft.DropdownOption(value, tr(label)) for value, label in
                     (("15", "15 minutes"), ("30", "30 minutes"), ("60", "1 hour"),
                      ("360", "6 hours"), ("1440", "24 hours"))],
        )
        changes_only = ft.Switch(label="Notify only when relevant changes are detected", value=True)
        page = self._page[0]

        def close(e=None):
            close_dialog(page)

        def save(e=None):
            self.db.save_scan_schedule(
                int(profile_value), int(interval.value or "60"), bool(changes_only.value)
            )
            close()
            self._reload_profiles_and_schedules()
            self.r_status.current.value = tr("Scheduled scan created.")
            self.r_status.current.color = GREEN
            self._safe_page_update()

        dialog = ft.AlertDialog(
            modal=True, title=ft.Text("Schedule recurring scan"),
            content=ft.Column([interval, changes_only], spacing=10, tight=True),
            actions=[ft.TextButton("Cancel", on_click=close),
                     ft.Button(content="Create schedule", on_click=save)],
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    async def _execute_scan(self, target: str, profile: str):
        previous = self.db.get_latest_network_scan(target)
        scan = await asyncio.to_thread(
            self.scanner.scan, target, profile, self._cancel_event,
        )
        scan.findings.extend(compare_scans(previous, scan))
        self.db.save_network_scan(scan)
        return previous, scan

    def poll_schedules(self):
        """Dispatch one due schedule without blocking the real-time UI loop."""
        if self._running or self._schedule_dispatching or self._disposed:
            return
        due = self.db.list_due_schedules()
        if not due or not self._page or not self._page[0]:
            return
        self._schedule_dispatching = True
        self._page[0].run_task(self._run_scheduled_scan, due[0])

    async def _run_scheduled_scan(self, schedule: dict):
        self._running = True
        self._cancel_event = threading.Event()
        if self.r_scan.current:
            self.r_scan.current.disabled = True
            self.r_progress.current.visible = True
            self.r_status.current.value = tr(f"Scheduled scan: {schedule['name']}...")
            self.r_status.current.color = BLUE
            self._safe_page_update()
        try:
            previous, scan = await self._execute_scan(schedule["target"], schedule["profile"])
            self.db.mark_schedule_run(schedule["id"], True)
            if not self._disposed:
                self._render_scan(scan)
                self._reload_history(selected=scan.scan_id)
                self._reload_profiles_and_schedules()
                notification = scheduled_scan_message(
                    scan, bool(schedule["notify_changes_only"]),
                    [host.address for host in scan.hosts
                     if previous is None
                     and (self.db.get_inventory_device(host.address) or {}).get("trust_status") == "new"],
                )
                relevant = notification[1] if notification else []
                if notification and self._notification_sink:
                    message = notification[0]
                    self._notification_sink(f"Scheduled scan · {schedule['name']}", message)
                self.r_status.current.value = tr(
                    f"Scheduled scan completed · {len(scan.hosts)} devices · {len(relevant)} relevant changes"
                )
                self.r_status.current.color = GREEN
        except asyncio.CancelledError:
            return
        except Exception as exc:
            self.db.mark_schedule_run(schedule["id"], False, str(exc))
            self._reload_profiles_and_schedules()
            if self._notification_sink:
                self._notification_sink(
                    f"Scheduled scan failed · {schedule['name']}", str(exc)
                )
            if self.r_status.current:
                self.r_status.current.value = str(exc)
                self.r_status.current.color = RED
        finally:
            self._running = False
            self._schedule_dispatching = False
            if not self._disposed and self.r_scan.current:
                self.r_scan.current.disabled = False
                self.r_progress.current.visible = False
                self._safe_page_update()

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
            previous, scan = await self._execute_scan(target, profile)
            if self._disposed:
                return
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
        self._current_scan = scan
        self._selected_host = ""
        self.r_devices.current.value = str(len(scan.hosts))
        self.r_ports.current.value = str(scan.open_port_count)
        self.r_risk.current.value = tr(scan.risk_level.upper())
        self.r_risk.current.color = self._risk_color(scan.risk_level)
        previous = self.db.get_latest_network_scan(
            scan.target, before_id=scan.scan_id
        ) if scan.scan_id else None
        self._previous_scan = previous
        self._render_diagnostics(previous, scan)
        self._render_comparison(previous, scan)
        self._render_topology(scan)
        self._render_health(scan)
        self._render_asset_workspace(scan)
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
                    ink=True, tooltip="Explain risk and verification",
                    on_click=lambda e, address=host.address, item=service:
                        self._show_service_explanation(address, item),
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
                        ft.IconButton(
                            icon=ft.Icons.EDIT_NOTE_ROUNDED, icon_color=CYAN,
                            icon_size=17, tooltip="Edit device inventory",
                            on_click=lambda e, address=host.address: self._edit_inventory(address),
                        ),
                    ], spacing=8),
                    ft.Text(subtitle, size=10, color=DIM,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Row(service_controls, spacing=6, wrap=True, run_spacing=6),
                ], spacing=6),
                bgcolor=SURFACE, border=ft.Border.all(1, tint(color, .21)),
                border_radius=10, padding=10, ink=True,
                data=host.address, tooltip=f"View alerts for {host.address}",
                on_click=lambda e: self._select_host(e.control.data),
            ))
        if self.r_device_list.current:
            self.r_device_list.current.controls = device_controls or [
                ft.Text("No responding devices were found.", color=MUTED)
            ]

        if self.r_device_list.current:
            translate_tree(self.r_device_list.current, get_language())

    def _render_asset_workspace(self, scan):
        if not self.r_asset_list.current:
            return
        online_ids = {host.device_id for host in scan.hosts if host.device_id}
        summary = self.db.asset_attention_summary(online_ids)
        self.r_asset_summary.current.value = (
            f"{summary['new']} new · {summary['unclassified']} review pending · "
            f"{summary['critical']} critical · {summary['blocked_online']} blocked online · "
            f"{summary['missing']} missing · {summary['pending_merges']} possible duplicate(s)"
        )
        controls = []
        for item in sorted(
            self.db.list_inventory(),
            key=lambda asset: (
                asset["lifecycle_status"] not in {"blocked", "new"},
                asset["criticality"] not in {"critical", "high"},
                not asset["review_required"], asset["address"],
            ),
        ):
            status = item["lifecycle_status"]
            color = (RED if status == "blocked" else AMBER if status in {"new", "observing"}
                     else MUTED if status in {"retired", "stale"} else GREEN)
            controls.append(ft.Container(
                content=ft.Row([
                    ft.Container(
                        content=ft.Text(f"#{item['device_id']}", color=color, size=10,
                                        weight=ft.FontWeight.W_700),
                        width=48, alignment=ft.Alignment.CENTER,
                    ),
                    ft.Column([
                        ft.Text(item["alias"] or item["detected_name"] or item["address"],
                                color=TEXT, size=10, weight=ft.FontWeight.W_700),
                        ft.Text(
                            f"{item['address']} · {item['identity_confidence']} identity · "
                            f"{item['criticality']} criticality · {item['owner'] or 'unassigned'}",
                            color=MUTED, size=9,
                        ),
                    ], spacing=2, expand=True),
                    ft.Text(status.upper(), color=color, size=9,
                            weight=ft.FontWeight.W_700),
                    ft.IconButton(
                        icon=ft.Icons.EDIT_NOTE_ROUNDED, icon_color=CYAN, icon_size=16,
                        tooltip="Edit asset", on_click=lambda e, address=item["address"]:
                            self._edit_inventory(address),
                    ),
                ], spacing=8),
                bgcolor=tint(color, .035), border=ft.Border.all(1, tint(color, .14)),
                border_radius=8, padding=8,
            ))

        suggestions = self.db.list_merge_suggestions()
        if suggestions:
            controls.insert(0, ft.Text("POSSIBLE DUPLICATES — HUMAN REVIEW REQUIRED",
                                       color=AMBER, size=9, weight=ft.FontWeight.W_700))
        for suggestion in suggestions:
            reasons = ", ".join(suggestion["reasons"])
            controls.insert(1, ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.COMPARE_ARROWS_ROUNDED, color=AMBER, size=17),
                    ft.Column([
                        ft.Text(
                            f"#{suggestion['device_a_id']} {suggestion['alias_a'] or suggestion['address_a']} "
                            f"↔ #{suggestion['device_b_id']} {suggestion['alias_b'] or suggestion['address_b']}",
                            color=TEXT, size=10, weight=ft.FontWeight.W_700,
                        ),
                        ft.Text(f"{suggestion['score']}% · {reasons}", color=MUTED, size=9),
                    ], spacing=2, expand=True),
                    ft.Button(
                        "MERGE", color=GREEN, bgcolor=tint(GREEN, .10),
                        on_click=lambda e, s=suggestion: self._accept_asset_merge(s),
                    ),
                    ft.TextButton(
                        "DISMISS", on_click=lambda e, sid=suggestion["id"]:
                            self._dismiss_asset_merge(sid),
                    ),
                ], spacing=7),
                bgcolor=tint(AMBER, .045), border=ft.Border.all(1, tint(AMBER, .18)),
                border_radius=8, padding=8,
            ))

        merged = self.db.list_merged_assets()
        if merged:
            controls.append(ft.Text("MERGED ASSETS", color=MUTED, size=9,
                                    weight=ft.FontWeight.W_700))
        for link in merged:
            controls.append(ft.Row([
                ft.Text(
                    f"#{link['source_device_id']} {link['source_alias'] or link['source_address']} "
                    f"→ #{link['target_device_id']} {link['target_alias'] or link['target_address']}",
                    color=MUTED, size=9, expand=True,
                ),
                ft.TextButton(
                    "SEPARATE", on_click=lambda e, source=link["source_device_id"]:
                        self._separate_asset(source),
                ),
            ], spacing=7))
        self.r_asset_list.current.controls = controls or [
            ft.Text("No assets observed yet.", color=MUTED, size=10)
        ]

    def _accept_asset_merge(self, suggestion):
        self.db.merge_assets(
            suggestion["device_a_id"], suggestion["device_b_id"], suggestion["id"]
        )
        if self._current_scan:
            self._render_asset_workspace(self._current_scan)
            self._safe_page_update()

    def _dismiss_asset_merge(self, suggestion_id: int):
        self.db.dismiss_merge_suggestion(suggestion_id)
        if self._current_scan:
            self._render_asset_workspace(self._current_scan)
            self._safe_page_update()

    def _separate_asset(self, source_device_id: int):
        self.db.separate_asset(source_device_id)
        if self._current_scan:
            self._render_asset_workspace(self._current_scan)
            self._safe_page_update()

    def _render_health(self, scan):
        health = calculate_network_health(scan, self.db.list_inventory())
        color = GREEN if health.score >= 90 else BLUE if health.score >= 75 else AMBER if health.score >= 60 else RED
        self.r_health.current.value = f"{health.score}/100"
        self.r_health.current.color = color
        self.r_health_summary.current.value = tr(
            f"{health.score}/100 · {tr(health.level.upper())} · "
            f"{health.total_deduction} points deducted"
        )
        controls = []
        for factor in health.factors:
            factor_color = self._risk_color(factor.severity)
            controls.append(ft.Container(
                content=ft.Row([
                    ft.Container(
                        content=ft.Text(f"-{factor.deduction}", color=factor_color,
                                        size=12, weight=ft.FontWeight.W_700),
                        width=48, alignment=ft.Alignment.CENTER,
                    ),
                    ft.Column([
                        ft.Text(tr(factor.label), color=TEXT, size=10,
                                weight=ft.FontWeight.W_700),
                        ft.Text(tr(factor.explanation), color=MUTED, size=9),
                    ], spacing=2, expand=True),
                ], spacing=8),
                bgcolor=tint(factor_color, .035),
                border=ft.Border.all(1, tint(factor_color, .14)),
                border_radius=7, padding=8,
            ))
        self.r_health_factors.current.controls = controls or [
            ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.CHECK_CIRCLE_ROUNDED, color=GREEN, size=18),
                    ft.Text("No deductions. The scanned network is healthy according to current evidence.",
                            color=GREEN, size=10),
                ], spacing=7),
                bgcolor=tint(GREEN, .04), border_radius=7, padding=8,
            )
        ]
        translate_tree(self.r_health_factors.current, get_language())

    def _render_comparison(self, previous, current):
        comparison = compare_scan_details(previous, current)
        if not comparison.has_baseline:
            self.r_comparison_summary.current.value = tr("A previous scan is required for comparison.")
            self.r_comparison.current.controls = [
                ft.Text("Run the same target again to create a before-and-now comparison.",
                        color=MUTED, size=11)
            ]
            return
        delta_symbol = "+" if comparison.risk_delta > 0 else ""
        self.r_comparison_summary.current.value = tr(
            f"#{comparison.previous_id or '-'} → #{comparison.current_id or '-'} · "
            f"{comparison.total_changes} changes · risk {delta_symbol}{comparison.risk_delta}"
        )

        def metric(title, before, now, color):
            return ft.Container(
                content=ft.Column([
                    ft.Text(title, size=9, color=MUTED, weight=ft.FontWeight.W_600),
                    ft.Row([
                        ft.Text(str(before), size=18, color=DIM, weight=ft.FontWeight.W_700),
                        ft.Icon(ft.Icons.ARROW_FORWARD_ROUNDED, size=15, color=color),
                        ft.Text(str(now), size=18, color=color, weight=ft.FontWeight.W_700),
                    ], spacing=7),
                ], spacing=3),
                bgcolor=SURFACE, border=ft.Border.all(1, tint(color, .18)),
                border_radius=8, padding=9, width=180,
            )

        details = []
        for address in comparison.new_devices:
            details.append(("NEW DEVICE", address, "Detected now", AMBER))
        for address in comparison.missing_devices:
            details.append(("MISSING DEVICE", address, "No longer responds", MUTED))
        for change in comparison.address_changes:
            details.append(("IP CHANGED", change.current_address,
                            f"{change.previous_address} → {change.current_address} · {change.mac}", BLUE))
        for change in comparison.port_changes:
            color = GREEN if change.change == "closed" else self._risk_color(change.severity)
            details.append((f"PORT {change.change.upper()}", change.address,
                            f"{change.port}/{change.protocol} · {change.service}", color))

        change_controls = [ft.Container(
            content=ft.Row([
                ft.Text(tr(kind), color=color, size=9, weight=ft.FontWeight.W_700, width=105),
                ft.Text(address, color=TEXT, size=10, font_family="monospace", width=125),
                ft.Text(tr(detail), color=MUTED, size=10, expand=True),
            ], spacing=7),
            bgcolor=tint(color, .035), border_radius=6,
            border=ft.Border.all(1, tint(color, .13)), padding=7,
        ) for kind, address, detail, color in details]
        self.r_comparison.current.controls = [
            ft.Row([
                metric("DEVICES", comparison.previous_hosts, comparison.current_hosts, CYAN),
                metric("OPEN PORTS", comparison.previous_ports, comparison.current_ports, GREEN),
                metric("RISK SCORE", comparison.previous_risk, comparison.current_risk,
                       RED if comparison.risk_delta > 0 else GREEN),
            ], spacing=8, wrap=True, run_spacing=8),
            ft.Column(change_controls or [
                ft.Text("No topology or port changes detected.", color=MUTED, size=11)
            ], spacing=6),
        ]
        translate_tree(self.r_comparison.current, get_language())

    def _show_service_explanation(self, address, service):
        if not self._page or not self._page[0]:
            return
        explanation = explain_service(address, service)
        color = self._risk_color(explanation.risk)
        page = self._page[0]

        def close(e=None):
            close_dialog(page)

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.SECURITY_ROUNDED, color=color),
                ft.Text(explanation.title, color=TEXT, size=15,
                        weight=ft.FontWeight.W_700),
            ]),
            content=ft.Container(content=ft.Column([
                ft.Text(f"Device: {address}", color=CYAN, size=11, font_family="monospace"),
                ft.Text("WHY IT MATTERS", color=MUTED, size=9, weight=ft.FontWeight.W_700),
                ft.Text(explanation.why, color=TEXT, size=11),
                ft.Text("RECOMMENDED ACTION", color=MUTED, size=9, weight=ft.FontWeight.W_700),
                ft.Text(explanation.recommendation, color=color, size=11),
                ft.Text("SAFE VERIFICATION", color=MUTED, size=9, weight=ft.FontWeight.W_700),
                ft.Container(
                    content=ft.Text(explanation.verification, color=CYAN, size=11,
                                    font_family="monospace", selectable=True),
                    bgcolor=SURFACE, border_radius=6, padding=8,
                ),
                ft.Text("Run verification only on networks you are authorized to assess.",
                        color=AMBER, size=9),
            ], spacing=8), width=520),
            actions=[ft.TextButton("Close", on_click=close)],
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    def _show_global_search(self, query: str):
        if not query or not self._page or not self._page[0]:
            return
        results = self.db.search_global(query)
        if self._state:
            needle = query.lower()
            for process, metrics in self._state.proc_traffic.items():
                if needle in process.lower():
                    results.append({
                        "category": "process", "label": process, "value": process,
                        "detail": f"{metrics.get('b', 0):,} bytes · {metrics.get('p', 0):,} packets",
                    })
        category_colors = {
            "inventory": CYAN, "service": AMBER, "traffic": PURPLE, "process": GREEN,
        }
        controls = []
        for result in results[:50]:
            color = category_colors.get(result["category"], MUTED)
            controls.append(ft.Container(
                content=ft.Row([
                    ft.Text(result["category"].upper(), color=color, size=8,
                            weight=ft.FontWeight.W_700, width=70),
                    ft.Column([
                        ft.Text(result["label"], color=TEXT, size=11,
                                weight=ft.FontWeight.W_600),
                        ft.Text(result["detail"] or result["value"], color=MUTED, size=9),
                    ], spacing=2, expand=True),
                    ft.Text(result["value"], color=CYAN, size=9, font_family="monospace"),
                ], spacing=8),
                bgcolor=tint(color, .035), border=ft.Border.all(1, tint(color, .13)),
                border_radius=7, padding=8,
            ))
        page = self._page[0]

        def close(e=None):
            close_dialog(page)

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(f"Global search · {query}"),
            content=ft.Container(
                content=ft.Column(controls or [ft.Text("No matching results.", color=MUTED)],
                                  spacing=6, scroll=ft.ScrollMode.AUTO),
                width=650, height=min(520, max(120, 72 * max(1, len(controls)))),
            ),
            actions=[ft.TextButton("Close", on_click=close)],
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    async def _export_current_reports(self):
        if not self._current_scan or not self._page or not self._page[0]:
            if self.r_status.current:
                self.r_status.current.value = tr("Select a scan before exporting.")
                self.r_status.current.color = AMBER
                self._safe_page_update()
            return
        scan = self._current_scan
        previous = self.db.get_latest_network_scan(
            scan.target, before_id=scan.scan_id
        ) if scan.scan_id else None
        try:
            self.r_status.current.value = tr("Generating PDF, HTML and CSV reports...")
            self.r_status.current.color = CYAN
            self._safe_page_update()
            paths = await asyncio.to_thread(
                export_scan_reports, scan, previous, self.db.list_inventory(),
                PROJECT_ROOT / "exports",
            )
            self.r_status.current.value = tr("Reports exported to exports folder.")
            self.r_status.current.color = GREEN
            page = self._page[0]

            def close(e=None):
                close_dialog(page)

            dialog = ft.AlertDialog(
                title=ft.Text("Reports exported"),
                content=ft.Column([
                    ft.Text(f"{kind.upper()}: {path}", selectable=True, size=10,
                            color=CYAN if kind == "pdf" else TEXT)
                    for kind, path in paths.items()
                ], spacing=7, tight=True),
                actions=[ft.TextButton("Close", on_click=close)],
            )
            translate_tree(dialog, get_language())
            open_dialog(page, dialog)
        except Exception as exc:
            self.r_status.current.value = f"Report export failed: {exc}"
            self.r_status.current.color = RED
            self._safe_page_update()

    def _render_topology(self, scan):
        inventory = self.db.list_inventory()
        hosts_by_address = {host.address: host for host in scan.hosts}
        local_addresses = {
            item.get("ip", "") for item in list_interfaces() if item.get("ip")
        }
        segments = build_topology(scan, inventory, local_addresses)
        self._topology_nodes = []
        self._topology_grids = []
        total_nodes = sum(len(segment.nodes) for segment in segments)
        self.r_topology_summary.current.value = tr(
            f"{len(segments)} segments · {total_nodes} nodes · select a node to filter alerts"
        )
        self._interactive_topology = NetworkTopologyMap(
            segments, hosts_by_address,
            on_select=self._select_topology_host,
            on_edit=self._edit_inventory,
            on_explain=self._show_service_explanation,
        ) if segments else None
        self.r_topology.current.controls = (
            [self._interactive_topology.control] if self._interactive_topology else
            [ft.Text("No responding devices were found.", color=MUTED)]
        )
        if self._interactive_topology:
            self._interactive_topology.resize(max(280.0, self._viewport_content_width - 28.0))
        translate_tree(self.r_topology.current, get_language())

    def _edit_inventory(self, address: str):
        device = self.db.get_inventory_device(address)
        if not device or not self._page or not self._page[0]:
            return
        ip_history = self.db.list_device_ip_history(address)
        previous_addresses = [item["address"] for item in ip_history
                              if item["address"] != address]
        def styled_field(label, value, icon, **kwargs):
            return ft.TextField(
                label=label, value=value, prefix_icon=icon,
                color=TEXT, cursor_color=CYAN,
                label_style=ft.TextStyle(color=MUTED, size=10),
                filled=True, fill_color=tint(CYAN, .035),
                border_color=BORDER, focused_border_color=CYAN,
                focused_border_width=1.5, border_radius=9,
                content_padding=ft.padding.Padding.symmetric(horizontal=12, vertical=10),
                **kwargs,
            )

        alias = styled_field("Custom name", device.get("alias") or "",
                             ft.Icons.BADGE_OUTLINED)
        device_type = styled_field("Device type", device.get("device_type") or "unknown",
                                   ft.Icons.DEVICES_OTHER_ROUNDED)
        owner = styled_field("Owner", device.get("owner") or "",
                             ft.Icons.PERSON_OUTLINE_ROUNDED)
        location = styled_field("Location", device.get("location") or "",
                                ft.Icons.LOCATION_ON_OUTLINED)
        notes = styled_field("Notes", device.get("notes") or "",
                             ft.Icons.NOTES_ROUNDED, multiline=True,
                             min_lines=2, max_lines=4)
        trust = ft.Dropdown(
            label="Trust status", value=device.get("trust_status") or "new",
            options=[ft.DropdownOption(value, tr(value.upper())) for value in
                     ("new", "known", "authorized", "blocked")],
            leading_icon=ft.Icons.VERIFIED_USER_OUTLINED,
            color=TEXT, label_style=ft.TextStyle(color=MUTED, size=10),
            filled=True, fill_color=CARD, bgcolor=CARD,
            menu_style=ft.MenuStyle(
                bgcolor=CARD, elevation=16,
                shape=ft.RoundedRectangleBorder(radius=9),
            ),
            border_color=BORDER, focused_border_color=CYAN,
            focused_border_width=1.5, border_radius=9,
            content_padding=ft.padding.Padding.symmetric(horizontal=12, vertical=10),
        )
        original_trust = device.get("trust_status") or "new"
        original_lifecycle = device.get("lifecycle_status") or "new"
        lifecycle = ft.Dropdown(
            label="Asset lifecycle", value=original_lifecycle,
            options=[ft.DropdownOption(value, tr(value.upper())) for value in
                     ("new", "observing", "authorized", "blocked", "retired", "stale")],
            leading_icon=ft.Icons.AUTORENEW_ROUNDED, color=TEXT,
            filled=True, fill_color=CARD, bgcolor=CARD,
            menu_style=ft.MenuStyle(
                bgcolor=CARD, elevation=16,
                shape=ft.RoundedRectangleBorder(radius=9),
            ),
            border_color=BORDER, focused_border_color=CYAN,
        )
        criticality = ft.Dropdown(
            label="Business criticality", value=device.get("criticality") or "medium",
            options=[ft.DropdownOption(value, tr(value.upper())) for value in
                     ("low", "medium", "high", "critical")],
            leading_icon=ft.Icons.PRIORITY_HIGH_ROUNDED, color=TEXT,
            filled=True, fill_color=CARD, bgcolor=CARD,
            menu_style=ft.MenuStyle(
                bgcolor=CARD, elevation=16,
                shape=ft.RoundedRectangleBorder(radius=9),
            ),
            border_color=BORDER, focused_border_color=AMBER,
        )
        tags = styled_field("Tags (comma separated)", device.get("tags") or "",
                            ft.Icons.LABEL_OUTLINE_ROUNDED)
        observations = self.db.list_asset_observations(device["device_id"])
        events = self.db.list_asset_events(device["device_id"], limit=5)
        evidence_text = " · ".join(
            f"{kind}: {sum(item['kind'] == kind for item in observations)}"
            for kind in ("ip", "mac", "hostname", "vendor", "os", "service")
            if any(item["kind"] == kind for item in observations)
        ) or "No identity evidence"
        event_text = "\n".join(
            f"{item['occurred_at'][:16]} · {item['summary']}" for item in events
        ) or "No asset events yet"
        page = self._page[0]

        def close(e=None):
            close_dialog(page)
            page.update()

        def save(e=None):
            selected_lifecycle = lifecycle.value or "new"
            if trust.value != original_trust and selected_lifecycle == original_lifecycle:
                selected_lifecycle = {
                    "new": "new", "known": "observing", "authorized": "authorized",
                    "blocked": "blocked",
                }.get(trust.value, selected_lifecycle)
            self.db.update_inventory_device(
                address, alias=alias.value or "", device_type=device_type.value or "unknown",
                owner=owner.value or "", location=location.value or "",
                notes=notes.value or "", trust_status=trust.value or "new",
                lifecycle_status=selected_lifecycle,
                criticality=criticality.value or "medium", tags=tags.value or "",
                reviewed=True,
            )
            close()
            if self._current_scan:
                self._render_scan(self._current_scan)
                self._safe_page_update()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Container(
                    content=ft.Icon(ft.Icons.EDIT_NOTE_ROUNDED, color=CYAN, size=22),
                    bgcolor=tint(CYAN, .09), border_radius=10, padding=8,
                ),
                ft.Column([
                    ft.Text("EDIT DEVICE INVENTORY", color=TEXT, size=13,
                            weight=ft.FontWeight.W_700),
                    ft.Text(address, color=CYAN, size=10, font_family="monospace"),
                ], spacing=1),
            ], spacing=10),
            content=ft.Container(
                content=ft.Column([
                    ft.Container(
                        content=ft.Row([
                            ft.Icon(ft.Icons.SWAP_HORIZ_ROUNDED, color=CYAN, size=17),
                            ft.Column([
                                ft.Text("CURRENT IP", color=MUTED, size=8,
                                        weight=ft.FontWeight.W_700),
                                ft.Text(address, color=CYAN, size=10,
                                        font_family="monospace"),
                                ft.Text(
                                    tr("Previous IPs: ") + ", ".join(previous_addresses),
                                    color=MUTED, size=9, font_family="monospace",
                                    visible=bool(previous_addresses),
                                ),
                            ], spacing=2),
                        ], spacing=8),
                        bgcolor=tint(CYAN, .04), border=ft.Border.all(1, tint(CYAN, .14)),
                        border_radius=8, padding=9,
                    ),
                    ft.Text("Identification and responsibility", color=MUTED, size=9,
                            weight=ft.FontWeight.W_700),
                    alias, device_type, owner, location,
                    ft.Text("Classification and notes", color=MUTED, size=9,
                            weight=ft.FontWeight.W_700),
                    trust, notes,
                    ft.Text("Enterprise asset management", color=MUTED, size=9,
                            weight=ft.FontWeight.W_700),
                    lifecycle, criticality, tags,
                    ft.Container(
                        content=ft.Column([
                            ft.Text(
                                f"IDENTITY CONFIDENCE: {(device.get('identity_confidence') or 'low').upper()}",
                                color=CYAN, size=9, weight=ft.FontWeight.W_700,
                            ),
                            ft.Text(evidence_text, color=MUTED, size=9),
                            ft.Text("RECENT ASSET EVENTS", color=MUTED, size=8,
                                    weight=ft.FontWeight.W_700),
                            ft.Text(event_text, color=MUTED, size=8, selectable=True),
                        ], spacing=4),
                        bgcolor=tint(CYAN, .035), border=ft.Border.all(1, tint(CYAN, .14)),
                        border_radius=8, padding=9,
                    ),
                ], spacing=10, scroll=ft.ScrollMode.AUTO),
                width=540, height=620,
            ),
            actions=[ft.TextButton("Cancel", on_click=close),
                     ft.Button(content="Save device", icon=ft.Icons.SAVE_ROUNDED,
                               color=CYAN, bgcolor=tint(CYAN, .12), on_click=save)],
            bgcolor=SURFACE, barrier_color="#66000000", elevation=18,
            shape=ft.RoundedRectangleBorder(radius=14),
            actions_padding=ft.padding.Padding.only(left=18, right=18, bottom=14),
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    def _select_host(self, address: str):
        if not self._current_scan or not address:
            return
        self._selected_host = address
        self._show_host_alerts_dialog(address)

    def _select_topology_host(self, address: str):
        """Select a map node without covering its inline detail panel."""
        if address:
            self._selected_host = address

    def _host_alert_controls(self, address: str):
        alert_controls = []
        severity_order = {"high": 0, "medium": 1, "low": 2}
        for finding in sorted(
            findings_for_host(self._current_scan, address),
            key=lambda item: severity_order.get(item.severity, 3)
        ):
            color = self._risk_color(finding.severity)
            alert_controls.append(ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=color, size=15),
                        ft.Text(tr(finding.title), color=TEXT, size=11,
                                weight=ft.FontWeight.W_600, expand=True),
                        ft.Text(finding.host, color=color, size=9,
                                font_family="monospace"),
                    ], spacing=6),
                    ft.Text(tr(finding.detail), size=10, color=MUTED),
                ], spacing=4),
                bgcolor=tint(color, .06), border=ft.Border.all(1, tint(color, .19)),
                border_radius=8, padding=9,
            ))
        return alert_controls or [
            ft.Text("No alerts or changes for this device.", color=GREEN, size=11)
        ]

    def _show_host_alerts_dialog(self, address: str):
        if not self._page or not self._page[0]:
            return
        page = self._page[0]

        def close(_=None):
            close_dialog(page)

        host = next((item for item in self._current_scan.hosts
                     if item.address == address), None)
        inventory = self.db.get_inventory_device(address) or {}
        diagnostics = [
            item for item in build_diagnostics(
                getattr(self, "_previous_scan", None), self._current_scan
            ).items if item.host == address
        ]
        risk_color = self._risk_color(host.risk_level if host else "low")
        identity = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Text(inventory.get("alias") or (host.hostname if host else "")
                            or "Unidentified device", color=TEXT, size=12,
                            weight=ft.FontWeight.W_700, expand=True),
                    ft.Text(tr((inventory.get("trust_status") or "new").upper()),
                            color=CYAN, size=9, weight=ft.FontWeight.W_700),
                ]),
                ft.Text(" | ".join(filter(None, [
                    host.mac if host else "", host.vendor if host else "",
                    host.os_name if host else "", inventory.get("location") or "",
                ])) or tr("No additional inventory data."), color=MUTED, size=9),
                ft.Row([
                    ft.Text(tr("RISK LEVEL"), color=MUTED, size=9),
                    ft.Text(tr((host.risk_level if host else "low").upper()),
                            color=risk_color, size=10, weight=ft.FontWeight.W_700),
                    ft.Text(f"{host.risk_score if host else 0}/100",
                            color=risk_color, size=10),
                ], spacing=7),
            ], spacing=5),
            bgcolor=tint(CYAN, .04), border=ft.Border.all(1, tint(CYAN, .16)),
            border_radius=8, padding=10,
        )
        services = []
        for service in (host.open_ports if host else []):
            color = self._risk_color(service.risk_level)
            services.append(ft.Container(
                content=ft.Column([
                    ft.Text(f"{service.port}/{service.protocol} · {service.name}",
                            color=color, size=10, weight=ft.FontWeight.W_700),
                    ft.Text(service.fingerprint or service.risk_reason or
                            tr("No additional service details."), color=MUTED, size=9),
                ], spacing=2),
                bgcolor=tint(color, .045), border=ft.Border.all(1, tint(color, .16)),
                border_radius=7, padding=8,
            ))
        diagnostic_controls = []
        for item in diagnostics:
            resolved = item.status == "resolved"
            color = GREEN if resolved else self._risk_color(item.severity)
            diagnostic_controls.append(ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Text(tr(item.title), color=TEXT, size=10,
                                weight=ft.FontWeight.W_700, expand=True),
                        ft.Text(tr("RESOLVED" if resolved else item.severity.upper()),
                                color=color, size=9, weight=ft.FontWeight.W_700),
                    ]),
                    ft.Text(tr("Why: " + item.why), color=MUTED, size=9),
                    ft.Text(tr("Recommended action: " + item.recommendation),
                            color=color, size=9),
                    ft.Text(tr("Evidence: " + item.evidence), color=DIM, size=8,
                            visible=bool(item.evidence)),
                ], spacing=4),
                bgcolor=tint(color, .045), border=ft.Border.all(1, tint(color, .16)),
                border_radius=8, padding=9,
            ))
        details = ft.Column([
            identity,
            ft.Text("OPEN PORTS AND SERVICES", color=MUTED, size=9,
                    weight=ft.FontWeight.W_700),
            *(services or [ft.Text("No open ports in this scan profile",
                                   color=GREEN, size=10)]),
            ft.Text("DIAGNOSIS AND RECOMMENDATIONS", color=MUTED, size=9,
                    weight=ft.FontWeight.W_700),
            *(diagnostic_controls or [ft.Text(
                "No alerts or changes for this device.", color=GREEN, size=10
            )]),
        ], spacing=8, scroll=ft.ScrollMode.AUTO)
        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED, color=AMBER, size=22),
                ft.Column([
                    ft.Text("ALERTS AND CHANGES", color=TEXT, size=13,
                            weight=ft.FontWeight.W_700),
                    ft.Text(address, color=CYAN, size=10, font_family="monospace"),
                ], spacing=1),
            ], spacing=9),
            content=ft.Container(
                content=details,
                width=560,
                height=420,
                padding=ft.padding.Padding.only(top=4),
            ),
            actions=[ft.TextButton("Close", on_click=close)],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    def _render_host_alerts(self, address: str):
        """Refreshes the legacy alert target when it is mounted."""
        if not self.r_alert_list.current:
            return
        self.r_alert_list.current.controls = self._host_alert_controls(address)
        translate_tree(self.r_alert_list.current, get_language())

    def _render_diagnostics(self, previous, scan):
        summary = build_diagnostics(previous, scan)
        priority = summary.priority
        if priority:
            self.r_diagnostic_summary.current.value = (
                f"Priority: {priority.title} · {summary.active_issues} active · "
                f"{summary.resolved_issues} resolved"
            )
        elif summary.resolved_issues:
            self.r_diagnostic_summary.current.value = (
                f"No active issues · {summary.resolved_issues} resolved"
            )
        else:
            self.r_diagnostic_summary.current.value = "No relevant changes detected."

        group_specs = [
            ("CRITICAL ISSUES", "high", "active", RED, ft.Icons.ERROR_OUTLINE_ROUNDED),
            ("REQUIRES ATTENTION", "medium", "active", AMBER, ft.Icons.WARNING_AMBER_ROUNDED),
            ("INFORMATIONAL", "low", "active", BLUE, ft.Icons.INFO_OUTLINE_ROUNDED),
            ("RESOLVED ISSUES", None, "resolved", GREEN, ft.Icons.CHECK_CIRCLE_OUTLINE_ROUNDED),
        ]
        controls = []
        for label, severity, status, color, icon in group_specs:
            items = [item for item in summary.items
                     if item.status == status and (severity is None or item.severity == severity)]
            if not items:
                continue
            hosts = []
            for address in dict.fromkeys(item.host for item in items):
                host_items = [item for item in items if item.host == address]
                previews = [ft.Container(
                    content=ft.Row([
                        ft.Text(tr(item.title), color=TEXT, size=10, expand=True),
                        ft.Text(tr("RESOLVED" if item.status == "resolved"
                                   else item.severity.upper()), color=color, size=8,
                                weight=ft.FontWeight.W_700),
                    ], spacing=6),
                    bgcolor=tint(color, .035), border_radius=6, padding=7,
                ) for item in host_items]
                hosts.append(ft.ExpansionTile(
                    title=ft.Text(address, color=CYAN, size=10,
                                  font_family="monospace", weight=ft.FontWeight.W_700),
                    subtitle=ft.Text(tr(f"{len(host_items)} findings"), color=MUTED, size=9),
                    leading=ft.Icon(ft.Icons.DEVICES_OTHER_ROUNDED, color=color, size=17),
                    controls=[ft.Column([
                        *previews,
                        ft.Row([
                            ft.Container(expand=True),
                            ft.Button(
                                content=tr("View device details"),
                                icon=ft.Icons.OPEN_IN_NEW_ROUNDED,
                                on_click=lambda e, host_address=address:
                                    self._select_host(host_address),
                            ),
                        ]),
                    ], spacing=6)],
                    controls_padding=ft.padding.Padding.only(left=10, right=8, bottom=8),
                    tile_padding=ft.padding.Padding.symmetric(horizontal=6, vertical=1),
                    text_color=TEXT, icon_color=color, collapsed_text_color=TEXT,
                    collapsed_icon_color=color, maintain_state=True, expanded=False,
                ))
            controls.append(ft.Container(
                content=ft.ExpansionTile(
                    title=ft.Text(tr(label), color=color, size=10,
                                  weight=ft.FontWeight.W_700),
                    subtitle=ft.Text(tr(f"{len(items)} findings in {len(hosts)} devices"),
                                     color=MUTED, size=9),
                    leading=ft.Icon(icon, color=color, size=18),
                    controls=hosts,
                    controls_padding=ft.padding.Padding.only(left=8, right=8, bottom=8),
                    tile_padding=ft.padding.Padding.symmetric(horizontal=6, vertical=1),
                    text_color=TEXT, icon_color=color, collapsed_text_color=TEXT,
                    collapsed_icon_color=color, maintain_state=True,
                    expanded=(label == "CRITICAL ISSUES"),
                ),
                bgcolor=tint(color, .03), border=ft.Border.all(1, tint(color, .14)),
                border_radius=8,
            ))
        self.r_diagnostic_list.current.controls = controls or [
            ft.Text("No active or recently resolved issues.", color=GREEN, size=11)
        ]
        translate_tree(self.r_diagnostic_list.current, get_language())

    def _reload_history(self, selected=None):
        if not self.r_history.current:
            return
        scans = self.db.list_network_scans()
        self.r_history.current.options = [
            ft.DropdownOption(
                key=str(scan["id"]),
                text=tr(f"#{scan['id']} {scan['started_at'][:16]} · {scan['target']} · "
                        f"{scan['host_count']} hosts · {scan['risk_level']}")
            )
            for scan in scans
        ]
        if selected:
            self.r_history.current.value = str(selected)

    def on_mount(self):
        self._reload_history()

    def _reset_scan_results(self):
        """Clear the displayed snapshot without deleting stored scan history."""
        self._current_scan = None
        self._previous_scan = None
        self._selected_host = ""
        for ref, value in (
            (self.r_devices, "0"), (self.r_ports, "0"),
            (self.r_risk, "—"), (self.r_changes, "0"),
            (self.r_health, "—"),
        ):
            if ref.current:
                ref.current.value = value
        if self.r_risk.current:
            self.r_risk.current.color = MUTED
        if self.r_health_summary.current:
            self.r_health_summary.current.value = "Run a scan to calculate network health."
        if self.r_health_factors.current:
            self.r_health_factors.current.controls = [
                ft.Text("No health assessment yet.", color=MUTED, size=10)
            ]
        if self.r_diagnostic_summary.current:
            self.r_diagnostic_summary.current.value = "Run two scans to compare changes."
        if self.r_diagnostic_list.current:
            self.r_diagnostic_list.current.controls = [
                ft.Text("No diagnostic information yet.", color=MUTED, size=11)
            ]
        if self.r_comparison_summary.current:
            self.r_comparison_summary.current.value = (
                "A previous scan is required for comparison."
            )
        if self.r_comparison.current:
            self.r_comparison.current.controls = [
                ft.Text("No comparison available.", color=MUTED, size=11)
            ]
        if self.r_topology_summary.current:
            self.r_topology_summary.current.value = "Segments and connections overview"
        if self.r_topology.current:
            self.r_topology.current.controls = [
                ft.Text("Run a scan to build the network map.", color=MUTED)
            ]
        if self.r_asset_summary.current:
            self.r_asset_summary.current.value = "Run a scan to build the asset inventory."
        if self.r_asset_list.current:
            self.r_asset_list.current.controls = [
                ft.Text("No assets observed yet.", color=MUTED, size=10)
            ]
        translate_tree(self._network_tabs, get_language())


# ── 3. LOCAL PORTS ─────────────────────────────────────────────────────

class LocalPortsView:
    """Dedicated, read-only view of services listening on this computer."""

    def __init__(self, page_ref):
        self._page = page_ref
        self.r_list = ft.Ref[ft.ListView]()
        self.r_total = ft.Ref[ft.Text]()
        self.r_exposed = ft.Ref[ft.Text]()
        self.r_attention = ft.Ref[ft.Text]()
        self.r_search = ft.Ref[ft.TextField]()
        self.r_filter = ft.Ref[ft.Dropdown]()
        self.r_match_count = ft.Ref[ft.Text]()
        self.r_refresh_status = ft.Ref[ft.Text]()
        self._listeners = []
        self._filtered = []
        self._summary_cards = []
        self._toolbar = None
        self._search_field = None
        self._results = None
        self._refresh_button = None
        self._refresh_spinner = None
        self._refreshing = False
        self._minimum_refresh_indicator_seconds = 1.0
        self._layout_key = None

    def build(self):
        async def on_refresh(_):
            await self.refresh_async()

        def metric(label, ref, color, icon):
            return card(ft.Row([
                ft.Container(ft.Icon(icon, color=color, size=25),
                             bgcolor=tint(color, .08), border_radius=11, padding=9),
                ft.Column([
                    ft.Text(label, color=MUTED, size=9, weight=ft.FontWeight.W_700),
                    ft.Text(ref=ref, value="0", color=color, size=22,
                            weight=ft.FontWeight.W_700, font_family="monospace"),
                ], spacing=1),
            ], spacing=9), padding=12)

        self._summary_cards = [
            metric("LISTENING PORTS", self.r_total, CYAN, ft.Icons.SENSORS_ROUNDED),
            metric("NETWORK VISIBLE", self.r_exposed, AMBER, ft.Icons.PUBLIC_ROUNDED),
            metric("REQUIRE ATTENTION", self.r_attention, RED,
                   ft.Icons.WARNING_AMBER_ROUNDED),
        ]
        self._refresh_button = ft.Button(
            content="REFRESH", icon=ft.Icons.REFRESH_ROUNDED,
            color=PURPLE, bgcolor=tint(PURPLE, .11),
            on_click=on_refresh,
        )
        self._refresh_spinner = ft.ProgressRing(
            width=18, height=18, stroke_width=2, color=PURPLE,
            visible=False,
        )
        self._search_field = ft.TextField(
            ref=self.r_search, label="Port, process, service or address",
            prefix_icon=ft.Icons.SEARCH_ROUNDED, width=360,
            filled=True, fill_color=tint(CYAN, .025), border_color=BORDER,
            focused_border_color=CYAN, border_radius=8,
            on_change=lambda e: self._render(),
        )
        self._toolbar = card(ft.Row([
            self._search_field,
            ft.Dropdown(
                ref=self.r_filter, label="Exposure filter", value="all", width=210,
                options=[ft.DropdownOption(key, tr(label)) for key, label in (
                    ("all", "All listeners"), ("exposed", "Network visible"),
                    ("attention", "Require attention"), ("local", "Local only"),
                )],
                filled=True, fill_color=tint(PURPLE, .025), border_color=BORDER,
                focused_border_color=PURPLE, border_radius=8,
                on_select=lambda e: self._render(),
            ),
            self._refresh_spinner,
            self._refresh_button,
            ft.Text(ref=self.r_refresh_status, value="Not updated yet",
                    color=MUTED, size=9),
        ], spacing=10, wrap=True, run_spacing=8), padding=10)
        self._results = card(ft.Column([
            ft.Row([
                section_title("PORTS OPEN ON THIS COMPUTER"),
                ft.Container(expand=True),
                ft.Text(ref=self.r_match_count,
                        value="Press Refresh to inspect local ports.",
                        color=MUTED, size=9),
            ]),
            ft.Text("A listening port is not automatically dangerous. Review the process and whether it is visible from the network.",
                    color=MUTED, size=9),
            ft.ListView(ref=self.r_list, spacing=6, expand=True, padding=2,
                        scroll=ft.ScrollMode.AUTO, build_controls_on_demand=False),
        ], spacing=8, expand=True), padding=12, expand=True)
        return ft.Column([
            view_heading("Local ports", "Processes and services listening on this computer",
                         ft.Icons.PRIVACY_TIP_OUTLINED, PURPLE),
            ft.Row(self._summary_cards, spacing=12, wrap=True, run_spacing=12),
            self._toolbar, self._results,
        ], spacing=12, expand=True)

    def refresh(self, background=False):
        # Protect against double-clicks and queued events while psutil is
        # enumerating system sockets.
        if self._refreshing:
            return
        self._refreshing = True
        page = self._page[0] if self._page and self._page[0] else None
        if self._refresh_button:
            self._refresh_button.disabled = True
            self._refresh_button.icon = None
            self._refresh_button.content = tr("UPDATING...")
        if self._refresh_spinner:
            self._refresh_spinner.visible = True
        if self.r_refresh_status.current:
            self.r_refresh_status.current.value = tr("Inspecting local listeners...")
            self.r_refresh_status.current.color = CYAN
        if page:
            page.update()
        self._finish_refresh(page, time.monotonic(), False)

    async def refresh_async(self):
        """Refresh without blocking Flutter's desktop event loop."""
        if self._refreshing:
            return
        self._refreshing = True
        page = self._page[0] if self._page and self._page[0] else None
        if self._refresh_button:
            self._refresh_button.disabled = True
            self._refresh_button.icon = None
            self._refresh_button.content = tr("UPDATING...")
        if self._refresh_spinner:
            self._refresh_spinner.visible = True
        if self.r_refresh_status.current:
            self.r_refresh_status.current.value = tr("Inspecting local listeners...")
            self.r_refresh_status.current.color = CYAN
        if page:
            page.update()
        started_at = time.monotonic()
        try:
            listeners = await asyncio.to_thread(list_local_listeners)
            remaining = self._minimum_refresh_indicator_seconds - (
                time.monotonic() - started_at
            )
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._finish_refresh(page, started_at, False, listeners)
        except Exception as exc:
            self._finish_refresh(page, started_at, False, error=exc)

    def _finish_refresh(self, page=None, started_at=None, keep_indicator_visible=False,
                        listeners=None, error=None):
        try:
            if error is not None:
                raise error
            self._listeners = listeners if listeners is not None else list_local_listeners()
            self.r_total.current.value = str(len(self._listeners))
            self.r_exposed.current.value = str(sum(item.exposure != "local" for item in self._listeners))
            self.r_attention.current.value = str(sum(
                item.risk_level in {"high", "medium"} for item in self._listeners
            ))
            self._render()
            if self.r_refresh_status.current:
                stamp = datetime.now().strftime("%H:%M:%S")
                self.r_refresh_status.current.value = tr(
                    f"Updated at {stamp} · {len(self._listeners)} listening ports found"
                )
                self.r_refresh_status.current.color = GREEN
        except Exception as exc:
            if self.r_refresh_status.current:
                self.r_refresh_status.current.value = tr(f"Update failed: {exc}")
                self.r_refresh_status.current.color = RED
        finally:
            if keep_indicator_visible and started_at is not None:
                remaining = self._minimum_refresh_indicator_seconds - (
                    time.monotonic() - started_at
                )
                if remaining > 0:
                    time.sleep(remaining)
            if self._refresh_button:
                self._refresh_button.disabled = False
                self._refresh_button.icon = ft.Icons.REFRESH_ROUNDED
                self._refresh_button.content = tr("REFRESH")
            if self._refresh_spinner:
                self._refresh_spinner.visible = False
            self._refreshing = False
            if page:
                page.update()

    def _render(self):
        query = ((self.r_search.current.value if self.r_search.current else "") or "").lower()
        selected = self.r_filter.current.value if self.r_filter.current else "all"
        exposure_labels = {"local": "This computer only",
                           "all_interfaces": "All network interfaces",
                           "network_interface": "Specific network interface"}
        filtered = []
        for item in self._listeners:
            haystack = f"{item.port} {item.protocol} {item.process} {item.service} {item.address}".lower()
            if query and query not in haystack:
                continue
            if selected == "exposed" and item.exposure == "local":
                continue
            if selected == "attention" and item.risk_level == "low":
                continue
            if selected == "local" and item.exposure != "local":
                continue
            filtered.append(item)
        self._filtered = filtered
        if self.r_match_count.current:
            self.r_match_count.current.value = tr(
                f"{len(filtered)} of {len(self._listeners)} listening ports match the current filters."
            )
        if self.r_list.current:
            self.r_list.current.controls = [self._port_control(item) for item in filtered] or [
                ft.Container(
                    content=ft.Text(
                        "No ports match the current filter, or administrator permission is required.",
                        color=MUTED, size=10,
                    ), padding=14, alignment=ft.Alignment.CENTER,
                )
            ]
            translate_tree(self.r_list.current, get_language())

    def _port_control(self, item):
        exposure_labels = {"local": "This computer only",
                           "all_interfaces": "All network interfaces",
                           "network_interface": "Specific network interface"}
        color = (RED if item.risk_level == "high"
                 else AMBER if item.risk_level == "medium" else MUTED)
        return ft.Container(
            content=ft.ListTile(
                leading=ft.Container(
                    content=ft.Text(f"{item.port}\n{item.protocol}", color=color,
                                    size=10, weight=ft.FontWeight.W_700,
                                    text_align=ft.TextAlign.CENTER,
                                    font_family="monospace"),
                    width=58, height=48, bgcolor=tint(color, .07),
                    border_radius=8, alignment=ft.Alignment.CENTER,
                ),
                title=ft.Text(
                    f"{item.process}  ·  PID {item.pid or '-'}  ·  {item.service}",
                    color=TEXT, size=10, weight=ft.FontWeight.W_700,
                ),
                subtitle=ft.Text(
                    f"{item.explanation}\n{item.address} · {item.family} · "
                    f"{tr(exposure_labels[item.exposure])}",
                    color=MUTED, size=9, max_lines=2,
                ),
                trailing=ft.Text(tr(item.risk_level.upper()), color=color, size=8,
                                 weight=ft.FontWeight.W_700),
                content_padding=ft.padding.Padding.symmetric(horizontal=8, vertical=2),
            ),
            bgcolor=tint(color, .025), border=ft.Border.all(1, tint(color, .13)),
            border_radius=8,
        )

    def _show_results_dialog(self):
        if not self._page or not self._page[0]:
            return
        page = self._page[0]
        exposure_labels = {"local": "This computer only",
                           "all_interfaces": "All network interfaces",
                           "network_interface": "Specific network interface"}
        controls = []
        for item in self._filtered:
            color = (RED if item.risk_level == "high"
                     else AMBER if item.risk_level == "medium" else MUTED)
            controls.append(ft.Container(
                content=ft.ListTile(
                    leading=ft.Container(
                        content=ft.Text(f"{item.port}\n{item.protocol}", color=color,
                                        size=10, weight=ft.FontWeight.W_700,
                                        text_align=ft.TextAlign.CENTER,
                                        font_family="monospace"),
                        width=58, height=48, bgcolor=tint(color, .07),
                        border_radius=8, alignment=ft.Alignment.CENTER,
                    ),
                    title=ft.Text(
                        f"{item.process}  ·  PID {item.pid or '-'}  ·  {item.service}",
                        color=TEXT, size=10, weight=ft.FontWeight.W_700,
                    ),
                    subtitle=ft.Text(
                        f"{item.explanation}\n{item.address} · {item.family} · "
                        f"{tr(exposure_labels[item.exposure])}",
                        color=MUTED, size=9, max_lines=2,
                    ),
                    trailing=ft.Text(tr(item.risk_level.upper()), color=color, size=8,
                                     weight=ft.FontWeight.W_700),
                    content_padding=ft.padding.Padding.symmetric(horizontal=8, vertical=2),
                ),
                bgcolor=tint(color, .025), border=ft.Border.all(1, tint(color, .13)),
                border_radius=8,
            ))
        def close(_=None):
            close_dialog(page)
            page.update()
        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("PORTS OPEN ON THIS COMPUTER", color=TEXT, size=13,
                          weight=ft.FontWeight.W_700),
            content=ft.Container(
                content=ft.Column(
                    controls or [ft.Text(
                        "No ports match the current filter, or administrator permission is required.",
                        color=MUTED, size=10,
                    )],
                    spacing=6, scroll=ft.ScrollMode.AUTO,
                ),
                width=760, height=520,
            ),
            actions=[ft.TextButton("Close", on_click=close)],
            bgcolor=SURFACE, barrier_color="#66000000",
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    def on_mount(self):
        # During the initial Flet mount the page is still composing its first
        # frame, so perform this first population directly. Manual refreshes
        # use the worker path and animated state above.
        self.refresh(background=False)

    def set_viewport(self, width: float, height: float):
        content_width = fit(max(300.0, width - 28.0))
        columns = 3 if content_width >= 760 else 1
        key = (columns, content_width)
        if key == self._layout_key or not self._summary_cards:
            return
        self._layout_key = key
        _apply_widths(self._summary_cards, split(content_width, columns, 12))
        self._toolbar.width = content_width
        # 330 px could not hold the Spanish label ("Puerto, proceso, servicio o
        # dirección"), which wrapped onto a second line and made the field
        # taller than the controls beside it. The field now takes the room the
        # filter and the refresh action leave free.
        self._search_field.width = snap(
            max(360.0, min(620.0, content_width - 430.0))
        )


# ── 4. LIVE PACKETS ────────────────────────────────────────────────────

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
                # The key stays English so filtering keeps working; the text is
                # what ``translate_tree`` localises.
                options=[ft.DropdownOption(x, x) for x in opts],
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
            # The surrounding card already draws the frame; a second border
            # here produced a double outline on every desktop size.
            bgcolor=CARD,
            border_radius=10,
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
        # A spacer keeps the two actions anchored to the trailing edge instead
        # of leaving one long empty strip on wide desktops.
        self._toolbar_spacer = ft.Container(expand=True)
        self._toolbar_row = ft.Row([
                    self._proto_filter,
                    self._direction_filter,
                    self._ip_filter,
                    ft.Text(ref=self.r_count, value="0 packets", size=12, color=MUTED),
                    self._toolbar_spacer,
                    ft.Button(
                        ref=self.r_pause_btn,
                        content="⏸ Pause", on_click=on_pause,
                        bgcolor=BORDER, color=TEXT,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                    ),
                    ft.Button(
                        content="Export CSV", icon=ft.Icons.FILE_DOWNLOAD_ROUNDED, on_click=on_export,
            bgcolor=tint(PURPLE, .19), color=PURPLE,
                        style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
                    ),
                ], spacing=10, wrap=False, run_spacing=10)
        self._toolbar_card = card(
            self._toolbar_row,
            padding=ft.padding.Padding.symmetric(horizontal=14, vertical=10),
        )
        # The stream area is a card like every other list in the workspace.
        # Without it the heading row floated alone over the page background and
        # the rest of the viewport read as an unfinished hole.
        self._table_container = card(
            ft.Stack([
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
            padding=ft.padding.Padding.only(left=6, top=6, right=6, bottom=6),
            expand=True,
            clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
        )

        return ft.Column([
            view_heading("Packet explorer", "Inspect, filter and export the live packet stream",
                         ft.Icons.DATA_OBJECT_ROUNDED, GREEN),
            self._toolbar_card,
            self._table_container,
        ], spacing=10, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = fit(max(280.0, width - 28.0))
        content_height = fit(max(360.0, height - 28.0))
        mode = "wide" if content_width >= 900 else "compact" if content_width >= 600 else "narrow"
        key = (mode, round(content_width), round(content_height))
        if key == self._layout_key or not self._toolbar_card:
            return
        self._layout_key = key
        self._toolbar_card.width = content_width
        self._toolbar_row.width = snap(max(250.0, content_width - 28.0))
        self._table_container.width = content_width
        if self.r_table.current:
            # Card border (1 px) plus its 6 px padding on both sides: the
            # heading row has to reach the frame, not stop short of it.
            self.r_table.current.width = snap(max(820.0, content_width - 14.0))

        # A Wrap cannot host an expanding spacer, so the trailing alignment is
        # only used while the toolbar fits on a single line.
        self._toolbar_row.wrap = mode == "narrow"
        self._toolbar_spacer.visible = mode != "narrow"
        # Spanish labels ("Protocolo", "Dirección") need more room than the
        # English source strings before the floating label wraps in two lines.
        if mode == "narrow":
            self._proto_filter.width = 150
            self._direction_filter.width = 140
            self._ip_filter.width = snap(min(220.0, content_width - 28.0))
        else:
            self._proto_filter.width = 165
            self._direction_filter.width = 150
            self._ip_filter.width = 240 if mode == "wide" else 200

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
            self.r_count.current.value = tr(f"{len(rows):,} packets")


# ── 3. CHARTS ────────────────────────────────────────────────────────────

class ChartsView:
    """Active quality checks and conservative capacity guidance."""

    def __init__(self, state: AppState, page_ref=None, db: DB | None = None):
        self.s = state
        self._page = page_ref or [None]
        self.db = db
        self.line_chart = None
        self.bar_chart = None
        self.r_status = ft.Ref[ft.Text]()
        self.r_reason = ft.Ref[ft.Text]()
        self.r_gateway = ft.Ref[ft.Text]()
        self.r_latency = ft.Ref[ft.Text]()
        self.r_jitter = ft.Ref[ft.Text]()
        self.r_loss = ft.Ref[ft.Text]()
        self.r_dns = ft.Ref[ft.Text]()
        self.r_internet = ft.Ref[ft.Text]()
        self.r_samples = ft.Ref[ft.Text]()
        self.r_button = ft.Ref[ft.Button]()
        self.r_trend = ft.Ref[ft.Text]()
        self.r_trend_detail = ft.Ref[ft.Text]()
        self.r_adapter = ft.Ref[ft.Text]()
        self.r_capacity = ft.Ref[ft.Text]()
        self.r_headroom = ft.Ref[ft.Text]()
        self.r_history = ft.Ref[ft.Column]()
        self._cards = []
        self._grid = None
        self._guidance_card = None
        self._status_card = None
        self._running = False
        self._last_gateway = None
        self._layout_mode = None

    def build(self):
        async def run_check(e):
            if self._running:
                return
            self._running = True
            if self.r_button.current:
                self.r_button.current.disabled = True
                self.r_button.current.icon = ft.Icons.SYNC_ROUNDED
                self.r_button.current.content = "CHECKING..."
                self.r_button.current.update()
            try:
                rows = self.db.list_quality_checks(30) if self.db else []
                checks_to_run = checks_needed_for_trend(rows) if self.db else 1
                for index in range(checks_to_run):
                    if self.r_button.current and checks_to_run > 1:
                        self.r_button.current.content = (
                            f"{tr('CHECKING...')} {index + 1}/{checks_to_run}"
                        )
                        self.r_button.current.update()
                    result = await asyncio.to_thread(measure_quality)
                    if self.db:
                        self.db.save_quality_check(self.s.interface, result)
                    self._apply_result(result)
                    # Repeating a blocked or inconclusive ICMP probe does not add
                    # useful evidence and would only delay feedback to the user.
                    if result.confidence != "sufficient":
                        break
                self._refresh_evidence()
            finally:
                self._running = False
                if self.r_button.current:
                    self.r_button.current.disabled = False
                    self.r_button.current.icon = ft.Icons.NETWORK_CHECK_ROUNDED
                    self.r_button.current.content = "RUN QUALITY CHECK"
                page = self._page[0]
                if page:
                    translate_tree(page, get_language())
                    page.update()

        def metric(label, ref, color):
            control = card(ft.Column([
                ft.Text(label, size=9, color=DIM, weight=ft.FontWeight.W_600),
                ft.Text(ref=ref, value="Not measured", size=22, color=color,
                        weight=ft.FontWeight.BOLD, font_family="monospace"),
            ], spacing=7), height=88)
            self._cards.append(control)
            return control

        self._grid = ft.Row([
            metric("GATEWAY LATENCY", self.r_latency, CYAN),
            metric("JITTER", self.r_jitter, PURPLE),
            metric("PACKET LOSS", self.r_loss, AMBER),
            metric("DNS RESOLUTION", self.r_dns, GREEN),
        ], spacing=12, wrap=True, run_spacing=12)
        self._status_card = status_card = card(ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.VERIFIED_USER_OUTLINED, color=CYAN, size=22),
                ft.Column([
                    ft.Text(ref=self.r_status, value="NOT MEASURED", color=TEXT,
                            size=14, weight=ft.FontWeight.W_700),
                    ft.Text(ref=self.r_reason,
                            value="Run a check to collect independent quality evidence.",
                            color=MUTED, size=10),
                ], spacing=2, expand=True),
                ft.Button(ref=self.r_button, content="RUN QUALITY CHECK",
                          icon=ft.Icons.NETWORK_CHECK_ROUNDED, on_click=run_check,
                          color=CYAN, bgcolor=tint(CYAN, .10)),
            ], spacing=10),
            ft.Divider(color=BORDER, height=8),
            ft.Row([
                ft.Text("Gateway:", color=MUTED, size=10),
                ft.Text(ref=self.r_gateway, value="Not detected", color=TEXT,
                        size=10, font_family="monospace"),
                ft.Text("Evidence:", color=MUTED, size=10),
                ft.Text(ref=self.r_samples, value="0/4 replies", color=TEXT, size=10),
                ft.Text("Internet:", color=MUTED, size=10),
                ft.Text(ref=self.r_internet, value="Not checked", color=TEXT, size=10),
            ], spacing=8, wrap=True),
        ], spacing=7))
        self._guidance_card = guidance = card(ft.Column([
            section_title("HOW TO INTERPRET THIS CHECK"),
            ft.Text(
                "Measurements are taken on demand and are not inferred from captured traffic. "
                "NetPulse requires at least three gateway replies before classifying quality. "
                "If ICMP is blocked, the result remains insufficient instead of reporting false loss.",
                color=MUTED, size=10,
            ),
            ft.Text(
                "Review thresholds: latency ≥100 ms, jitter ≥30 ms or packet loss ≥5%. "
                "DNS and Internet checks are reported independently.",
                color=DIM, size=10,
            ),
        ], spacing=8))
        def capacity_metric(label, value_ref, color, detail_ref=None):
            controls = [
                ft.Text(label, color=MUTED, size=9, weight=ft.FontWeight.W_600),
                ft.Text(ref=value_ref, value=("INSUFFICIENT DATA" if detail_ref else
                                              "Not detected" if value_ref is self.r_adapter
                                              else "Unavailable"),
                        color=color, size=12, weight=ft.FontWeight.W_600),
            ]
            if detail_ref:
                controls.append(ft.Text(ref=detail_ref, value="0/5 valid checks",
                                        color=DIM, size=9))
            return ft.Container(
                content=ft.Column(controls, spacing=3, tight=True),
                col={"xs": 12, "sm": 6, "lg": 3},
                bgcolor=tint(color, .035),
                border=ft.Border.all(1, tint(color, .13)),
                border_radius=8,
                padding=10,
                height=72,
            )

        self._capacity_grid = ft.ResponsiveRow([
            capacity_metric("ACTIVE ADAPTER", self.r_adapter, CYAN),
            capacity_metric("LINK CAPACITY", self.r_capacity, BLUE),
            capacity_metric("OBSERVED HEADROOM", self.r_headroom, GREEN),
            capacity_metric("QUALITY TREND", self.r_trend, AMBER, self.r_trend_detail),
        ], columns=12, spacing=10, run_spacing=10)
        capacity_card = card(ft.Column([
            section_title("CAPACITY AND TREND"),
            self._capacity_grid,
        ], spacing=10, tight=True))
        history_card = card(ft.Column([
            section_title("RECENT QUALITY CHECKS"),
            ft.Column(ref=self.r_history, controls=[
                ft.Text("No saved quality checks yet.", color=MUTED, size=10)
            ], spacing=5, horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
        ], spacing=8))
        self._capacity_card = capacity_card
        self._history_card = history_card
        self._refresh_evidence()
        return ft.Column([
            view_heading("Performance and capacity",
                         "Measure connection quality without duplicating dashboard traffic",
                         ft.Icons.SPEED_ROUNDED, PURPLE),
            status_card,
            self._grid,
            capacity_card,
            history_card,
            guidance,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = fit(max(280.0, width - 28.0))
        mode = "wide" if content_width >= 900 else "compact" if content_width >= 560 else "narrow"
        layout_key = (mode, content_width, round(height))
        if layout_key == self._layout_mode or not self._cards:
            return
        self._layout_mode = layout_key
        self._grid.width = content_width
        self._history_card.width = content_width
        # The guidance card had no width of its own, so it stopped short of the
        # cards above it and left a ragged edge down the right of the view.
        self._guidance_card.width = content_width
        self._status_card.width = content_width
        count = 4 if mode == "wide" else 2 if mode == "compact" else 1
        _apply_widths(self._cards, split(content_width, count, 12))

    def refresh(self):
        # Quality checks are intentionally on demand; the global refresh loop
        # must not generate background network traffic or duplicate Dashboard.
        return

    def on_mount(self):
        self._refresh_evidence()
        for ref in (
            self.r_adapter, self.r_capacity, self.r_headroom, self.r_trend,
            self.r_trend_detail, self.r_history,
        ):
            if ref.current:
                try:
                    ref.current.update()
                except RuntimeError:
                    pass

    def _apply_result(self, result):
        self._last_gateway = result.target
        status, reason = classify_quality(result)
        color = GREEN if status == "STABLE" else AMBER if status == "REVIEW" else MUTED
        self.r_status.current.value = tr(status)
        self.r_status.current.color = color
        self.r_reason.current.value = tr(reason or "No classification available.")
        self.r_gateway.current.value = result.target
        self.r_samples.current.value = f"{result.received}/{result.samples} replies"
        self.r_latency.current.value = (f"{result.latency_ms:.1f} ms"
                                        if result.latency_ms is not None else tr("Unavailable"))
        self.r_jitter.current.value = (f"{result.jitter_ms:.1f} ms"
                                       if result.jitter_ms is not None else tr("Unavailable"))
        self.r_loss.current.value = (f"{result.loss_percent:.0f}%"
                                     if result.loss_percent is not None else tr("Insufficient"))
        self.r_dns.current.value = (f"{result.dns_ms:.1f} ms"
                                    if result.dns_ms is not None else tr("Unavailable"))
        self.r_internet.current.value = tr(
            "Reachable" if result.internet_reachable is True
            else "Not reachable" if result.internet_reachable is False
            else "Inconclusive"
        )

    def _refresh_evidence(self):
        capacity = adapter_capacity(self.s.interface, self._last_gateway)
        if self.r_adapter.current:
            self.r_adapter.current.value = capacity["name"]
            # This evidence is written after ``translate_tree`` has walked the
            # view, so each value has to be localised as it is produced.
            self.r_capacity.current.value = (
                f"{capacity['speed_mbps']:.0f} Mbps" if capacity["speed_mbps"]
                else tr("Unavailable")
            )
            observed_mbps = (self.s.peak_kbps_in + self.s.peak_kbps_out) * 8 / 1024
            if capacity["speed_mbps"] and observed_mbps > 0:
                used = min(100.0, observed_mbps / capacity["speed_mbps"] * 100)
                self.r_headroom.current.value = tr(f"{100 - used:.1f}% (capture peak)")
            else:
                self.r_headroom.current.value = tr("Insufficient data")
        rows = self.db.list_quality_checks(30) if self.db else []
        trend, detail = quality_trend(rows)
        if self.r_trend.current:
            self.r_trend.current.value = tr(trend)
            self.r_trend_detail.current.value = tr(detail)
        if self.r_history.current:
            self.r_history.current.controls = [
                ft.Container(
                    content=ft.Row([
                        ft.Text(str(row["ts"])[5:16].replace("T", "  "),
                                color=TEXT, size=10, font_family="monospace", width=105),
                        ft.Text(row["gateway"], color=CYAN, size=10,
                                font_family="monospace", width=120),
                        ft.Text(f"{tr('Latency')}  {row['latency_ms']:.1f} ms",
                                color=MUTED if row["latency_ms"] < 100 else AMBER,
                                size=10, width=145),
                        ft.Text(f"Jitter  {row['jitter_ms']:.1f} ms",
                                color=MUTED if row["jitter_ms"] < 30 else AMBER,
                                size=10, width=130),
                        ft.Text(f"{tr('Loss')}  {row['loss_percent']:.0f}%",
                                color=MUTED if row["loss_percent"] < 5 else AMBER,
                                size=10, width=115),
                        ft.Text(f"DNS  {row['dns_ms']:.1f} ms" if row["dns_ms"] is not None
                                else f"DNS  {tr('not available')}", color=PURPLE, size=10),
                    ], spacing=10, wrap=True, run_spacing=5),
                    bgcolor=tint(CYAN, .035),
                    border=ft.Border.all(1, tint(CYAN, .14)),
                    border_radius=7,
                    padding=ft.padding.Padding.symmetric(horizontal=10, vertical=8),
                )
                for row in rows[:8]
                if row["received"] >= 3 and row["latency_ms"] is not None
                and row["jitter_ms"] is not None and row["loss_percent"] is not None
            ] or [ft.Text("No saved quality checks yet.", color=MUTED, size=10)]


# ── 4. HISTORY ────────────────────────────────────────────────────────────

class HistoryView:
    def __init__(self, db: DB):
        self.db = db
        self.r_dd    = ft.Ref[ft.Dropdown]()
        self.r_table = ft.Ref[ft.DataTable]()
        self.r_info  = ft.Ref[ft.Text]()
        self.r_session_count = ft.Ref[ft.Text]()
        self.line_chart = LineChartCanvas(CYAN, GREEN, "Received", "Sent", 300, 210)
        self._metric_values = {}
        self._protocol_rows = None
        self._insight_text = None
        self._metrics_row = None
        self._metric_cards = []
        self._analysis_row = None
        self._header_card = None
        self._header_row = None
        self._chart_card = None
        self._table_card = None
        self._session_dropdown = None
        self._top_table = None
        self._compare_dropdown = None
        self._comparison_text = None
        self._trend_text = None
        self._apps_column = None
        self._events_column = None
        self._detail_row = None
        self._selected_sid = None
        self._layout_key = None

    @staticmethod
    def _format_bytes(value: int) -> str:
        value = int(value or 0)
        if value >= 1024 ** 3:
            return f"{value / 1024 ** 3:.2f} GB"
        if value >= 1024 ** 2:
            return f"{value / 1024 ** 2:.1f} MB"
        if value >= 1024:
            return f"{value / 1024:.1f} KB"
        return f"{value} B"

    @staticmethod
    def _format_duration(seconds: float) -> str:
        seconds = max(0, int(seconds or 0))
        hours, rest = divmod(seconds, 3600)
        minutes, secs = divmod(rest, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    @staticmethod
    def _parse_time(value):
        try:
            return datetime.fromisoformat(str(value)) if value else None
        except (TypeError, ValueError):
            return None

    def build(self):
        def on_session(e):
            if e.control.value:
                self._load(int(e.control.value))
        def on_refresh(e):
            self._reload_sessions()
        def on_compare(e):
            self._render_comparison(int(e.control.value)) if e.control.value else None
        def on_export(e):
            self._export_selected()

        top_table = ft.DataTable(
            ref=self.r_table,
            columns=[
                ft.DataColumn(ft.Text("Remote IP",   color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Traffic",      color=DIM, size=11, weight=ft.FontWeight.W_600), numeric=True),
                ft.DataColumn(ft.Text("Share",        color=DIM, size=11, weight=ft.FontWeight.W_600), numeric=True),
                ft.DataColumn(ft.Text("Packets",      color=DIM, size=11, weight=ft.FontWeight.W_600), numeric=True),
                ft.DataColumn(ft.Text("Last activity", color=DIM, size=11, weight=ft.FontWeight.W_600)),
                ft.DataColumn(ft.Text("Identity / Geo", color=DIM, size=11, weight=ft.FontWeight.W_600)),
            ],
            rows=[], bgcolor=CARD, border=ft.Border.all(1, BORDER), border_radius=10,
            column_spacing=20, heading_row_color=SURFACE, heading_row_height=36,
            data_row_min_height=30, divider_thickness=0.4,
        )
        self._top_table = top_table
        self._session_dropdown = ft.Dropdown(
            ref=self.r_dd, label="Captured session",
            hint_text="Choose a session to review", options=[],
            on_select=on_session, width=620,
            filled=True, fill_color=tint(CYAN, .025), color=TEXT,
            border_color=BORDER, focused_border_color=CYAN,
            border_radius=9, text_size=12, menu_height=360,
            leading_icon=ft.Icons.HISTORY_ROUNDED,
            enable_search=True,
        )
        self._compare_dropdown = ft.Dropdown(
            label="Compare with", hint_text="Optional second session", options=[],
            on_select=on_compare, width=330, filled=True,
            fill_color=tint(PURPLE, .025), color=TEXT, border_color=BORDER,
            focused_border_color=PURPLE, border_radius=9, text_size=11,
            enable_search=True,
        )
        self._header_row = ft.Row([
            self._session_dropdown,
            self._compare_dropdown,
            ft.Button(content="RELOAD SESSIONS", icon=ft.Icons.REFRESH_ROUNDED,
                      on_click=on_refresh, color=CYAN, bgcolor=tint(CYAN, .09)),
            ft.Button(content="EXPORT SESSION", icon=ft.Icons.DOWNLOAD_ROUNDED,
                      on_click=on_export, color=GREEN, bgcolor=tint(GREEN, .09)),
        ], spacing=10, wrap=True, run_spacing=10)
        self._header_card = card(
            ft.Column([
                ft.Row([
                    section_title("CAPTURED SESSIONS"),
                    ft.Container(expand=True),
                    ft.Text(ref=self.r_session_count, value="0 sessions",
                            color=MUTED, size=10),
                ]),
                self._header_row,
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.INFO_OUTLINE_ROUNDED, color=CYAN, size=16),
                        ft.Text(ref=self.r_info, value="Select a session to see its summary",
                                size=11, color=DIM, expand=True),
                    ], spacing=7),
                    bgcolor=tint(CYAN, .025), border_radius=7,
                    padding=ft.padding.Padding.symmetric(horizontal=10, vertical=7),
                ),
            ], spacing=9),
            padding=12,
        )
        metric_specs = (
            ("volume", "TOTAL TRANSFERRED", ft.Icons.SWAP_VERT_ROUNDED, CYAN),
            ("average", "AVERAGE THROUGHPUT", ft.Icons.TIMELAPSE_ROUNDED, GREEN),
            ("peak", "PEAK SECOND", ft.Icons.BOLT_ROUNDED, AMBER),
            ("direction", "TRAFFIC DIRECTION", ft.Icons.COMPARE_ARROWS_ROUNDED, PURPLE),
            ("endpoints", "REMOTE ENDPOINTS", ft.Icons.PUBLIC_ROUNDED, BLUE),
        )
        self._metrics_row = ft.Row(spacing=10, wrap=True, run_spacing=10)
        for key, label, icon, color in metric_specs:
            value = ft.Text("—", color=color, size=17, weight=ft.FontWeight.W_700,
                            overflow=ft.TextOverflow.ELLIPSIS)
            detail = ft.Text("", color=MUTED, size=9,
                             overflow=ft.TextOverflow.ELLIPSIS)
            self._metric_values[key] = (value, detail)
            item = card(ft.Row([
                ft.Container(content=ft.Icon(icon, color=color, size=20),
                             width=38, height=38, alignment=ft.Alignment.CENTER,
                             bgcolor=tint(color, .10), border_radius=9),
                ft.Column([
                    ft.Text(label, color=DIM, size=8, weight=ft.FontWeight.W_700),
                    value, detail,
                ], spacing=0, expand=True),
            ], spacing=8), padding=10)
            self._metric_cards.append(item)
        self._metrics_row.controls = self._metric_cards

        self._chart_card = card(ft.Column([
            ft.Row([
                section_title("SESSION TIMELINE  ( KB/s per second )"),
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
        self._protocol_rows = ft.Column([
            ft.Text("Select a session to calculate protocol activity.", color=MUTED, size=10)
        ], spacing=8)
        self._protocol_card = card(ft.Column([
            section_title("PROTOCOL ACTIVITY"),
            ft.Text("Packet counts accumulated during this capture.", color=MUTED, size=9),
            ft.Divider(color=BORDER, height=6),
            self._protocol_rows,
        ], spacing=7))
        self._analysis_row = ft.Row([
            self._chart_card, self._protocol_card,
        ], spacing=10, wrap=True, run_spacing=10,
           vertical_alignment=ft.CrossAxisAlignment.START)
        self._insight_text = ft.Text(
            "Select a session to generate a concise activity summary.",
            color=DIM, size=10, expand=True,
        )
        self._insight_card = card(ft.Row([
            ft.Container(content=ft.Icon(ft.Icons.LIGHTBULB_OUTLINE_ROUNDED,
                                         color=AMBER, size=20),
                         width=38, height=38, alignment=ft.Alignment.CENTER,
                         bgcolor=tint(AMBER, .09), border_radius=9),
            ft.Column([
                ft.Text("SESSION HIGHLIGHTS", color=TEXT, size=10,
                        weight=ft.FontWeight.W_700),
                self._insight_text,
            ], spacing=3, expand=True),
        ], spacing=9), padding=10)
        self._comparison_text = ft.Text(
            "Choose a second session to compare volume, packets, duration and drops.",
            color=DIM, size=10, selectable=True,
        )
        self._trend_text = ft.Text(
            "Daily trends will appear when captures are available.",
            color=DIM, size=10, selectable=True,
        )
        comparison_card = card(ft.Column([
            section_title("SESSION COMPARISON"), self._comparison_text,
            ft.Divider(color=BORDER, height=5),
            section_title("LAST 30 DAYS"), self._trend_text,
        ], spacing=7), padding=10)
        self._apps_column = ft.Column([
            ft.Text("No historical application data for this session.", color=MUTED, size=10)
        ], spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)
        self._events_column = ft.Column([
            ft.Text("No session events recorded.", color=MUTED, size=10)
        ], spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)
        # Never put Expanded children inside a wrapping Row. Flutter implements
        # Row(wrap=True) as a Wrap, where Expanded is invalid and Flet renders
        # the affected region as a large grey error surface.
        apps_card = card(ft.Column([
            section_title("APPLICATIONS AND PROCESSES"), self._apps_column,
        ], spacing=8, expand=True), padding=10)
        events_card = card(ft.Column([
            section_title("ALERTS, DROPS AND EVENTS"), self._events_column,
        ], spacing=8, expand=True), padding=10)
        self._detail_row = ft.Row([apps_card, events_card], spacing=10, wrap=True,
                                  run_spacing=10,
                                  vertical_alignment=ft.CrossAxisAlignment.START)
        self._table_card = card(ft.Column([
            section_title("REMOTE ENDPOINTS  ( ranked by traffic )"),
            ft.Divider(color=BORDER, height=6),
            ft.Column([ft.Row([top_table], scroll=ft.ScrollMode.ALWAYS)],
                      scroll=ft.ScrollMode.ALWAYS, expand=True),
        ], spacing=10, expand=True))

        return ft.Column([
            view_heading("Session history", "Compare stored captures and review their top endpoints",
                         ft.Icons.HISTORY_ROUNDED, AMBER),
            self._header_card,
            self._metrics_row,
            self._analysis_row,
            self._insight_card,
            comparison_card,
            self._detail_row,
            self._table_card,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = fit(max(280.0, width - 28.0))
        content_height = fit(max(420.0, height - 28.0))
        mode = "wide" if content_width >= 900 else "compact" if content_width >= 580 else "narrow"
        key = (mode, content_width, content_height)
        if key == self._layout_key or not self._header_card:
            return
        self._layout_key = key
        for control in (self._header_card, self._insight_card, self._table_card):
            control.width = content_width
        self._header_row.width = fit(max(240.0, content_width - 28.0))
        # The picker used to stop at 460 px. Maximized, that left roughly a
        # thousand pixels of empty card to the right of the reload action while
        # the session captions ("#79 · 2026-08-26T08:00:56 · All · 0 packets")
        # were the longest strings in the view. It now takes the row it shares
        # with that button, which needs ~260 px for its Spanish caption.
        self._session_dropdown.width = fit(
            max(320.0, content_width * .42)
            if mode != "narrow"
            else max(220.0, content_width - 84.0)
        )
        self._compare_dropdown.width = fit(
            max(260.0, content_width * .28) if mode != "narrow"
            else max(220.0, content_width - 84.0)
        )
        metric_columns = 5 if content_width >= 1120 else 3 if content_width >= 720 else 2
        metric_widths = split(content_width, metric_columns, 10)
        _apply_widths(self._metric_cards, metric_widths)
        chart_height = 190 if content_height >= 720 else 165 if content_height >= 560 else 145
        if mode == "wide":
            chart_width = snap(content_width * .67 - 5)
            protocol_width = snap(content_width - chart_width - 10)
        else:
            chart_width = protocol_width = content_width
        self._chart_card.width = chart_width
        self._protocol_card.width = protocol_width
        self._analysis_row.width = content_width
        self._detail_row.width = content_width
        detail_widths = split(content_width, 2, 10) if mode == "wide" else [content_width]
        for index, item in enumerate(self._detail_row.controls):
            item.width = detail_widths[index] if mode == "wide" else content_width
            item.height = 250
        self.line_chart.resize(chart_width - 28.0, chart_height)
        self._table_card.height = snap(max(250.0, content_height * .42))
        if self._top_table:
            self._top_table.width = snap(max(880.0, content_width - 36.0))

    def on_mount(self):
        self._reload_sessions()

    def _reload_sessions(self):
        if not self.r_dd.current:
            return
        sessions = self.db.list_sessions()
        self.r_dd.current.options = [
            ft.DropdownOption(
                key=str(s["id"]),
                text=(f"#{s['id']}  ·  {str(s['start_time'])[:19]}"
                      f"  ·  {s['interface']}  ·  "
                      f"{tr('Completed') if s.get('end_time') else tr('Active')}"),
            )
            for s in sessions
        ]
        selected_value = self.r_dd.current.value
        self._compare_dropdown.options = [
            ft.DropdownOption(str(s["id"]), f"#{s['id']} · {str(s['start_time'])[:19]}")
            for s in sessions if str(s["id"]) != selected_value
        ]
        if self.r_session_count.current:
            self.r_session_count.current.value = tr(f"{len(sessions)} sessions")
        valid_values = {str(session["id"]) for session in sessions}
        if self.r_dd.current.value not in valid_values:
            self.r_dd.current.value = str(sessions[0]["id"]) if sessions else None
            if sessions:
                self._load(sessions[0]["id"])
        if not sessions and self.r_info.current:
            self.r_info.current.value = tr("No captured sessions yet")
        try:
            self.r_dd.current.update()
        except RuntimeError:
            # Allows the view model to be refreshed before first mount; Flet
            # will render the populated value when the control is attached.
            pass

    def _load(self, sid: int):
        self._selected_sid = sid
        stats = self.db.get_stats(sid)
        inbound_series = [r["bytes_in"] / 1024 for r in stats]
        outbound_series = [r["bytes_out"] / 1024 for r in stats]
        self.line_chart._n = max(1, len(stats))
        self.line_chart.update_data(inbound_series, outbound_series)

        tops = self.db.get_top_ips(sid, 100)
        all_sessions = self.db.list_sessions()
        session = next((item for item in all_sessions if item["id"] == sid), None)
        if not session:
            return

        start = self._parse_time(session.get("start_time"))
        end = self._parse_time(session.get("end_time"))
        if end is None and stats:
            end = self._parse_time(stats[-1].get("ts"))
        duration = max(0.0, (end - start).total_seconds()) if start and end else 0.0
        inbound = max(int(session.get("total_bytes_in") or 0),
                      sum(int(row.get("bytes_in") or 0) for row in stats))
        outbound = max(int(session.get("total_bytes_out") or 0),
                       sum(int(row.get("bytes_out") or 0) for row in stats))
        total_bytes = inbound + outbound
        packet_total = max(int(session.get("total_pkts") or 0),
                           sum(int(row.get("pkts_in") or 0) + int(row.get("pkts_out") or 0)
                               for row in stats))
        average_kbps = total_bytes / 1024 / duration if duration else 0.0
        peak_row = max(stats, key=lambda row: int(row.get("bytes_in") or 0)
                       + int(row.get("bytes_out") or 0), default=None)
        peak_kbps = ((int(peak_row.get("bytes_in") or 0)
                      + int(peak_row.get("bytes_out") or 0)) / 1024
                     if peak_row else 0.0)
        inbound_share = inbound / total_bytes * 100 if total_bytes else 0.0
        outbound_share = 100.0 - inbound_share if total_bytes else 0.0

        protocols = {
            "TCP": sum(int(row.get("n_tcp") or 0) for row in stats),
            "UDP": sum(int(row.get("n_udp") or 0) for row in stats),
            "HTTPS": sum(int(row.get("n_https") or 0) for row in stats),
            "HTTP": sum(int(row.get("n_http") or 0) for row in stats),
            "DNS": sum(int(row.get("n_dns") or 0) for row in stats),
            "ICMP": sum(int(row.get("n_icmp") or 0) for row in stats),
            "OTHER": sum(int(row.get("n_other") or 0) for row in stats),
        }
        protocol_total = sum(protocols.values())
        protocol_rank = sorted(protocols.items(), key=lambda item: item[1], reverse=True)
        dominant_protocol, dominant_count = protocol_rank[0] if protocol_rank else ("—", 0)

        def metric(key, value, detail):
            value_control, detail_control = self._metric_values[key]
            value_control.value = value
            detail_control.value = detail
            try:
                value_control.update()
                detail_control.update()
            except RuntimeError:
                pass

        metric("volume", self._format_bytes(total_bytes),
               f"↓ {self._format_bytes(inbound)} · ↑ {self._format_bytes(outbound)}")
        metric("average", f"{average_kbps:.1f} KB/s",
               f"{self._format_duration(duration)} {tr('duration').lower()}")
        metric("peak", f"{peak_kbps:.1f} KB/s",
               str(peak_row.get("ts") or "")[:19] if peak_row else tr("No samples"))
        metric("direction", f"{inbound_share:.0f}% ↓  {outbound_share:.0f}% ↑",
               tr("Received versus sent"))
        metric("endpoints", f"{len(tops):,}",
               f"{packet_total:,} {tr('packets')}")

        if self._protocol_rows is not None:
            protocol_controls = []
            for name, count in protocol_rank:
                if count <= 0:
                    continue
                share = count / protocol_total if protocol_total else 0.0
                color = proto_color(name)
                protocol_controls.append(ft.Column([
                    ft.Row([
                        ft.Text(name, color=color, size=9,
                                weight=ft.FontWeight.W_700, width=54),
                        ft.Text(f"{count:,}", color=TEXT, size=9,
                                font_family="monospace", width=72),
                        ft.Text(f"{share * 100:.0f}%", color=DIM, size=9,
                                text_align=ft.TextAlign.RIGHT, expand=True),
                    ], spacing=6),
                    ft.ProgressBar(value=share, color=color,
                                   bgcolor=tint(color, .10), height=5),
                ], spacing=3))
            self._protocol_rows.controls = protocol_controls or [
                ft.Text("No protocol samples were stored for this session.",
                        color=MUTED, size=10)
            ]
            try:
                self._protocol_rows.update()
            except RuntimeError:
                pass

        if self.r_table.current:
            endpoint_bytes = sum(int(item.get("total_bytes") or 0) for item in tops)
            self.r_table.current.rows = [
                ft.DataRow(cells=[
                    ft.DataCell(ft.Text(t["ip"],   size=11, color=TEXT,  font_family="monospace")),
                    ft.DataCell(ft.Text(self._format_bytes(t["total_bytes"]), size=11,
                                        color=CYAN, font_family="monospace")),
                    ft.DataCell(ft.Text(
                        f"{(int(t['total_bytes'] or 0) / endpoint_bytes * 100):.1f}%"
                        if endpoint_bytes else "0%", size=10, color=GREEN,
                        font_family="monospace")),
                    ft.DataCell(ft.Text(f"{t['total_pkts']:,}",  size=11, color=DIM,   font_family="monospace")),
                    ft.DataCell(ft.Text(str(t["last_seen"] or "")[:19], size=10, color=MUTED)),
                    ft.DataCell(ft.Text(geo_cache.get_label(t["ip"]) or "…",
                                        size=10, color=PURPLE,
                                        overflow=ft.TextOverflow.ELLIPSIS)),
                ])
                for t in tops[:15]
            ]
            try:
                self.r_table.current.update()
            except RuntimeError:
                pass

        if self.r_info.current:
            status = tr("Active") if not session.get("end_time") else tr("Completed")
            time_range = str(session.get("start_time") or "")[:19]
            if session.get("end_time"):
                time_range += f"  →  {str(session['end_time'])[:19]}"
            self.r_info.current.value = (
                f"#{sid}  ·  {status}  ·  {session.get('interface') or 'All'}  ·  "
                f"{time_range}  ·  {self._format_duration(duration)}"
            )
            try:
                self.r_info.current.update()
            except RuntimeError:
                pass

        if self._insight_text is not None:
            top_endpoint = tops[0]["ip"] if tops else tr("none recorded")
            peak_time = str(peak_row.get("ts") or "")[:19] if peak_row else tr("no peak sample")
            self._insight_text.value = (
                f"{tr('Busiest endpoint')}: {top_endpoint}  ·  "
                f"{tr('Dominant protocol')}: {dominant_protocol} "
                f"({dominant_count:,} {tr('packets')})  ·  "
                f"{tr('Peak throughput')}: {peak_kbps:.1f} KB/s  ·  {peak_time}"
            )
            try:
                self._insight_text.update()
            except RuntimeError:
                pass
        self._render_history_details(sid)
        self._render_trends()
        if self._compare_dropdown is not None:
            self._compare_dropdown.options = [
                ft.DropdownOption(str(item["id"]),
                                  f"#{item['id']} · {str(item['start_time'])[:19]}")
                for item in self.db.list_sessions() if int(item["id"]) != int(sid)
            ]
            if str(self._compare_dropdown.value or "") == str(sid):
                self._compare_dropdown.value = None

    def _render_history_details(self, sid: int):
        applications = self.db.get_session_applications(sid, 50)
        events = self.db.list_session_events(sid, 100)
        if self._apps_column is not None:
            self._apps_column.controls = [
                ft.Container(content=ft.Row([
                    ft.Icon(ft.Icons.APPS_ROUNDED, color=CYAN, size=16),
                    ft.Column([
                        ft.Text(f"{app.get('process_name') or 'Unknown'}"
                                f"  ·  PID {app.get('pid') or '—'}",
                                color=TEXT, size=10, weight=ft.FontWeight.W_600),
                        ft.Text(
                            f"↓ {self._format_bytes(app.get('bytes_in', 0))}  ·  "
                            f"↑ {self._format_bytes(app.get('bytes_out', 0))}  ·  "
                            f"peak {float(app.get('peak_kbps') or 0):.1f} KB/s",
                            color=MUTED, size=9,
                        ),
                    ], spacing=2, expand=True),
                ], spacing=7), bgcolor=tint(CYAN, .035), border_radius=7, padding=7)
                for app in applications
            ] or [ft.Text("No historical application data for this session.",
                          color=MUTED, size=10)]
            self._safe_history_update(self._apps_column)
        if self._events_column is not None:
            self._events_column.controls = [
                ft.Container(content=ft.Column([
                    ft.Row([
                        ft.Text(str(event.get("title") or "Event"), color=TEXT, size=10,
                                weight=ft.FontWeight.W_600, expand=True),
                        ft.Text(str(event.get("ts") or "")[:19], color=MUTED, size=8),
                    ]),
                    ft.Text(str(event.get("detail") or event.get("event_type") or ""),
                            color=DIM, size=9),
                ], spacing=2), bgcolor=tint(
                    AMBER if event.get("severity") == "warning" else CYAN, .04
                ), border_radius=7, padding=7)
                for event in events
            ] or [ft.Text("No session events recorded.", color=MUTED, size=10)]
            self._safe_history_update(self._events_column)

    def _render_comparison(self, other_sid: int):
        if not self._selected_sid or self._comparison_text is None:
            return
        sessions = {int(item["id"]): item for item in self.db.list_sessions()}
        current, other = sessions.get(int(self._selected_sid)), sessions.get(int(other_sid))
        if not current or not other:
            return
        def totals(item):
            return (int(item.get("total_bytes_in") or 0) + int(item.get("total_bytes_out") or 0),
                    int(item.get("total_pkts") or 0), int(item.get("dropped_packets") or 0),
                    max(0, int(((self._parse_time(item.get("end_time")) or
                                self._parse_time(item.get("start_time"))) -
                               self._parse_time(item.get("start_time"))).total_seconds()))
                    if self._parse_time(item.get("start_time")) else 0)
        now_values, old_values = totals(current), totals(other)
        def delta(left, right):
            return f"{left - right:+,}"
        self._comparison_text.value = (
            f"Session #{self._selected_sid} versus #{other_sid}  ·  "
            f"traffic {delta(now_values[0], old_values[0])} B  ·  "
            f"packets {delta(now_values[1], old_values[1])}  ·  "
            f"drops {delta(now_values[2], old_values[2])}  ·  "
            f"duration {delta(now_values[3], old_values[3])} s"
        )
        self._safe_history_update(self._comparison_text)

    def _render_trends(self):
        if self._trend_text is None:
            return
        trends = self.db.session_trends(30)
        weekly = self.db.session_trends(84, "week")
        if not trends:
            self._trend_text.value = "No captures in the last 30 days."
        else:
            total_sessions = sum(int(row.get("sessions") or 0) for row in trends)
            total_bytes = sum(int(row.get("bytes_in") or 0) + int(row.get("bytes_out") or 0)
                              for row in trends)
            busiest = max(trends, key=lambda row: int(row.get("bytes_in") or 0)
                          + int(row.get("bytes_out") or 0))
            self._trend_text.value = (
                f"{len(trends)} active days  ·  {total_sessions} sessions  ·  "
                f"{self._format_bytes(total_bytes)} total  ·  "
                f"busiest day {busiest['period']} ({self._format_bytes(int(busiest.get('bytes_in') or 0) + int(busiest.get('bytes_out') or 0))})"
            )
            if weekly:
                busiest_week = max(weekly, key=lambda row: int(row.get("bytes_in") or 0)
                                   + int(row.get("bytes_out") or 0))
                self._trend_text.value += (
                    f"  ·  busiest week {busiest_week['period']} "
                    f"({self._format_bytes(int(busiest_week.get('bytes_in') or 0) + int(busiest_week.get('bytes_out') or 0))})"
                )
        self._safe_history_update(self._trend_text)

    def _export_selected(self):
        if not self._selected_sid:
            return None
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = PROJECT_ROOT / "exports" / f"netpulse_session_{self._selected_sid}_{stamp}.json"
        result = self.db.export_session(self._selected_sid, target)
        if self.r_info.current:
            self.r_info.current.value = f"Session exported: {result}"
            self._safe_history_update(self.r_info.current)
        return result

    @staticmethod
    def _safe_history_update(control):
        try:
            control.update()
        except (AssertionError, RuntimeError):
            pass


# ── 5. SETTINGS ────────────────────────────────────────────────────────────

class SettingsView:
    def __init__(self, state: AppState, language: str = "en", on_language_change=None,
                 appearance=None, on_appearance_change=None,
                 on_interface_change=None, alerts=None, retention_days=None,
                 on_retention_change=None):
        self.state = state
        self.language = language
        self.on_language_change = on_language_change
        self.appearance = appearance or {"theme": "netpulse", "accent": "cyan",
                                         "density": "standard"}
        self.on_appearance_change = on_appearance_change
        self.on_interface_change = on_interface_change
        # Thresholds and retention survive restarts, so the fields must show the
        # persisted values instead of resetting the workspace to zero.
        self.alerts = alerts if alerts is not None else load_alerts()
        self.retention_days = (
            retention_days if retention_days is not None else load_retention_days()
        )
        self.on_retention_change = on_retention_change
        self.state.alert_bw_thresh = self.alerts["bandwidth_kbps"]
        self.state.alert_pps_thresh = self.alerts["packets_per_second"]
        self.r_bw_thresh   = ft.Ref[ft.TextField]()
        self.r_pps_thresh  = ft.Ref[ft.TextField]()
        self.r_alert_status = ft.Ref[ft.Text]()
        self.r_retention_status = ft.Ref[ft.Text]()
        self._cards = []
        self._settings_body = None
        self._settings_columns = []
        self._interface_dropdown = None
        self._language_dropdown = None
        self._retention_dropdown = None
        self._bw_field = None
        self._pps_field = None
        self._alert_fields_row = None
        self._alert_button = None
        self._layout_key = None

    def _alert_summary(self) -> str:
        """Describe the active thresholds, mirroring what was persisted."""
        parts = []
        if self.state.alert_bw_thresh > 0:
            parts.append(f"BW ≥ {self.state.alert_bw_thresh:.0f} KB/s")
        if self.state.alert_pps_thresh > 0:
            parts.append(f"PPS ≥ {self.state.alert_pps_thresh:.0f} pkt/s")
        if not parts:
            return tr("⚠️ Alerts disabled (set threshold > 0)")
        return tr("✅ Alerts active:") + " " + "  |  ".join(parts)

    def _alert_summary_color(self) -> str:
        active = self.state.alert_bw_thresh > 0 or self.state.alert_pps_thresh > 0
        return GREEN if active else AMBER

    def _retention_summary(self) -> str:
        if not self.retention_days:
            return tr("Keeping every capture session.")
        return (f"{tr('Sessions older than')} {self.retention_days} "
                f"{tr('days are removed at startup.')}")

    def build(self):
        ifaces = list_interfaces()
        opts = [ft.DropdownOption("All", "All interfaces")] + [
            ft.DropdownOption(i["name"], f"{i['name']}  —  {i['ip']}")
            for i in ifaces
        ]
        def on_iface(e):
            self.state.interface = e.control.value or "All"
            if self.on_interface_change:
                self.on_interface_change(self.state.interface)

        def on_retention(e):
            try:
                days = int(e.control.value or 0)
            except (TypeError, ValueError):
                days = 0
            self.retention_days = max(0, days)
            save_retention_days(self.retention_days)
            if self.on_retention_change:
                self.on_retention_change(self.retention_days)
            if self.r_retention_status.current:
                self.r_retention_status.current.value = self._retention_summary()
                try:
                    self.r_retention_status.current.update()
                except (RuntimeError, AssertionError):
                    pass

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
                save_alerts(self.state.alert_bw_thresh, self.state.alert_pps_thresh)
                self.alerts = {
                    "bandwidth_kbps": self.state.alert_bw_thresh,
                    "packets_per_second": self.state.alert_pps_thresh,
                }
                if self.r_alert_status.current:
                    self.r_alert_status.current.value = self._alert_summary()
                    self.r_alert_status.current.color = self._alert_summary_color()
                    try:
                        self.r_alert_status.current.update()
                    except (RuntimeError, AssertionError):
                        pass
            except ValueError:
                if self.r_alert_status.current:
                    self.r_alert_status.current.value = tr("❌ Invalid number")
                    self.r_alert_status.current.color = RED
                    try:
                        self.r_alert_status.current.update()
                    except (RuntimeError, AssertionError):
                        pass

        def apply_appearance(e=None):
            if self.on_appearance_change:
                self.on_appearance_change(
                    self._theme_dropdown.value or "netpulse",
                    self._accent_dropdown.value or "cyan",
                    self._density_dropdown.value or "standard",
                )

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
            label="Network Interface", value=self.state.interface or "All",
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
                section_title("CAPTURE SETTINGS", icon=ft.Icons.TUNE_ROUNDED, color=CYAN),
                ft.Divider(color=BORDER, height=8),
                self._language_dropdown,
                self._interface_dropdown,
                ft.Text("Changes take effect on the next capture start.",
                        size=11, color=MUTED, italic=True),
            ], spacing=12))

        self._theme_dropdown = ft.Dropdown(
            label="Visual theme", value=self.appearance["theme"], width=250,
            options=[ft.DropdownOption(key, tr(label)) for key, label in (
                ("netpulse", "NetPulse dark"), ("midnight", "Midnight blue"),
                ("graphite", "Graphite"), ("black", "Pure black"),
                ("daylight", "Daylight (light)"), ("paper", "Paper (light)"),
            )],
            bgcolor=SURFACE, color=TEXT, border_color=BORDER,
            focused_border_color=PURPLE,
        )
        self._accent_dropdown = ft.Dropdown(
            label="Accent color", value=self.appearance["accent"], width=220,
            options=[ft.DropdownOption(key, tr(label)) for key, label in (
                ("cyan", "Cyan"), ("blue", "Blue"), ("violet", "Violet"),
                ("magenta", "Magenta"), ("slate", "Slate"),
            )],
            bgcolor=SURFACE, color=TEXT, border_color=BORDER,
            focused_border_color=PURPLE,
        )
        self._density_dropdown = ft.Dropdown(
            label="Interface density", value=self.appearance["density"], width=220,
            options=[ft.DropdownOption(key, tr(label)) for key, label in (
                ("compact", "Compact"), ("standard", "Standard"),
                ("comfortable", "Comfortable"),
            )],
            bgcolor=SURFACE, color=TEXT, border_color=BORDER,
            focused_border_color=PURPLE,
        )
        appearance_card = card(ft.Column([
            section_title("APPEARANCE", icon=ft.Icons.PALETTE_OUTLINED, color=PURPLE),
            ft.Divider(color=BORDER, height=8),
            ft.Text("Customize the interface without restarting NetPulse. "
                    "The accent colours the chrome only; green, amber and red "
                    "stay reserved for status.",
                    color=MUTED, size=11),
            ft.Row([self._theme_dropdown, self._accent_dropdown,
                    self._density_dropdown], spacing=9, wrap=True, run_spacing=9),
            ft.Button(content="APPLY APPEARANCE", icon=ft.Icons.PALETTE_OUTLINED,
                      color=PURPLE, bgcolor=tint(PURPLE, .13),
                      on_click=apply_appearance),
        ], spacing=10))

        self._bw_field = ft.TextField(
            ref=self.r_bw_thresh,
            label="Bandwidth threshold (KB/s)",
            hint_text="e.g. 1000  (0 = disabled)",
            value=f"{self.alerts['bandwidth_kbps']:g}", width=260,
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
            value=f"{self.alerts['packets_per_second']:g}", width=260,
            bgcolor=SURFACE, color=TEXT,
            border_color=BORDER, focused_border_color=AMBER,
            cursor_color=AMBER, text_size=12,
            prefix_icon=ft.Icons.SPEED_ROUNDED,
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self._alert_button = ft.Button(
            content="Save Alerts", icon=ft.Icons.SAVE_ROUNDED,
            on_click=on_save_alerts,
            bgcolor=tint(AMBER, .19), color=AMBER,
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
        )
        self._alert_fields_row = ft.Row(
            [self._bw_field, self._pps_field],
            spacing=10, wrap=True, run_spacing=10,
        )
        alerts_card = card(ft.Column([
                section_title("TRAFFIC ALERTS", icon=ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED, color=AMBER),
                ft.Divider(color=BORDER, height=8),
                ft.Text("Set thresholds to trigger notifications during capture.",
                        size=11, color=MUTED),
                self._alert_fields_row,
                self._alert_button,
                ft.Text(ref=self.r_alert_status,
                        value=self._alert_summary(),
                        size=11, color=self._alert_summary_color()),
            ], spacing=12))

        self._retention_dropdown = ft.Dropdown(
            label="Capture history retention", value=str(self.retention_days),
            width=260, on_select=on_retention,
            options=[ft.DropdownOption(key, tr(label)) for key, label in (
                ("0", "Keep everything"), ("7", "7 days"), ("30", "30 days"),
                ("90", "90 days"), ("365", "365 days"),
            )],
            bgcolor=SURFACE, color=TEXT, border_color=BORDER,
            focused_border_color=CYAN, text_size=12,
        )
        database_card = card(ft.Column([
                section_title("DATABASE  ( SQLite )", icon=ft.Icons.STORAGE_ROUNDED, color=CYAN),
                ft.Divider(color=BORDER, height=8),
                ft.Row([
                    ft.Icon(ft.Icons.STORAGE_ROUNDED, color=CYAN, size=18),
                    ft.Text(str(DEFAULT_DATABASE_PATH), size=11, color=TEXT,
                            selectable=True, expand=True),
                ], spacing=10),
                self._retention_dropdown,
                ft.Text(ref=self.r_retention_status, value=self._retention_summary(),
                        size=11, color=MUTED),
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
                section_title("REQUIREMENTS", icon=ft.Icons.CHECKLIST_ROUNDED, color=AMBER),
                ft.Divider(color=BORDER, height=8),
                check_row("Npcap installed  →  npcap.com"),
                check_row("Python 3.10+"),
                check_row("Run as Administrator  →  scripts/start.bat", AMBER),
                check_row("Internet access for IP Geo-lookup (ip-api.com)", CYAN),
            ], spacing=10))

        # Three cards on the left against two on the right left the right column
        # ending some 270 px higher than the left one, so the bottom of the page
        # was half empty. Requirements is the shortest card, and moving it over
        # brings the two columns within ~140 px of each other.
        left_column = ft.Column(
            [capture_card, database_card], spacing=12,
        )
        right_column = ft.Column(
            [alerts_card, appearance_card, requirements_card], spacing=12,
        )
        self._settings_columns = [left_column, right_column]
        self._settings_body = ft.Row(
            self._settings_columns, spacing=12, wrap=True, run_spacing=12,
            vertical_alignment=ft.CrossAxisAlignment.START,
        )
        self._cards = [
            intro_card, capture_card, appearance_card, alerts_card,
            database_card, requirements_card
        ]
        return ft.Column([
            view_heading("System settings", "Capture source, alert thresholds and local storage",
                         ft.Icons.TUNE_ROUNDED, CYAN),
            intro_card,
            ft.Row([
                ft.Icon(ft.Icons.CONTENT_COPY_ROUNDED, color=CYAN, size=14),
                ft.Text("Tip: drag over any result text to select it, then press Ctrl+C.",
                        color=MUTED, size=10),
            ], spacing=7),
            self._settings_body,
        ], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)

    def set_viewport(self, width: float, height: float):
        content_width = fit(max(280.0, width - 28.0))
        content_height = fit(max(420.0, height - 28.0))
        mode = "wide" if content_width >= 600 else "compact" if content_width >= 420 else "narrow"
        key = (mode, content_width, content_height)
        if key == self._layout_key or not self._cards:
            return
        self._layout_key = key
        self._cards[0].width = content_width
        self._settings_body.width = content_width

        if mode == "wide":
            # 44/56 gives the alert and appearance forms the wider side; the
            # pair still has to end flush with the intro card above it.
            left = snap(content_width * 0.44 - 6)
            column_widths = (left, content_width - 12 - left)
        else:
            column_widths = (content_width, content_width)

        self._settings_columns[0].width, self._settings_columns[1].width = column_widths
        for control in (self._cards[1], self._cards[4]):
            control.width = column_widths[0]
        for control in (self._cards[2], self._cards[3], self._cards[5]):
            control.width = column_widths[1]

        for control in self._cards[1:]:
            control.height = None
            control.expand = False
        for column in self._settings_columns:
            column.height = None
        capture_inner = fit(max(220.0, column_widths[0] - 28.0))
        # Language and interface sat at 240 px and 500 px inside the same card,
        # which read as two unrelated forms. They share one measure now.
        #
        # That measure used to be capped at 420 px. On a maximized window the
        # capture column is ~770 px wide, so the cap left a 320 px hole to the
        # right of every field while the alert and appearance cards opposite
        # them filled their own row edge to edge — the two columns read as
        # different designs. The fields now take the card they live in.
        field_measure = capture_inner
        self._interface_dropdown.width = field_measure
        self._language_dropdown.width = field_measure
        self._retention_dropdown.width = field_measure
        alert_inner = fit(max(220.0, column_widths[1] - 28.0))
        self._alert_fields_row.width = alert_inner
        # Two pixels of slack keep the pair on one line: an exact half plus the
        # 10 px gap rounds above the row width and the fields wrapped. Below
        # ~330 px the threshold captions themselves wrap over the field border,
        # so the pair stacks and each field takes the full column instead.
        half = float(int(max(160.0, (alert_inner - 12.0) / 2)))
        field_width = half if mode == "wide" and half >= 330.0 else alert_inner
        self._bw_field.width = field_width
        self._pps_field.width = field_width



# ── 6. PROCESSES ────────────────────────────────────────────────────────

class _LegacyProcessView:
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
        content_width = fit(max(280.0, width - 28.0))
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


# Kept in its own module so application telemetry can evolve without growing
# this already large collection of views.
from .application_traffic import ProcessView


