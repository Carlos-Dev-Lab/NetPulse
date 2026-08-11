"""User-focused application network activity view."""

from datetime import datetime
from pathlib import Path

import flet as ft

from netpulse.domain.state import AppState
from netpulse.services.ip_info import geo_cache
from .i18n import tr, translate_tree, get_language
from .theme import (
    AMBER, BLUE, BORDER, CARD, CYAN, DIM, GREEN, MUTED, PURPLE, RED,
    SURFACE, TEXT, card, tint, view_heading,
)


class ProcessView:
    """Explain local network usage in terms of applications and destinations."""

    _ICONS = {
        "chrome.exe": "🌐", "firefox.exe": "🦊", "msedge.exe": "🌐",
        "discord.exe": "💬", "slack.exe": "💬", "teams.exe": "💬",
        "steam.exe": "🎮", "explorer.exe": "🗂️", "svchost.exe": "⚙️",
        "python.exe": "🐍", "pythonw.exe": "🐍", "node.exe": "🟩",
        "spotify.exe": "🎵", "zoom.exe": "📹", "code.exe": "💻",
        "onedrive.exe": "☁️", "dropbox.exe": "☁️", "curl.exe": "🌐",
    }

    def __init__(self, state: AppState, page_ref=None):
        self.s = state
        self._page = page_ref
        self.r_table = ft.Ref[ft.Column]()
        self.r_search = ft.Ref[ft.TextField]()
        self.r_filter = ft.Ref[ft.Dropdown]()
        self.r_active = ft.Ref[ft.Text]()
        self.r_download = ft.Ref[ft.Text]()
        self.r_upload = ft.Ref[ft.Text]()
        self.r_destinations = ft.Ref[ft.Text]()
        self.r_top = ft.Ref[ft.Text]()
        # Compatibility refs used by existing smoke tests and integrations.
        self.r_total = ft.Ref[ft.Text]()
        self.r_procs = ft.Ref[ft.Text]()
        self._empty_control = None
        self._summary_cards = []
        self._root = None
        self._list_card = None
        self._layout_key = None
        self._name_width = 230.0
        self._traffic_width = 112.0
        self._dest_width = 78.0

    @staticmethod
    def _bytes(value: int) -> str:
        if value < 1024:
            return f"{value} B"
        if value < 1_048_576:
            return f"{value / 1024:.1f} KB"
        if value < 1_073_741_824:
            return f"{value / 1_048_576:.2f} MB"
        return f"{value / 1_073_741_824:.2f} GB"

    @staticmethod
    def _rate(value: float) -> str:
        return f"{value:.1f} KB/s" if value < 1024 else f"{value / 1024:.2f} MB/s"

    @staticmethod
    def _is_active(app: dict) -> bool:
        if app.get("rate_in", 0) + app.get("rate_out", 0) > 0:
            return True
        last = app.get("last_seen")
        return isinstance(last, datetime) and (datetime.now() - last).total_seconds() <= 3

    def _icon(self, name: str) -> str:
        return self._ICONS.get(name.lower(), "📦")

    def _metric(self, label, ref, color, icon):
        control = card(ft.Row([
            ft.Container(ft.Icon(icon, color=color, size=22),
                         bgcolor=tint(color, .09), border_radius=10, padding=8),
            ft.Column([
                ft.Text(label, color=MUTED, size=8, weight=ft.FontWeight.W_700),
                ft.Text(ref=ref, value="0", color=color, size=17,
                        weight=ft.FontWeight.W_700, font_family="monospace",
                        overflow=ft.TextOverflow.ELLIPSIS),
            ], spacing=1, expand=True),
        ], spacing=8), padding=10)
        self._summary_cards.append(control)
        return control

    def build(self):
        def apply_filter(e=None):
            self.refresh()
            control = self.r_table.current
            if control:
                try:
                    control.update()
                except RuntimeError:
                    pass

        summary = ft.Row([
            self._metric("ACTIVE NOW", self.r_active, GREEN, ft.Icons.BOLT_ROUNDED),
            self._metric("DOWNLOADED", self.r_download, CYAN, ft.Icons.ARROW_DOWNWARD_ROUNDED),
            self._metric("UPLOADED", self.r_upload, PURPLE, ft.Icons.ARROW_UPWARD_ROUNDED),
            self._metric("DESTINATIONS", self.r_destinations, BLUE, ft.Icons.PUBLIC_ROUNDED),
            self._metric("TOP APPLICATION", self.r_top, AMBER, ft.Icons.LEADERBOARD_ROUNDED),
        ], spacing=10, wrap=True, run_spacing=10)
        self._summary_row = summary

        filters = ft.Row([
            ft.TextField(
                ref=self.r_search, label="Search application, PID, domain or IP",
                prefix_icon=ft.Icons.SEARCH_ROUNDED, expand=True,
                bgcolor=SURFACE, color=TEXT, border_color=BORDER,
                focused_border_color=CYAN, text_size=11, on_change=apply_filter,
            ),
            ft.Dropdown(
                ref=self.r_filter, value="all", width=190, dense=True,
                options=[
                    ft.DropdownOption("all", "All applications"),
                    ft.DropdownOption("active", "Active now"),
                    ft.DropdownOption("download", "Highest download"),
                    ft.DropdownOption("upload", "Highest upload"),
                    ft.DropdownOption("unknown", "Unidentified processes"),
                ],
                on_select=apply_filter, bgcolor=CARD, fill_color=CARD, filled=True,
                color=TEXT, border_color=BORDER, focused_border_color=CYAN,
                menu_style=ft.MenuStyle(bgcolor=CARD, elevation=14),
            ),
        ], spacing=9)
        self._filter_row = filters

        self._empty_control = ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.APPS_ROUNDED, color=MUTED, size=40),
                ft.Text("No application traffic available", color=DIM, size=13,
                        weight=ft.FontWeight.W_600),
                ft.Text("Start monitoring and generate network activity.",
                        color=MUTED, size=11),
            ], spacing=6, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            alignment=ft.Alignment.CENTER, expand=True, padding=30,
        )
        self._legend = ft.Row([
            ft.Container(ft.Text("Application", size=9, color=MUTED), width=self._name_width),
            ft.Container(ft.Text("Download", size=9, color=MUTED), width=self._traffic_width),
            ft.Container(ft.Text("Upload", size=9, color=MUTED), width=self._traffic_width),
            ft.Container(ft.Text("Destinations", size=9, color=MUTED), width=self._dest_width),
            ft.Text("Activity", size=9, color=MUTED, expand=True),
        ], spacing=8)
        table = ft.Column(ref=self.r_table, controls=[self._empty_control],
                          spacing=7, scroll=ft.ScrollMode.AUTO, expand=True)
        self._list_card = card(ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.APPS_ROUNDED, color=GREEN, size=20),
                ft.Text("WHAT IS USING YOUR NETWORK", color=TEXT, size=12,
                        weight=ft.FontWeight.W_700),
                ft.Container(expand=True),
                ft.Text(ref=self.r_procs, value="0 processes", color=MUTED, size=10),
                ft.Text(ref=self.r_total, value="0 KB total", color=CYAN, size=10,
                        font_family="monospace"),
            ], spacing=8),
            filters,
            self._legend,
            ft.Divider(color=BORDER, height=4),
            table,
        ], spacing=8, expand=True), expand=True)
        self._root = ft.Column([
            view_heading("Application traffic",
                         "Understand which applications communicate, where and how much",
                         ft.Icons.APPS_ROUNDED, GREEN),
            summary,
            self._list_card,
        ], spacing=12, expand=True)
        return self._root

    def set_viewport(self, width: float, height: float):
        content_width = max(280.0, width - 28.0)
        mode = "wide" if content_width >= 900 else "compact" if content_width >= 620 else "narrow"
        key = (mode, round(content_width), round(height))
        if key == self._layout_key or not self._root:
            return
        self._layout_key = key
        columns = 5 if mode == "wide" else 2 if mode == "compact" else 1
        metric_width = (content_width - 10 * (columns - 1)) / columns
        for metric in self._summary_cards:
            metric.width = metric_width
        self._name_width = 250 if mode == "wide" else 180 if mode == "compact" else 125
        self._traffic_width = 118 if mode == "wide" else 92 if mode == "compact" else 72
        self._dest_width = 82 if mode != "narrow" else 64
        for control, value in zip(
            self._legend.controls[:4],
            (self._name_width, self._traffic_width, self._traffic_width, self._dest_width),
        ):
            control.width = value
        self._filter_row.wrap = mode == "narrow"
        self.r_search.current.width = content_width if mode == "narrow" else None

    def _apps(self) -> list[dict]:
        if self.s.app_traffic:
            raw_apps = list(self.s.app_traffic.values())
        else:
            # Safe compatibility with state produced before detailed telemetry.
            raw_apps = [
            {
                "key": name, "pid": None, "name": name, "b": data["b"], "p": data["p"],
                "bytes_in": 0, "bytes_out": data["b"], "packets_in": 0,
                "packets_out": data["p"], "rate_in": 0.0, "rate_out": 0.0,
                "protocols": {}, "destinations": {}, "last_seen": None,
            }
            for name, data in self.s.proc_traffic.items()
            ]
        grouped: dict[str, dict] = {}
        for instance in raw_apps:
            group_key = instance["name"].casefold()
            group = grouped.setdefault(group_key, {
                "key": group_key, "pid": instance.get("pid"), "pids": [],
                "name": instance["name"], "instances": [], "instance_count": 0,
                "active_instances": 0, "b": 0, "p": 0,
                "bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0,
                "rate_in": 0.0, "rate_out": 0.0, "protocols": {},
                "rate_pps": 0.0, "peak_rate": 0.0, "peak_pps": 0.0,
                "average_rate": 0.0, "spike_events": [], "rate_history": [],
                "destinations": {}, "first_seen": instance.get("first_seen"),
                "last_seen": instance.get("last_seen"),
            })
            group["instances"].append(instance)
            group["instance_count"] += 1
            if instance.get("pid") is not None:
                group["pids"].append(instance["pid"])
            if self._is_active(instance):
                group["active_instances"] += 1
            for field in (
                "b", "p", "bytes_in", "bytes_out", "packets_in", "packets_out",
                "rate_in", "rate_out",
            ):
                group[field] += instance.get(field, 0)
            group["rate_pps"] += instance.get("rate_pps", 0)
            group["average_rate"] += instance.get("average_rate", 0)
            group["spike_events"].extend(instance.get("spike_events", []))
            group["rate_history"].extend(instance.get("rate_history", []))
            for protocol, count in instance.get("protocols", {}).items():
                group["protocols"][protocol] = group["protocols"].get(protocol, 0) + count
            first_seen = instance.get("first_seen")
            last_seen = instance.get("last_seen")
            if first_seen and (not group["first_seen"] or first_seen < group["first_seen"]):
                group["first_seen"] = first_seen
            if last_seen and (not group["last_seen"] or last_seen > group["last_seen"]):
                group["last_seen"] = last_seen
            for ip, item in instance.get("destinations", {}).items():
                destination = group["destinations"].setdefault(ip, {
                    "ip": ip, "bytes_in": 0, "bytes_out": 0, "packets": 0,
                    "ports": set(), "protocols": set(),
                    "first_seen": item.get("first_seen"),
                    "last_seen": item.get("last_seen"),
                })
                destination["bytes_in"] += item.get("bytes_in", 0)
                destination["bytes_out"] += item.get("bytes_out", 0)
                destination["packets"] += item.get("packets", 0)
                destination["ports"].update(item.get("ports", set()))
                destination["protocols"].update(item.get("protocols", set()))
                if item.get("first_seen") and (
                    not destination["first_seen"]
                    or item["first_seen"] < destination["first_seen"]
                ):
                    destination["first_seen"] = item["first_seen"]
                if item.get("last_seen") and (
                    not destination["last_seen"]
                    or item["last_seen"] > destination["last_seen"]
                ):
                    destination["last_seen"] = item["last_seen"]
        for group in grouped.values():
            group["pids"] = sorted(set(group["pids"]))
            group["pid"] = group["pids"][0] if len(group["pids"]) == 1 else None
            group["spike_events"].sort(key=lambda item: item["ts"], reverse=True)
            combined_history = {}
            for sample in group["rate_history"]:
                point = combined_history.setdefault(
                    sample["ts"], {"ts": sample["ts"], "in": 0.0, "out": 0.0, "pps": 0.0}
                )
                point["in"] += sample["in"]
                point["out"] += sample["out"]
                point["pps"] += sample["pps"]
            group["rate_history"] = sorted(
                combined_history.values(), key=lambda item: item["ts"]
            )[-150:]
            if group["rate_history"]:
                group["peak_rate"] = max(
                    item["in"] + item["out"] for item in group["rate_history"]
                )
                group["peak_pps"] = max(item["pps"] for item in group["rate_history"])
        return list(grouped.values())

    def refresh(self):
        if not self.r_table.current:
            return
        apps = self._apps()
        total = sum(app["b"] for app in apps)
        active = [app for app in apps if self._is_active(app)]
        all_destinations = {ip for app in apps for ip in app["destinations"]}
        download = sum(app["bytes_in"] for app in apps)
        upload = sum(app["bytes_out"] for app in apps)
        top_name = max(apps, key=lambda app: app["b"])["name"] if apps else "—"
        if self.r_active.current:
            self.r_active.current.value = str(len(active))
            self.r_download.current.value = self._bytes(download)
            self.r_upload.current.value = self._bytes(upload)
            self.r_destinations.current.value = str(len(all_destinations))
            self.r_top.current.value = top_name
        if self.r_procs.current:
            instance_count = sum(app.get("instance_count", 1) for app in apps)
            self.r_procs.current.value = (
                f"0 {tr('processes')}" if not apps else
                f"{len(apps)} {tr('applications')} · {instance_count} {tr('processes')}"
            )
        if self.r_total.current:
            self.r_total.current.value = "0 KB total" if not total else f"{self._bytes(total)} total"

        query = (self.r_search.current.value or "").strip().casefold() if self.r_search.current else ""
        mode = self.r_filter.current.value if self.r_filter.current else "all"
        filtered = []
        for app in apps:
            destination_text = " ".join(
                f"{ip} {geo_cache.get_domain(ip)} {geo_cache.get_asn(ip)}"
                for ip in app["destinations"]
            ).casefold()
            haystack = (
                f"{app['name']} {' '.join(map(str, app.get('pids', [])))} "
                f"{destination_text}"
            ).casefold()
            if query and query not in haystack:
                continue
            if mode == "active" and not self._is_active(app):
                continue
            if mode == "unknown" and app.get("pid") and app["name"]:
                continue
            filtered.append(app)
        sort_key = "bytes_in" if mode == "download" else "bytes_out" if mode == "upload" else "b"
        filtered.sort(key=lambda app: -app[sort_key])

        if not filtered:
            self.r_table.current.controls = [self._empty_control]
            return
        total = total or 1
        rows = []
        for app in filtered[:50]:
            active_now = self._is_active(app)
            share = app["b"] / total
            intensity = RED if share > .5 else AMBER if share > .2 else CYAN if share > .05 else GREEN
            rate = app["rate_in"] + app["rate_out"]
            rows.append(ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Container(
                            ft.Row([
                                ft.Text(self._icon(app["name"]), size=18),
                                ft.Column([
                                    ft.Text(app["name"], color=TEXT, size=10,
                                            weight=ft.FontWeight.W_700,
                                            overflow=ft.TextOverflow.ELLIPSIS),
                                    ft.Text(
                                        (
                                            f"PID {app.get('pid') or 'unknown'}"
                                            if app.get("instance_count", 1) == 1
                                            else f"{app['instance_count']} {tr('instances')} · "
                                                 f"{app['active_instances']} {tr('active')}"
                                        ) + f" · {tr('Active now') if active_now else tr('Inactive')}",
                                        color=GREEN if active_now else MUTED, size=8,
                                    ),
                                ], spacing=1, expand=True),
                            ], spacing=7),
                            width=self._name_width,
                        ),
                        ft.Container(ft.Text(f"↓ {self._bytes(app['bytes_in'])}",
                                             color=CYAN, size=9, font_family="monospace"),
                                     width=self._traffic_width),
                        ft.Container(ft.Text(f"↑ {self._bytes(app['bytes_out'])}",
                                             color=PURPLE, size=9, font_family="monospace"),
                                     width=self._traffic_width),
                        ft.Container(ft.Text(str(len(app["destinations"])), color=BLUE,
                                             size=9, font_family="monospace"),
                                     width=self._dest_width),
                        ft.Column([
                            ft.Text(
                                f"{self._rate(rate)} · {share * 100:.1f}%",
                                color=intensity, size=8, font_family="monospace",
                            ),
                            ft.ProgressBar(value=share, color=intensity,
                                           bgcolor=tint(intensity, .12), height=5,
                                           border_radius=3),
                        ], spacing=2, expand=True),
                        ft.Icon(ft.Icons.CHEVRON_RIGHT_ROUNDED, color=MUTED, size=18),
                    ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ], spacing=3),
                bgcolor=tint(intensity, .025), border=ft.Border.all(1, tint(intensity, .14)),
                border_radius=9, padding=8, ink=True, data=app["key"],
                tooltip="Open application network details",
                on_click=lambda e, item=app: self._show_details(item),
            ))
        self.r_table.current.controls = rows

    def _show_details(self, app: dict):
        if not self._page or not self._page[0]:
            return
        page = self._page[0]
        executable_paths = []
        try:
            import psutil
            for pid in app.get("pids", []):
                try:
                    path = psutil.Process(pid).exe()
                    if path and path not in executable_paths:
                        executable_paths.append(path)
                except Exception:
                    continue
        except Exception:
            executable_paths = []

        destinations = sorted(
            app["destinations"].values(),
            key=lambda item: -(item["bytes_in"] + item["bytes_out"]),
        )
        destination_controls = []
        for destination in destinations[:25]:
            ip = destination["ip"]
            label = geo_cache.get_label(ip) or "Unresolved destination"
            age = (
                (datetime.now() - destination["last_seen"]).total_seconds()
                if destination.get("last_seen") else 999
            )
            connection_state = "ACTIVE" if age <= 10 else "RECENT"
            dominant_direction = (
                "mostly incoming" if destination["bytes_in"] > destination["bytes_out"] * 1.5
                else "mostly outgoing" if destination["bytes_out"] > destination["bytes_in"] * 1.5
                else "bidirectional"
            )
            destination_controls.append(ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Text(ip, color=CYAN, size=10, font_family="monospace"),
                        ft.Text(connection_state, color=GREEN if age <= 10 else MUTED,
                                size=7, weight=ft.FontWeight.W_700),
                        ft.Text(" · ".join(sorted(destination["protocols"])),
                                color=AMBER, size=8),
                        ft.Container(expand=True),
                        ft.Text(f"↓ {self._bytes(destination['bytes_in'])}",
                                color=CYAN, size=8, font_family="monospace"),
                        ft.Text(f"↑ {self._bytes(destination['bytes_out'])}",
                                color=PURPLE, size=8, font_family="monospace"),
                    ], spacing=6),
                    ft.Text(label, color=MUTED, size=8),
                    ft.Text(
                        "Ports: " + (", ".join(map(str, sorted(destination["ports"]))) or "—")
                        + f" · {dominant_direction}"
                        + (
                            f" · Last activity {destination['last_seen']:%H:%M:%S}"
                            if destination.get("last_seen") else ""
                        ),
                        color=MUTED, size=8,
                    ),
                ], spacing=2),
                bgcolor=tint(CYAN, .03), border=ft.Border.all(1, tint(CYAN, .12)),
                border_radius=7, padding=7,
            ))
        packet_controls = []
        for packet in reversed(self.s.live):
            if packet.proc_name.casefold() != app["name"].casefold() or (
                app.get("pids") and packet.pid not in app["pids"]
            ):
                continue
            packet_controls.append(ft.Text(
                f"{packet.ts:%H:%M:%S.%f}"[:-3]
                + f" · {packet.direction} · {packet.protocol} · "
                + f"{packet.src}:{packet.sport or '-'} → {packet.dst}:{packet.dport or '-'}"
                + f" · {packet.size} B"
                + (f" · {packet.info}" if packet.info else ""),
                color=MUTED, size=8, font_family="monospace", selectable=True,
            ))
            if len(packet_controls) >= 20:
                break

        protocols = ", ".join(
            f"{name} {count}" for name, count in
            sorted(app["protocols"].items(), key=lambda item: -item[1])
        ) or "No protocol information"
        total_packets = app["p"] or 1
        udp_share = app["protocols"].get("UDP", 0) / total_packets
        encrypted_share = app["protocols"].get("HTTPS", 0) / total_packets
        average_packet = app["b"] / total_packets
        insight_controls = []

        def insight(icon, title, detail, color):
            insight_controls.append(ft.Container(
                content=ft.Row([
                    ft.Icon(icon, color=color, size=16),
                    ft.Column([
                        ft.Text(title, color=TEXT, size=9, weight=ft.FontWeight.W_700),
                        ft.Text(detail, color=MUTED, size=8),
                    ], spacing=1, expand=True),
                ], spacing=7),
                bgcolor=tint(color, .035), border=ft.Border.all(1, tint(color, .14)),
                border_radius=7, padding=7,
            ))

        if app.get("spike_events"):
            latest = app["spike_events"][0]
            dominant = "download" if latest["rate_in"] >= latest["rate_out"] else "upload"
            insight(
                ft.Icons.SSID_CHART_ROUNDED, "Network spike detected",
                f"{latest['ts']:%H:%M:%S} · {self._rate(latest['rate'])} · "
                f"mainly {dominant} · normal baseline {self._rate(latest['baseline'])}.",
                AMBER,
            )
        if udp_share >= .5 and app.get("peak_pps", 0) >= 5:
            insight(
                ft.Icons.SPORTS_ESPORTS_ROUNDED, "Real-time UDP pattern",
                f"{udp_share * 100:.0f}% UDP · peak {app['peak_pps']:.0f} pkt/s · "
                "consistent with gaming, voice or streaming; this is not proof of game traffic.",
                GREEN,
            )
        if app["bytes_out"] > max(102_400, app["bytes_in"] * 2):
            insight(
                ft.Icons.UPLOAD_ROUNDED, "Upload-heavy activity",
                f"Sent {self._bytes(app['bytes_out'])} versus "
                f"{self._bytes(app['bytes_in'])} received. Review destinations if unexpected.",
                AMBER,
            )
        if app["protocols"].get("HTTP", 0):
            insight(
                ft.Icons.NO_ENCRYPTION_ROUNDED, "Unencrypted HTTP observed",
                "Traffic metadata and possibly content may be readable on the local network.",
                RED,
            )
        if len(destinations) >= 20:
            insight(
                ft.Icons.HUB_ROUNDED, "Many remote destinations",
                f"{len(destinations)} unique IPs observed. This can be normal for browsers and CDNs.",
                BLUE,
            )
        if not insight_controls:
            insight(
                ft.Icons.CHECK_CIRCLE_OUTLINE_ROUNDED, "No notable pattern detected",
                "Current metadata does not show a spike or an obvious traffic pattern.",
                GREEN,
            )

        visibility_text = (
            f"{encrypted_share * 100:.0f}% of observed packets use HTTPS/TLS. "
            "For encrypted traffic NetPulse can show direction, size, timing, destination, "
            "port and application—but not the exact message, file contents or credentials. "
            f"Average packet size: {average_packet:.0f} B."
        )
        spike_controls = [
            ft.Text(
                f"{event['ts']:%H:%M:%S} · {self._rate(event['rate'])} "
                f"(↓ {self._rate(event['rate_in'])}, ↑ {self._rate(event['rate_out'])}) "
                f"· baseline {self._rate(event['baseline'])}",
                color=AMBER, size=8, font_family="monospace",
            )
            for event in app.get("spike_events", [])[:10]
        ]
        content = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Container(ft.Text(self._icon(app["name"]), size=28),
                                 bgcolor=tint(GREEN, .08), border_radius=10, padding=9),
                    ft.Column([
                        ft.Text(app["name"], color=TEXT, size=15,
                                weight=ft.FontWeight.W_700),
                        ft.Text(
                            (
                                f"PID {app.get('pid') or 'unknown'}"
                                if app.get("instance_count", 1) == 1
                                else f"{app['instance_count']} {tr('instances')} · "
                                     + ", ".join(f"PID {pid}" for pid in app["pids"])
                            ),
                            color=MUTED, size=9,
                        ),
                        ft.Text(" · ".join(executable_paths) or "Executable path unavailable",
                                color=MUTED, size=8, selectable=True,
                                overflow=ft.TextOverflow.ELLIPSIS),
                    ], spacing=2, expand=True),
                ], spacing=9),
                ft.Container(
                    content=ft.Column([
                        ft.Text("PROCESS INSTANCES", color=MUTED, size=8,
                                weight=ft.FontWeight.W_700),
                        *[
                            ft.Row([
                                ft.Text(f"PID {instance.get('pid') or 'unknown'}",
                                        color=TEXT, size=9, width=100),
                                ft.Text(
                                    tr("ACTIVE") if self._is_active(instance) else tr("INACTIVE"),
                                    color=GREEN if self._is_active(instance) else MUTED,
                                    size=8, width=62,
                                ),
                                ft.Text(f"↓ {self._bytes(instance.get('bytes_in', 0))}",
                                        color=CYAN, size=8),
                                ft.Text(f"↑ {self._bytes(instance.get('bytes_out', 0))}",
                                        color=PURPLE, size=8),
                                ft.Text(f"{len(instance.get('destinations', {}))} {tr('destinations')}",
                                        color=BLUE, size=8),
                            ], spacing=7)
                            for instance in sorted(
                                app.get("instances", []),
                                key=lambda item: -item.get("b", 0),
                            )
                        ],
                    ], spacing=4),
                    visible=app.get("instance_count", 1) > 1,
                    bgcolor=tint(BLUE, .035), border=ft.Border.all(1, tint(BLUE, .13)),
                    border_radius=8, padding=8,
                ),
                ft.Row([
                    self._detail_metric("DOWNLOADED", self._bytes(app["bytes_in"]), CYAN),
                    self._detail_metric("UPLOADED", self._bytes(app["bytes_out"]), PURPLE),
                    self._detail_metric("DESTINATIONS", str(len(destinations)), BLUE),
                    self._detail_metric("PACKETS", f"{app['p']:,}", AMBER),
                ], spacing=7, wrap=True, run_spacing=7),
                ft.Text("WHAT CAN BE SEEN", color=TEXT, size=9,
                        weight=ft.FontWeight.W_700),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.LOCK_OUTLINE_ROUNDED, color=BLUE, size=17),
                        ft.Text(visibility_text, color=MUTED, size=8, expand=True),
                    ], spacing=7),
                    bgcolor=tint(BLUE, .035), border=ft.Border.all(1, tint(BLUE, .14)),
                    border_radius=7, padding=8,
                ),
                ft.Text("TRAFFIC INSIGHTS", color=TEXT, size=9,
                        weight=ft.FontWeight.W_700),
                ft.Column(insight_controls, spacing=5),
                ft.Container(
                    content=ft.Column([
                        ft.Text("SPIKE HISTORY", color=MUTED, size=8,
                                weight=ft.FontWeight.W_700),
                        *(spike_controls or [
                            ft.Text("No significant spikes recorded in this session.",
                                    color=MUTED, size=8)
                        ]),
                    ], spacing=3),
                    bgcolor=tint(AMBER, .025), border_radius=7, padding=7,
                ),
                ft.Text(f"Protocols: {protocols}", color=MUTED, size=9),
                ft.Text("REMOTE CONNECTIONS", color=TEXT, size=9,
                        weight=ft.FontWeight.W_700),
                ft.Column(destination_controls or [
                    ft.Text("No destination information available.", color=MUTED, size=9)
                ], spacing=5),
                ft.Text("RECENT PACKET EVIDENCE", color=TEXT, size=9,
                        weight=ft.FontWeight.W_700),
                ft.Column(packet_controls or [
                    ft.Text("No matching packets remain in the live buffer.",
                            color=MUTED, size=9)
                ], spacing=2),
            ], spacing=9, scroll=ft.ScrollMode.AUTO),
            width=720, height=610,
        )

        def close(e=None):
            try:
                page.pop_dialog()
            except AttributeError:
                page.dialog.open = False
            page.update()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("APPLICATION NETWORK ACTIVITY", color=TEXT, size=13,
                          weight=ft.FontWeight.W_700),
            content=content,
            actions=[ft.TextButton("Close", on_click=close)],
            bgcolor=SURFACE, barrier_color="#77000000",
            shape=ft.RoundedRectangleBorder(radius=14),
        )
        translate_tree(dialog, get_language())
        if hasattr(page, "show_dialog"):
            page.show_dialog(dialog)
        else:
            page.dialog = dialog
            dialog.open = True
            page.update()

    @staticmethod
    def _detail_metric(label: str, value: str, color: str):
        return ft.Container(
            content=ft.Column([
                ft.Text(label, color=MUTED, size=7, weight=ft.FontWeight.W_700),
                ft.Text(value, color=color, size=11, weight=ft.FontWeight.W_700,
                        font_family="monospace"),
            ], spacing=1),
            width=150, bgcolor=tint(color, .045), border=ft.Border.all(1, tint(color, .14)),
            border_radius=7, padding=7,
        )
