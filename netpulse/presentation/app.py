"""Application composition root and Flet event loop."""

import asyncio
import time
from collections import defaultdict
import logging
import os

import flet as ft

from netpulse.config import (
    DEFAULT_DATABASE_PATH, ensure_runtime_directories, load_alerts,
    load_appearance, load_interface, load_language, load_retention_days,
    save_appearance, save_interface, save_language,
)
from netpulse.domain.state import AppState
from netpulse.logging_setup import configure_logging
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import NmapScanner
from netpulse.infrastructure.sniffer import Sniffer, list_interfaces
from netpulse.services.ip_info import geo_cache
from .charts import apply_palette as apply_chart_palette
from .theme import (
    AMBER, BG, BORDER, CARD, CYAN, GREEN, MUTED, PALETTE_ROLES, RED, SURFACE, TEXT,
    accented, appearance_palette, apply_accent, clear_accent_registry,
    make_theme, recolor_tree, selectable_content, set_active_palette,
    theme_mode, tint,
)
from .views import (
    ChartsView, DashboardView, HistoryView, LocalPortsView, NetworkView,
    PacketsView, ProcessView, SettingsView,
)
from .data_management import DataManagementView
from .dialogs import close_dialog, open_dialog
from .i18n import set_language, tr, translate_tree


UPDATE_INTERVAL_SECONDS = 0.2
DATABASE_FLUSH_TICKS = 5
logger = logging.getLogger(__name__)


def main(page: ft.Page):
    # ── Page config ────────────────────────────────────────────────────
    appearance = load_appearance()
    current_palette = [appearance_palette(appearance["theme"], appearance["accent"])]
    densities = {
        "compact": ft.VisualDensity.COMPACT,
        "standard": ft.VisualDensity.STANDARD,
        "comfortable": ft.VisualDensity.COMFORTABLE,
    }
    clear_accent_registry()
    set_active_palette(current_palette[0])
    apply_chart_palette(current_palette[0])
    page.title      = "NetPulse — Network Analyzer"
    page.bgcolor    = current_palette[0]["bg"]
    page.theme      = make_theme(current_palette[0]["accent"], current_palette[0]["surface"],
                                 densities[appearance["density"]],
                                 palette=current_palette[0])
    page.theme_mode = theme_mode(current_palette[0])
    page.padding    = 0
    # Flet uses logical pixels and Windows applies DPI scaling afterwards.
    # 1080x660 remains fully visible on a 1707x1067 desktop at 150% scaling,
    # while the dashboard still has room for its four primary metrics.
    page.window.width      = 1080
    page.window.height     = 660
    page.window.min_width  = 900
    page.window.min_height = 620
    page.window.bgcolor    = current_palette[0]["bg"]
    # NetPulse is an operations workspace: start maximized so analytical views
    # use the available desktop instead of booting directly into compact mode.
    # The dimensions above remain the safe restored-window size.
    page.window.maximized  = True

    # ── Core objects ───────────────────────────────────────────────────
    ensure_runtime_directories()
    configure_logging()
    state   = AppState(ip_enricher=geo_cache)
    # Capture preferences survive restarts so an operator does not have to
    # re-select the adapter and re-enter thresholds on every launch.
    state.interface = load_interface()
    persisted_alerts = load_alerts()
    state.alert_bw_thresh = persisted_alerts["bandwidth_kbps"]
    state.alert_pps_thresh = persisted_alerts["packets_per_second"]
    sniffer = Sniffer()
    nmap_scanner = NmapScanner()
    db      = DB(DEFAULT_DATABASE_PATH)
    retention_days = load_retention_days()
    try:
        removed = db.purge_old_sessions(retention_days)
        if removed:
            logger.info("Removed %d capture sessions beyond retention", removed)
    except Exception:
        logger.exception("Could not apply the capture history retention policy")
    _page_ref = [page]  # mutable ref for sub-views
    _closing = [False]
    language = [load_language()]
    set_language(language[0])

    def on_language_change(code: str):
        language[0] = code
        set_language(code)
        save_language(code)
        try:
            translate_tree(app_layout, code)
            for chart in (
                dash.line_chart, dash.pie_chart, chart_v.line_chart,
                chart_v.bar_chart, dash.spark_cpu, dash.spark_ram,
            ):
                canvas = getattr(chart, "_canvas", None)
                if canvas is not None:
                    canvas.shapes = chart._build_shapes()
            page.update()
        except NameError:
            pass

    def on_appearance_change(theme_name: str, accent_name: str, density_name: str):
        old_palette = current_palette[0]
        new_palette = appearance_palette(theme_name, accent_name)
        save_appearance(theme_name, accent_name, density_name)
        page.bgcolor = new_palette["bg"]
        page.window.bgcolor = new_palette["bg"]
        page.theme = make_theme(
            new_palette["accent"], new_palette["surface"],
            densities.get(density_name, ft.VisualDensity.STANDARD),
            palette=new_palette,
        )
        # Light themes need the matching brightness, otherwise Flet keeps
        # painting its own dark chrome behind the recoloured controls.
        page.theme_mode = theme_mode(new_palette)
        set_active_palette(new_palette)
        apply_chart_palette(new_palette)
        try:
            _repaint(old_palette, new_palette)
        except NameError:
            pass
        current_palette[0] = new_palette
        page.update()

    def _repaint(old_palette: dict, new_palette: dict) -> None:
        """Repaint the whole workspace, not only the section on screen.

        Flet only reaches the mounted wrapper through ``main_content``; the other
        the remaining sections live in ``wrappers`` and would keep the previous palette
        until they were rebuilt. One shared ``seen`` set walks every root exactly
        once.
        """
        seen: set = set()
        recolor_tree(app_layout, old_palette, new_palette, seen)
        for wrapper in wrappers:
            recolor_tree(wrapper, old_palette, new_palette, seen)
        main_content.bgcolor = new_palette["bg"]
        apply_accent(new_palette["accent"])
        _recolor_charts(old_palette, new_palette)

    def _recolor_charts(old_palette: dict, new_palette: dict) -> None:
        """Canvases redraw from Python, so their series colours are swapped here."""
        mapping = {
            old_palette[role].upper(): new_palette[role]
            for role in PALETTE_ROLES + ("accent",)
            if role in old_palette and role in new_palette
            and old_palette[role] != new_palette[role]
        }
        if not mapping:
            return
        for chart in (dash.line_chart, dash.pie_chart, dash.spark_cpu, dash.spark_ram,
                      chart_v.line_chart, chart_v.bar_chart):
            recolor = getattr(chart, "recolor", None)
            if recolor is not None:
                recolor(mapping)

    # ── Views ──────────────────────────────────────────────────────────
    dash    = DashboardView(state)
    net_v   = NetworkView(
        db, nmap_scanner, _page_ref, state,
        notification_sink=lambda title, message: _pending_alerts.append((title, message)),
    )
    ports_v = LocalPortsView(_page_ref)
    pkt_v   = PacketsView(state, _page_ref)
    chart_v = ChartsView(state, _page_ref, db)
    hist_v  = HistoryView(db)
    proc_v  = ProcessView(state, _page_ref)
    def on_interface_change(value: str):
        state.interface = value or "All"
        save_interface(state.interface)
        try:
            if r_iface.current:
                r_iface.current.value = state.interface
                r_iface.current.update()
        except NameError:
            pass

    sett_v  = SettingsView(
        state, language[0], on_language_change,
        appearance=appearance, on_appearance_change=on_appearance_change,
        on_interface_change=on_interface_change,
        alerts=persisted_alerts, retention_days=retention_days,
    )
    data_v = DataManagementView(db, _page_ref, state)

    try:
        initial_view = max(0, min(8, int(os.getenv("NETPULSE_INITIAL_VIEW", "0"))))
    except ValueError:
        initial_view = 0
    _active = [initial_view]

    def _wrap(v):
        return ft.Container(
            content=selectable_content(v), expand=True, visible=True,
            padding=ft.padding.Padding.only(left=14, top=14, right=14, bottom=14),
        )

    w_dash  = _wrap(dash.build())
    w_net   = _wrap(net_v.build())
    w_ports = _wrap(ports_v.build())
    w_pkt   = _wrap(pkt_v.build())
    w_chart = _wrap(chart_v.build())
    w_hist  = _wrap(hist_v.build())
    w_proc  = _wrap(proc_v.build())
    w_sett  = _wrap(sett_v.build())
    w_data  = _wrap(data_v.build())
    # Navigation follows the operator's flow: observe, investigate, analyze,
    # review history, then use the administrative tools.
    wrappers = [w_dash, w_net, w_proc, w_pkt, w_chart, w_hist, w_ports, w_data, w_sett]

    # ── Header refs ────────────────────────────────────────────────────
    r_dot    = ft.Ref[ft.Container]()
    r_status = ft.Ref[ft.Text]()
    r_pps_h  = ft.Ref[ft.Text]()
    r_bw_h   = ft.Ref[ft.Text]()
    r_iface  = ft.Ref[ft.Dropdown]()
    r_start  = ft.Ref[ft.Button]()
    r_sb_sess = ft.Ref[ft.Text]()
    r_sb_pkts = ft.Ref[ft.Text]()
    r_sb_time  = ft.Ref[ft.Text]()
    r_sb_drop  = ft.Ref[ft.Text]()

    # ── Capture control ────────────────────────────────────────────────
    def _show_alert_dialog(title: str, msg: str):
        def close(e=None):
            close_dialog(page)
        dialog = ft.AlertDialog(
            modal=False,
            title=ft.Text(title, color=AMBER),
            content=ft.Text(msg, color=TEXT, size=12),
            actions=[ft.TextButton("OK", on_click=close)],
            bgcolor=CARD,
        )
        translate_tree(dialog, language[0])
        open_dialog(page, dialog)

    def _err(msg: str):
        def close(e=None):
            close_dialog(page)
        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.ERROR_OUTLINE_ROUNDED, color=RED, size=18),
                ft.Text("Error", color=RED, weight=ft.FontWeight.W_700),
            ], spacing=8, tight=True),
            content=ft.Text(msg, color=TEXT, size=12, selectable=True),
            actions=[ft.TextButton("OK", on_click=close)],
            bgcolor=CARD,
        )
        translate_tree(dialog, language[0])
        open_dialog(page, dialog)

    def _set_header(capturing: bool):
        if r_dot.current:
            r_dot.current.bgcolor = GREEN if capturing else RED
            r_dot.current.opacity = 1.0
            r_dot.current.update()
        if r_status.current:
            r_status.current.value = "CAPTURING" if capturing else "STOPPED"
            r_status.current.color = GREEN if capturing else RED
            r_status.current.update()
        if r_start.current:
            r_start.current.content = "STOP" if capturing else "START"
            r_start.current.bgcolor = tint(RED, .25) if capturing else tint(GREEN, .25)
            r_start.current.color   = RED          if capturing else GREEN
            r_start.current.update()
        if r_iface.current:
            r_iface.current.value = state.interface or "All"
            r_iface.current.disabled = capturing
            r_iface.current.update()
        if sett_v._interface_dropdown:
            sett_v._interface_dropdown.value = state.interface or "All"
            sett_v._interface_dropdown.disabled = capturing
            try:
                sett_v._interface_dropdown.update()
            except RuntimeError:
                pass

    _capture_start_time = [None]
    _pending_stats = defaultdict(int)
    _pending_ips = defaultdict(lambda: {"b": 0, "p": 0})
    _persisted_event_keys: set[str] = set()

    def _flush_stats():
        if not state.session_id or not _pending_stats:
            return
        db.save_stat(state.session_id, dict(_pending_stats))
        db.upsert_ips(
            state.session_id,
            [(ip, values["b"], values["p"]) for ip, values in _pending_ips.items()],
        )
        db.save_session_applications(state.session_id, state.app_traffic)
        for app_key, app in state.app_traffic.items():
            for spike in app.get("spike_events", ()):
                stamp = spike.get("ts")
                fingerprint = f"spike:{app_key}:{getattr(stamp, 'isoformat', lambda: str(stamp))()}"
                if fingerprint in _persisted_event_keys:
                    continue
                db.save_session_event(
                    state.session_id, "application_spike",
                    f"Traffic spike · {app.get('name') or 'Unknown'}",
                    f"{float(spike.get('rate', 0)):.1f} KB/s; baseline "
                    f"{float(spike.get('baseline', 0)):.1f} KB/s",
                    "warning", stamp, fingerprint,
                )
                _persisted_event_keys.add(fingerprint)
        _pending_stats.clear()
        _pending_ips.clear()

    def start_capture(e=None):
        if state.capturing:
            return
        try:
            state.reset()
            _pending_stats.clear()
            _pending_ips.clear()
            _persisted_event_keys.clear()
            state.capturing  = True
            state.session_id = db.new_session(state.interface or "All")
            db.save_session_event(
                state.session_id, "capture_started", "Capture started",
                f"Interface: {state.interface or 'All'}", fingerprint="capture_started",
            )
            sniffer.start(state.interface if state.interface != "All" else None)
            _capture_start_time[0] = time.time()
            _set_header(True)
        except Exception as ex:
            state.capturing = False
            _err(f"Could not start capture:\n\n{ex}\n\n"
                 "→ Run as Administrator\n"
                 "→ Npcap must be installed  (npcap.com)")

    def stop_capture(e=None):
        if not state.capturing:
            return
        state.capturing = False
        sniffer.stop()
        state.cur_kbps_in = 0.0
        state.cur_kbps_out = 0.0
        state.cur_pps = 0.0
        _capture_start_time[0] = None
        if state.session_id:
            try:
                _flush_stats()
            except Exception:
                pass
            db.close_session(state.session_id,
                             state.total_pkts, state.bytes_in, state.bytes_out,
                             sniffer.dropped)
            db.save_session_event(
                state.session_id, "capture_stopped", "Capture completed",
                f"{state.total_pkts} packets; {sniffer.dropped} dropped",
                "warning" if sniffer.dropped else "info",
                fingerprint="capture_stopped",
            )
        _set_header(False)

    def cleanup(e=None):
        """Release workers without writing to a page whose session is closing."""
        if _closing[0]:
            return
        _closing[0] = True
        net_v.dispose()
        if state.capturing:
            state.capturing = False
            sniffer.stop()
            if state.session_id:
                try:
                    _flush_stats()
                    db.close_session(
                        state.session_id,
                        state.total_pkts,
                        state.bytes_in,
                        state.bytes_out,
                        sniffer.dropped,
                    )
                except Exception:
                    logger.exception("Could not finalize the capture session")

    page.on_disconnect = cleanup
    page.on_close = cleanup

    def toggle(e=None):
        stop_capture() if state.capturing else start_capture()

    # ── Navigation ─────────────────────────────────────────────────────
    section_names = ["Overview", "Network discovery", "Applications",
                     "Packet explorer", "Performance and capacity", "Session history",
                     "Local ports", "Data management", "System settings"]

    def on_nav(e: ft.ControlEvent):
        idx = e.control.selected_index
        main_content.content = wrappers[idx]
        _active[0] = idx
        if r_section.current:
            r_section.current.value = section_names[idx]
            translate_tree(r_section.current, language[0])
            # A rail change can arrive before Flet has finished mounting the
            # header; the page update below still repaints the new value.
            try:
                r_section.current.update()
            except (RuntimeError, AssertionError):
                pass
        translate_tree(wrappers[idx], language[0])
        try:
            main_content.update()
        except Exception:
            pass
        if idx == 1:   # Network discovery
            net_v.on_mount()
        if idx == 6:   # Local ports
            ports_v.on_mount()
        if idx == 4:   # Performance and capacity
            chart_v.on_mount()
        if idx == 5:   # Traffic history
            hist_v.on_mount()
            try:
                main_content.update()
            except Exception:
                pass
        if idx == 7:   # Saved data management
            data_v.on_mount()

    def nav_icon(icon, selected=False):
        return ft.Icon(icon, size=27 if selected else 25)

    def nav_dest(icon, selected_icon, label):
        return ft.NavigationRailDestination(
            icon=nav_icon(icon),
            selected_icon=nav_icon(selected_icon, True),
            label=label,
            padding=ft.padding.Padding.symmetric(vertical=0),
        )

    nav = ft.NavigationRail(
        selected_index=initial_view,
        label_type=ft.NavigationRailLabelType.ALL,
        min_width=104,
        min_extended_width=180,
        bgcolor=SURFACE,
        indicator_color=tint(CYAN, .19),   # registered below as chrome
        indicator_shape=ft.RoundedRectangleBorder(radius=12),
        destinations=[
            nav_dest(ft.Icons.DASHBOARD_OUTLINED, ft.Icons.DASHBOARD_ROUNDED, "Overview"),
            nav_dest(ft.Icons.LAN_OUTLINED, ft.Icons.LAN_ROUNDED, "Network"),
            nav_dest(ft.Icons.APPS_OUTLINED, ft.Icons.APPS_ROUNDED, "Apps"),
            nav_dest(ft.Icons.TABLE_ROWS_OUTLINED, ft.Icons.TABLE_ROWS_ROUNDED, "Packets"),
            nav_dest(ft.Icons.SPEED_OUTLINED, ft.Icons.SPEED_ROUNDED, "Analytics"),
            nav_dest(ft.Icons.HISTORY_ROUNDED, ft.Icons.HISTORY_ROUNDED, "History"),
            nav_dest(ft.Icons.PRIVACY_TIP_OUTLINED, ft.Icons.PRIVACY_TIP_ROUNDED,
                     "Local ports"),
            nav_dest(ft.Icons.STORAGE_OUTLINED, ft.Icons.STORAGE_ROUNDED, "Data"),
            nav_dest(ft.Icons.SETTINGS_OUTLINED, ft.Icons.SETTINGS_ROUNDED, "Settings"),
        ],
        on_change=on_nav,
    )
    accented(nav, "indicator_color", .19)

    # ── Header ─────────────────────────────────────────────────────────
    r_section = ft.Ref[ft.Text]()
    header_sparklines = ft.Column([
        ft.Text(ref=r_section, value=section_names[initial_view], size=14, color=TEXT,
                weight=ft.FontWeight.W_700),
        ft.Text("REAL-TIME NETWORK OPERATIONS", size=8, color=MUTED,
                weight=ft.FontWeight.W_600),
    ], spacing=0)
    header_live_stats = ft.Row([
        ft.Row([ft.Icon(ft.Icons.SPEED_ROUNDED, color=AMBER, size=14),
                ft.Text(ref=r_pps_h, value="0 pkt/s", size=12, color=AMBER,
                        font_family="monospace")], spacing=4),
        ft.Row([ft.Icon(ft.Icons.SWAP_VERT_ROUNDED, color=CYAN, size=14),
                ft.Text(ref=r_bw_h, value="↓ 0.0  ↑ 0.0 KB/s", size=12, color=CYAN,
                        font_family="monospace")], spacing=4),
    ], spacing=10)

    header_brand = ft.Row([
        accented(
            ft.Container(
                accented(ft.Icon(ft.Icons.RADAR_ROUNDED, color=CYAN, size=24)),
                width=38, height=38, alignment=ft.Alignment.CENTER,
                bgcolor=tint(CYAN, .07), border_radius=11,
                border=ft.Border.all(1, tint(CYAN, .21)),
            ),
            "bgcolor", .07,
        ),
        accented(ft.Text("NETPULSE", size=10, color=CYAN,
                         weight=ft.FontWeight.W_700)),
        ft.VerticalDivider(color=BORDER, width=12, thickness=1),
    ], spacing=7, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    interface_options = [ft.DropdownOption("All", "All interfaces")]
    interface_options.extend(
        ft.DropdownOption(
            item["name"],
            f"{item['name']}  ·  {item['ip']}" + ("" if item["up"] else "  ·  offline"),
        )
        for item in list_interfaces()
    )

    interface_selector = ft.Dropdown(
        ref=r_iface,
        value=state.interface or "All",
        options=interface_options,
        on_select=lambda e: on_interface_change(e.control.value),
        width=230,
        dense=True,
        text_size=11,
        bgcolor=CARD,
        color=TEXT,
        border_color=BORDER,
        focused_border_color=CYAN,
        tooltip="Capture interface",
    )
    accented(interface_selector, "focused_border_color")

    header = ft.Container(
        content=ft.Row([
            ft.Container(width=10),
            header_brand,
            ft.Container(ref=r_dot, width=10, height=10, bgcolor=RED, border_radius=5,
                         animate=ft.Animation(600, ft.AnimationCurve.EASE_IN_OUT)),
            ft.Text(ref=r_status,  value="STOPPED", size=12, color=RED,
                    weight=ft.FontWeight.W_700),
            interface_selector,
            ft.Button(
                ref=r_start, content="START", on_click=toggle,
                bgcolor=tint(GREEN, .25), color=GREEN,
                style=ft.ButtonStyle(
                    shape=ft.RoundedRectangleBorder(radius=8),
                    padding=ft.padding.Padding.symmetric(horizontal=18, vertical=8),
                    overlay_color=tint(GREEN, .13),
                ),
            ),
            ft.VerticalDivider(color=BORDER, width=12, thickness=1),
            header_sparklines,
            ft.Container(expand=True),
            header_live_stats,
            ft.Container(width=12),
        ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        height=62, bgcolor=SURFACE,
        border=ft.Border.only(bottom=ft.BorderSide(color=BORDER, width=1)),
    )

    # ── Status bar ─────────────────────────────────────────────────────
    status_refresh = ft.Row([
        accented(ft.ProgressRing(width=10, height=10, stroke_width=1.5, color=CYAN)),
        ft.Text("200ms refresh", size=10, color=MUTED),
    ], spacing=8)
    status_database = ft.Row([
        ft.Icon(ft.Icons.STORAGE_ROUNDED, color=MUTED, size=12),
        ft.Text("netpulse.db", size=11, color=MUTED),
        ft.VerticalDivider(color=BORDER, width=16, thickness=1),
    ], spacing=4)
    status_bar = ft.Container(
        content=ft.Row([
            ft.Container(width=8),
            status_database,
            ft.Text(ref=r_sb_sess, value="No session", size=11, color=MUTED),
            ft.VerticalDivider(color=BORDER, width=16, thickness=1),
            ft.Text(ref=r_sb_pkts, value="0 packets", size=11, color=MUTED),
            ft.VerticalDivider(color=BORDER, width=16, thickness=1),
            ft.Icon(ft.Icons.TIMER_OUTLINED, color=MUTED, size=12),
            ft.Text(ref=r_sb_time, value="00:00:00", size=11, color=MUTED,
                    font_family="monospace"),
            ft.VerticalDivider(color=BORDER, width=16, thickness=1),
            ft.Text(ref=r_sb_drop, value="0 dropped", size=11, color=MUTED,
                    tooltip="Packets discarded because the capture queue was full"),
            ft.Container(expand=True),
            status_refresh,
            ft.Container(width=8),
        ], spacing=4, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        height=28, bgcolor=SURFACE,
        border=ft.Border.only(top=ft.BorderSide(color=BORDER, width=1)),
    )

    # ── Layout ─────────────────────────────────────────────────────────
    def logical_viewport(width: float, height: float = 0.0) -> tuple[float, float]:
        """Return the logical dimensions already reported by Flet Desktop."""
        return float(width), float(height) if height else 0.0

    def on_content_resize(e):
        width, height = logical_viewport(e.width, e.height)
        # This callback belongs to ``main_content``: Flet already reports the
        # center pane's width after the navigation rail and divider are laid
        # out. Subtracting the rail again leaves an unused strip on the right.
        width = max(280.0, width)
        dash.set_viewport(width, height)
        net_v.set_viewport(width, height)
        ports_v.set_viewport(width, height)
        pkt_v.set_viewport(width, height)
        chart_v.set_viewport(width, height)
        hist_v.set_viewport(width, height)
        proc_v.set_viewport(width, height)
        sett_v.set_viewport(width, height)
        data_v.set_viewport(width, height)
        page.update()

    main_content = ft.Container(
        content=wrappers[initial_view],
        expand=True,
        bgcolor=BG,
        on_size_change=on_content_resize,
        size_change_interval=80,
    )
    workspace = ft.Row([
        nav,
        ft.VerticalDivider(color=BORDER, width=1, thickness=1),
        main_content,
    ], expand=True, spacing=0)
    app_layout = ft.Column([
        header,
        workspace,
        status_bar,
    ], spacing=0, expand=True)
    default_palette = appearance_palette("netpulse", "cyan")
    if current_palette[0] != default_palette:
        _repaint(default_palette, current_palette[0])
    else:
        apply_accent(current_palette[0]["accent"])
    page.add(app_layout)
    translate_tree(app_layout, language[0])
    page.update()
    if initial_view == 1:
        net_v.on_mount()
    elif initial_view == 6:
        ports_v.on_mount()
    elif initial_view == 4:
        chart_v.on_mount()
    elif initial_view == 5:
        hist_v.on_mount()
    elif initial_view == 7:
        data_v.on_mount()

    def apply_responsive_layout(width: float, height: float):
        compact = width < 980
        narrow = width < 820
        header_live_stats.visible = not compact
        header_sparklines.visible = not narrow
        status_database.visible = not narrow
        status_refresh.visible = not compact
        header_brand.controls[1].visible = not narrow
        if r_iface.current:
            r_iface.current.visible = not narrow
        # Labels on every destination require too much vertical room in short
        # restored windows. Keep the active label for orientation and show all
        # labels again as soon as the desktop has sufficient height.
        nav.label_type = (
            ft.NavigationRailLabelType.SELECTED
            if height < 650 else ft.NavigationRailLabelType.ALL
        )
        page.update()

    def on_page_resize(e):
        width, height = logical_viewport(e.width, e.height)
        apply_responsive_layout(width, height)

    page.on_resize = on_page_resize
    initial_width, initial_height = logical_viewport(
        page.width or page.window.width or 1100,
        page.height or page.window.height or 660,
    )
    apply_responsive_layout(initial_width, initial_height)

    # ── Update loop — 200 ms real-time ─────────────────────────────────
    _tick   = 0
    _last_t = time.time()
    _pulse  = False
    _pending_alerts: list = []

    async def update_loop():
        nonlocal _tick, _last_t, _pulse, _pending_alerts
        await asyncio.sleep(0.5)   # wait for initial render

        while not _closing[0]:
            try:
                await asyncio.sleep(UPDATE_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                return
            try:
                now = time.time()
                dt  = now - _last_t
                _last_t = now
                _tick  += 1

                # 1. Drain + aggregate
                stat_dict: dict = {}
                if state.capturing and sniffer.running:
                    pkts = sniffer.drain()
                    stat_dict = state.process(pkts, dt)
                    for key, value in stat_dict.items():
                        _pending_stats[key] += value
                    for ip, values in state.last_ip_deltas.items():
                        _pending_ips[ip]["b"] += values["b"]
                        _pending_ips[ip]["p"] += values["p"]

                    # Check alerts
                    alerts = state.check_alerts()
                    _pending_alerts.extend(alerts)
                    if state.session_id:
                        for title, message in alerts:
                            db.save_session_event(
                                state.session_id, "threshold_alert", title, message,
                                "warning",
                            )

                    # Save to DB every ~1s (5 ticks × 0.2s)
                    if _tick % DATABASE_FLUSH_TICKS == 0 and state.session_id and _pending_stats:
                        try:
                            _flush_stats()
                        except Exception:
                            pass

                # 2. Pulse dot
                if state.capturing and _tick % DATABASE_FLUSH_TICKS == 0:
                    _pulse = not _pulse
                    if r_dot.current:
                        r_dot.current.opacity = 1.0 if _pulse else 0.55

                # 3. Header stats
                if r_pps_h.current:
                    r_pps_h.current.value = f"{state.cur_pps:.0f} pkt/s"
                if r_bw_h.current:
                    r_bw_h.current.value = (f"↓ {state.cur_kbps_in:.1f}  "
                                            f"↑ {state.cur_kbps_out:.1f} KB/s")

                # 4. Status bar
                if r_sb_pkts.current:
                    r_sb_pkts.current.value = tr(f"{state.total_pkts:,} packets")
                if r_sb_sess.current:
                    r_sb_sess.current.value = tr(
                        f"Session #{state.session_id}" if state.session_id
                        else "No session")
                # Session elapsed time
                if r_sb_time.current:
                    if state.capturing and _capture_start_time[0]:
                        elapsed = int(time.time() - _capture_start_time[0])
                        h, rem = divmod(elapsed, 3600)
                        m, s   = divmod(rem, 60)
                        r_sb_time.current.value = f"{h:02d}:{m:02d}:{s:02d}"
                    else:
                        r_sb_time.current.value = "00:00:00"

                # Dropped packets warn that the displayed rates are incomplete.
                if r_sb_drop.current:
                    dropped = sniffer.dropped
                    r_sb_drop.current.value = tr(f"{dropped:,} dropped")
                    r_sb_drop.current.color = AMBER if dropped else MUTED

                # 5. Poll CPU/RAM every ~1s (5 ticks)
                if _tick % DATABASE_FLUSH_TICKS == 0:
                    try:
                        import psutil as _ps
                        state.sys_cpu = _ps.cpu_percent(interval=None)
                        state.sys_ram = _ps.virtual_memory().percent
                        state.spark_cpu.append(state.sys_cpu)
                        state.spark_ram.append(state.sys_ram)
                    except Exception:
                        pass

                # Dispatch persistent scan schedules every five seconds. The
                # scan itself runs in its own task and never blocks telemetry.
                if _tick % 25 == 0:
                    net_v.poll_schedules()

                # 6. Refresh active view
                idx = nav.selected_index
                if idx == 0:
                    dash.refresh()
                elif idx == 3:
                    pkt_v.refresh()
                elif idx == 4:
                    chart_v.refresh()
                elif idx == 2:
                    proc_v.refresh()
                # Network/history/settings are event and DB based.

                try:
                    page.update()
                except RuntimeError as exc:
                    if "destroyed session" not in str(exc).lower():
                        logger.exception("Desktop client rejected page update")
                    cleanup()
                    break

                # 7. Show pending alerts (after page.update to avoid conflicts)
                if _pending_alerts:
                    alert = _pending_alerts.pop(0)
                    _show_alert_dialog(alert[0], alert[1])

            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("Unhandled error in the real-time update loop")

    page.run_task(update_loop)

