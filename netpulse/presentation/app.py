"""Application composition root and Flet event loop."""

import asyncio
import time
from collections import defaultdict
import logging
import os

import flet as ft

from netpulse.config import (
    DEFAULT_DATABASE_PATH, ensure_runtime_directories, load_language, save_language,
)
from netpulse.domain.state import AppState
from netpulse.infrastructure.database import DB
from netpulse.infrastructure.nmap_scanner import NmapScanner
from netpulse.infrastructure.sniffer import Sniffer
from netpulse.services.ip_info import geo_cache
from .theme import (
    AMBER, BG, BORDER, CARD, CYAN, GREEN, MUTED, RED, SURFACE, TEXT,
    make_theme, tint,
)
from .views import (
    ChartsView, DashboardView, HistoryView, NetworkView, PacketsView, ProcessView,
    SettingsView,
)
from .i18n import set_language, translate_tree


UPDATE_INTERVAL_SECONDS = 0.2
DATABASE_FLUSH_TICKS = 5
logger = logging.getLogger(__name__)


def main(page: ft.Page):
    # ── Page config ────────────────────────────────────────────────────
    page.title      = "NetPulse — Network Analyzer"
    page.bgcolor    = BG
    page.theme      = make_theme()
    page.theme_mode = ft.ThemeMode.DARK
    page.padding    = 0
    # Flet uses logical pixels and Windows applies DPI scaling afterwards.
    # 1080x660 remains fully visible on a 1707x1067 desktop at 150% scaling,
    # while the dashboard still has room for its four primary metrics.
    page.window.width      = 1080
    page.window.height     = 660
    page.window.min_width  = 900
    page.window.min_height = 620
    page.window.bgcolor    = BG
    # NetPulse is an operations workspace: start maximized so analytical views
    # use the available desktop instead of booting directly into compact mode.
    # The dimensions above remain the safe restored-window size.
    page.window.maximized  = True

    # ── Core objects ───────────────────────────────────────────────────
    ensure_runtime_directories()
    state   = AppState(ip_enricher=geo_cache)
    sniffer = Sniffer()
    nmap_scanner = NmapScanner()
    db      = DB(DEFAULT_DATABASE_PATH)
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

    # ── Views ──────────────────────────────────────────────────────────
    dash    = DashboardView(state)
    net_v   = NetworkView(db, nmap_scanner, _page_ref)
    pkt_v   = PacketsView(state, _page_ref)
    chart_v = ChartsView(state)
    hist_v  = HistoryView(db)
    proc_v  = ProcessView(state)
    sett_v  = SettingsView(state, language[0], on_language_change)

    try:
        initial_view = max(0, min(6, int(os.getenv("NETPULSE_INITIAL_VIEW", "0"))))
    except ValueError:
        initial_view = 0
    _active = [initial_view]

    def _wrap(v):
        return ft.Container(
            content=v, expand=True, visible=True,
            padding=ft.padding.Padding.only(left=14, top=14, right=14, bottom=14),
        )

    w_dash  = _wrap(dash.build())
    w_net   = _wrap(net_v.build())
    w_pkt   = _wrap(pkt_v.build())
    w_chart = _wrap(chart_v.build())
    w_hist  = _wrap(hist_v.build())
    w_proc  = _wrap(proc_v.build())
    w_sett  = _wrap(sett_v.build())
    wrappers = [w_dash, w_net, w_pkt, w_chart, w_hist, w_proc, w_sett]

    # ── Header refs ────────────────────────────────────────────────────
    r_dot    = ft.Ref[ft.Container]()
    r_status = ft.Ref[ft.Text]()
    r_pps_h  = ft.Ref[ft.Text]()
    r_bw_h   = ft.Ref[ft.Text]()
    r_iface  = ft.Ref[ft.Text]()
    r_start  = ft.Ref[ft.Button]()
    r_sb_sess = ft.Ref[ft.Text]()
    r_sb_pkts = ft.Ref[ft.Text]()
    r_sb_time  = ft.Ref[ft.Text]()

    # ── Capture control ────────────────────────────────────────────────
    def _show_alert_dialog(title: str, msg: str):
        def close(e):
            page.dialog.open = False
            page.update()
        page.dialog = ft.AlertDialog(
            modal=False,
            title=ft.Text(title, color=AMBER),
            content=ft.Text(msg, color=TEXT, size=12),
            actions=[ft.TextButton("OK", on_click=close)],
            bgcolor=CARD,
        )
        page.dialog.open = True
        page.update()

    def _err(msg: str):
        def close(e):
            page.dialog.open = False
            page.update()
        page.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("⚠  Error", color=RED),
            content=ft.Text(msg, color=TEXT, size=12, selectable=True),
            actions=[ft.TextButton("OK", on_click=close)],
            bgcolor=CARD,
        )
        page.dialog.open = True
        page.update()

    def _set_header(capturing: bool):
        if r_dot.current:
            r_dot.current.bgcolor = GREEN if capturing else RED
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
            r_iface.current.value = f"[ {state.interface or 'All'} ]"
            r_iface.current.update()

    _capture_start_time = [None]
    _pending_stats = defaultdict(int)
    _pending_ips = defaultdict(lambda: {"b": 0, "p": 0})

    def _flush_stats():
        if not state.session_id or not _pending_stats:
            return
        db.save_stat(state.session_id, dict(_pending_stats))
        db.upsert_ips(
            state.session_id,
            [(ip, values["b"], values["p"]) for ip, values in _pending_ips.items()],
        )
        _pending_stats.clear()
        _pending_ips.clear()

    def start_capture(e=None):
        if state.capturing:
            return
        try:
            state.reset()
            _pending_stats.clear()
            _pending_ips.clear()
            state.capturing  = True
            state.session_id = db.new_session(state.interface or "All")
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
                             state.total_pkts, state.bytes_in, state.bytes_out)
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
                    )
                except Exception:
                    logger.exception("Could not finalize the capture session")

    page.on_disconnect = cleanup
    page.on_close = cleanup

    def toggle(e=None):
        stop_capture() if state.capturing else start_capture()

    # ── Navigation ─────────────────────────────────────────────────────
    section_names = ["Overview", "Network discovery", "Packet explorer",
                     "Traffic analytics", "Session history", "Applications",
                     "System settings"]

    def on_nav(e: ft.ControlEvent):
        idx = e.control.selected_index
        main_content.content = wrappers[idx]
        _active[0] = idx
        if r_section.current:
            r_section.current.value = section_names[idx]
            translate_tree(r_section.current, language[0])
            r_section.current.update()
        translate_tree(wrappers[idx], language[0])
        try:
            main_content.update()
        except Exception:
            pass
        if idx == 1:   # Network discovery
            net_v.on_mount()
        if idx == 4:   # Traffic history
            hist_v.on_mount()
            try:
                main_content.update()
            except Exception:
                pass

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
        indicator_color=tint(CYAN, .19),
        indicator_shape=ft.RoundedRectangleBorder(radius=12),
        destinations=[
            nav_dest(ft.Icons.DASHBOARD_OUTLINED, ft.Icons.DASHBOARD_ROUNDED, "Overview"),
            nav_dest(ft.Icons.LAN_OUTLINED, ft.Icons.LAN_ROUNDED, "Network"),
            nav_dest(ft.Icons.TABLE_ROWS_OUTLINED, ft.Icons.TABLE_ROWS_ROUNDED, "Packets"),
            nav_dest(ft.Icons.SHOW_CHART_OUTLINED, ft.Icons.SHOW_CHART_ROUNDED, "Analytics"),
            nav_dest(ft.Icons.HISTORY_ROUNDED, ft.Icons.HISTORY_ROUNDED, "History"),
            nav_dest(ft.Icons.APPS_ROUNDED, ft.Icons.APPS_ROUNDED, "Apps"),
            nav_dest(ft.Icons.SETTINGS_OUTLINED, ft.Icons.SETTINGS_ROUNDED, "Settings"),
        ],
        on_change=on_nav,
    )

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
        ft.Container(
            ft.Icon(ft.Icons.RADAR_ROUNDED, color=CYAN, size=24),
            width=38, height=38, alignment=ft.Alignment.CENTER,
            bgcolor=tint(CYAN, .07), border_radius=11,
            border=ft.Border.all(1, tint(CYAN, .21)),
        ),
        ft.Text("NETPULSE", size=10, color=CYAN, weight=ft.FontWeight.W_700),
        ft.VerticalDivider(color=BORDER, width=12, thickness=1),
    ], spacing=7, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    header = ft.Container(
        content=ft.Row([
            ft.Container(width=10),
            header_brand,
            ft.Container(ref=r_dot, width=10, height=10, bgcolor=RED, border_radius=5,
                         animate=ft.Animation(600, ft.AnimationCurve.EASE_IN_OUT)),
            ft.Text(ref=r_status,  value="STOPPED", size=12, color=RED,
                    weight=ft.FontWeight.W_700),
            ft.Text(ref=r_iface,   value="[ None ]", size=11, color=MUTED),
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
        ft.ProgressRing(width=10, height=10, stroke_width=1.5, color=CYAN),
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
        pkt_v.set_viewport(width, height)
        chart_v.set_viewport(width, height)
        hist_v.set_viewport(width, height)
        proc_v.set_viewport(width, height)
        sett_v.set_viewport(width, height)
        page.update()

    main_content = ft.Container(
        content=wrappers[initial_view],
        expand=True,
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
    page.add(app_layout)
    translate_tree(app_layout, language[0])
    page.update()
    if initial_view == 1:
        net_v.on_mount()
    elif initial_view == 4:
        hist_v.on_mount()

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

                    # Save to DB every ~1s (5 ticks × 0.2s)
                    if _tick % DATABASE_FLUSH_TICKS == 0 and state.session_id and _pending_stats:
                        try:
                            _flush_stats()
                        except Exception:
                            pass

                # 2. Pulse dot
                if state.capturing:
                    _pulse = not _pulse
                    if r_dot.current:
                        r_dot.current.opacity = 1.0 if _pulse else 0.4
                        r_dot.current.width   = 11  if _pulse else 7
                        r_dot.current.height  = 11  if _pulse else 7

                # 3. Header stats
                if r_pps_h.current:
                    r_pps_h.current.value = f"{state.cur_pps:.0f} pkt/s"
                if r_bw_h.current:
                    r_bw_h.current.value = (f"↓ {state.cur_kbps_in:.1f}  "
                                            f"↑ {state.cur_kbps_out:.1f} KB/s")

                # 4. Status bar
                if r_sb_pkts.current:
                    r_sb_pkts.current.value = f"{state.total_pkts:,} packets"
                if r_sb_sess.current:
                    r_sb_sess.current.value = (f"Session #{state.session_id}"
                                               if state.session_id else "No session")
                # Session elapsed time
                if r_sb_time.current:
                    if state.capturing and _capture_start_time[0]:
                        elapsed = int(time.time() - _capture_start_time[0])
                        h, rem = divmod(elapsed, 3600)
                        m, s   = divmod(rem, 60)
                        r_sb_time.current.value = f"{h:02d}:{m:02d}:{s:02d}"
                    else:
                        r_sb_time.current.value = "00:00:00"

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

                # 6. Refresh active view
                idx = nav.selected_index
                if idx == 0:
                    dash.refresh()
                elif idx == 2:
                    pkt_v.refresh()
                elif idx == 3:
                    chart_v.refresh()
                elif idx == 5:
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

