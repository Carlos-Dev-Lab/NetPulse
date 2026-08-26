"""Manual management of data persisted by NetPulse."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sqlite3

import flet as ft

from netpulse.domain.state import AppState
from netpulse.infrastructure.database import DB
from netpulse.config import DEFAULT_LOG_PATH, DEFAULT_SETTINGS_PATH, PROJECT_ROOT
from .dialogs import close_dialog, open_dialog
from .i18n import get_language, tr, translate_tree
from .theme import (
    AMBER, BLUE, BORDER, CARD, CYAN, DIM, GREEN, MUTED, PURPLE, RED,
    SURFACE, TEXT, card, snap, split, tint, view_heading,
)


CATEGORIES = {
    "sessions": ("Capture sessions", ft.Icons.MONITOR_HEART_ROUNDED, CYAN),
    "scans": ("Network scans", ft.Icons.RADAR_ROUNDED, PURPLE),
    "assets": ("Inventory assets", ft.Icons.DEVICES_OTHER_ROUNDED, BLUE),
    "quality": ("Quality checks", ft.Icons.SPEED_ROUNDED, AMBER),
    "profiles": ("Scan profiles", ft.Icons.TUNE_ROUNDED, GREEN),
    "schedules": ("Scan schedules", ft.Icons.SCHEDULE_ROUNDED, PURPLE),
    "events": ("Session events", ft.Icons.EVENT_NOTE_ROUNDED, CYAN),
}

SINGULAR_CATEGORIES = {
    "sessions": "Capture session",
    "scans": "Network scan",
    "assets": "Inventory asset",
    "quality": "Quality check",
    "profiles": "Scan profile",
    "schedules": "Scan schedule",
    "events": "Session event",
}


class DataManagementView:
    """Browse and selectively remove records saved in SQLite."""

    def __init__(self, db: DB, page_ref, state: AppState | None = None):
        self.db = db
        self._page = page_ref
        self.state = state
        self.category = "sessions"
        self.selected: set[int] = set()
        self._visible_ids: list[int] = []
        self._records: list[dict] = []
        self._summary_cards: list[ft.Container] = []
        self._layout_key = None
        self._root = None
        self._summary_row = None
        self._toolbar_card = None
        self._toolbar_row = None
        self._records_card = None
        self._records_column = None
        self._category_dropdown = None
        self._search = None
        self._select_all = None
        self._delete_button = None
        self._selection_text = None
        self._empty = None
        self._backup_dropdown = None
        self._restore_button = None
        self._operation_status = None
        self._summary_values: dict[str, ft.Text] = {}

    @staticmethod
    def _format_date(value) -> str:
        if not value:
            return "—"
        try:
            return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d  %H:%M")
        except (TypeError, ValueError):
            return str(value)

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

    def build(self):
        def on_category(event):
            self.category = event.control.value or "sessions"
            self.selected.clear()
            self.refresh()

        def on_search(event=None):
            self._render_records()

        def on_select_all(event):
            if event.control.value:
                self.selected.update(self._visible_ids)
            else:
                self.selected.difference_update(self._visible_ids)
            self._render_records()

        self._summary_row = ft.Row(spacing=10, wrap=True, run_spacing=10)
        summary_specs = (
            ("sessions", "SESSIONS", ft.Icons.MONITOR_HEART_ROUNDED, CYAN),
            ("scans", "SCANS", ft.Icons.RADAR_ROUNDED, PURPLE),
            ("assets", "ASSETS", ft.Icons.DEVICES_OTHER_ROUNDED, BLUE),
            ("quality", "CHECKS", ft.Icons.SPEED_ROUNDED, AMBER),
            ("bytes", "DATABASE SIZE", ft.Icons.STORAGE_ROUNDED, GREEN),
        )
        for key, label, icon, color in summary_specs:
            value = ft.Text("0", color=color, size=20, weight=ft.FontWeight.W_700)
            self._summary_values[key] = value
            summary = card(ft.Row([
                ft.Container(
                    content=ft.Icon(icon, color=color, size=20),
                    width=38, height=38, alignment=ft.Alignment.CENTER,
                    bgcolor=tint(color, .10), border_radius=9,
                ),
                ft.Column([
                    ft.Text(label, color=DIM, size=9, weight=ft.FontWeight.W_700),
                    value,
                ], spacing=0, expand=True),
            ], spacing=9), padding=10)
            self._summary_cards.append(summary)
        self._summary_row.controls = self._summary_cards

        self._backup_dropdown = ft.Dropdown(
            label="Available backups", width=360, options=[], bgcolor=SURFACE,
            color=TEXT, border_color=BORDER, focused_border_color=CYAN,
            enable_search=True,
        )
        self._restore_button = ft.Button(
            content="RESTORE SELECTED", icon=ft.Icons.RESTORE_ROUNDED,
            color=AMBER, bgcolor=tint(AMBER, .11), disabled=True,
            on_click=lambda e: self._confirm_restore(),
        )
        self._backup_dropdown.on_select = lambda e: self._set_restore_enabled()
        self._operation_status = ft.Text(
            "Create a verified backup before major changes.", color=MUTED, size=9,
            expand=True, selectable=True,
        )
        operations = card(ft.Column([
            ft.Row([
                ft.Text("BACKUP, RESTORE AND EXPORT", color=TEXT, size=10,
                        weight=ft.FontWeight.W_700),
                ft.Container(expand=True), self._operation_status,
            ], spacing=8),
            ft.Row([
                ft.Button(content="CREATE BACKUP", icon=ft.Icons.BACKUP_ROUNDED,
                          color=CYAN, bgcolor=tint(CYAN, .10),
                          on_click=lambda e: self._handle_backup()),
                ft.Button(content="EXPORT ALL DATA", icon=ft.Icons.ARCHIVE_OUTLINED,
                          color=GREEN, bgcolor=tint(GREEN, .10),
                          on_click=lambda e: self._handle_export()),
                self._backup_dropdown, self._restore_button,
            ], spacing=9, wrap=True, run_spacing=8),
        ], spacing=8), padding=10)

        self._category_dropdown = ft.Dropdown(
            label="Data type", value=self.category,
            options=[ft.DropdownOption(key, label) for key, (label, _, _) in CATEGORIES.items()],
            width=220, bgcolor=SURFACE, color=TEXT, border_color=BORDER,
            focused_border_color=CYAN, on_select=on_category,
        )
        self._search = ft.TextField(
            hint_text="Search saved records", prefix_icon=ft.Icons.SEARCH_ROUNDED,
            expand=True, bgcolor=SURFACE, color=TEXT, border_color=BORDER,
            focused_border_color=CYAN, on_change=on_search,
        )
        self._delete_button = ft.Button(
            content="DELETE SELECTED", icon=ft.Icons.DELETE_OUTLINE_ROUNDED,
            color=RED, bgcolor=tint(RED, .12), disabled=True,
            on_click=lambda e: self._confirm_delete(),
        )
        self._toolbar_row = ft.Row([
            self._category_dropdown,
            self._search,
            ft.Button(content="REFRESH", icon=ft.Icons.REFRESH_ROUNDED,
                      color=CYAN, bgcolor=tint(CYAN, .10),
                      on_click=lambda e: self.refresh()),
            self._delete_button,
        ], spacing=9, wrap=False, run_spacing=8)
        self._toolbar_card = card(self._toolbar_row, padding=10)

        self._select_all = ft.Checkbox(
            label="Select all visible", value=False, fill_color=CYAN,
            on_change=on_select_all,
        )
        self._selection_text = ft.Text("0 selected", color=MUTED, size=10)
        self._records_column = ft.Column(spacing=7, scroll=ft.ScrollMode.ALWAYS,
                                         expand=True)
        self._empty = ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.INBOX_OUTLINED, color=MUTED, size=30),
                ft.Text("No saved records in this category.", color=MUTED, size=11),
            ], spacing=7, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            alignment=ft.Alignment.CENTER, expand=True,
        )
        self._records_card = card(ft.Column([
            ft.Row([
                ft.Text("SAVED RECORDS", color=TEXT, size=11,
                        weight=ft.FontWeight.W_700),
                ft.Container(expand=True),
                self._select_all,
                self._selection_text,
            ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ft.Divider(color=BORDER, height=6),
            self._records_column,
        ], spacing=7, expand=True), padding=12, expand=True)

        notice = ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.SHIELD_OUTLINED, color=AMBER, size=18),
                ft.Text(
                    "Deletion is permanent. Related samples and evidence are removed safely; "
                    "an active capture session cannot be selected.",
                    color=DIM, size=10, expand=True,
                ),
            ], spacing=8),
            bgcolor=tint(AMBER, .055), border=ft.Border.all(1, tint(AMBER, .20)),
            border_radius=9, padding=10,
        )
        self._root = ft.Column([
            view_heading("Data management", "Review and control records stored by NetPulse",
                         ft.Icons.STORAGE_ROUNDED, CYAN),
            self._summary_row,
            operations,
            notice,
            self._toolbar_card,
            self._records_card,
        ], spacing=10, expand=True)
        self.refresh()
        return self._root

    def _load_records(self) -> list[dict]:
        if self.category == "sessions":
            return self.db.list_sessions()
        if self.category == "scans":
            return self.db.list_network_scans(250)
        if self.category == "assets":
            return self.db.list_inventory()
        if self.category == "quality":
            return self.db.list_quality_checks(250)
        if self.category == "profiles":
            return self.db.list_scan_profiles()
        if self.category == "schedules":
            return self.db.list_scan_schedules()
        return self.db.list_session_events(limit=250)

    def _record_id(self, item: dict) -> int:
        return int(item.get("device_id") if self.category == "assets" else item["id"])

    def _record_content(self, item: dict):
        category = self.category
        if category == "sessions":
            title = f"{tr('Session')} #{item['id']}"
            subtitle = self._format_date(item.get("start_time"))
            facts = [
                (ft.Icons.CABLE_ROUNDED, item.get("interface") or "All"),
                (ft.Icons.DATA_USAGE_ROUNDED, f"{int(item.get('total_pkts') or 0):,} {tr('packets')}"),
                (ft.Icons.SWAP_VERT_ROUNDED, self._format_bytes(
                    int(item.get("total_bytes_in") or 0) + int(item.get("total_bytes_out") or 0))),
            ]
            color = CYAN
        elif category == "scans":
            title = item.get("target") or f"Scan #{item['id']}"
            subtitle = f"#{item['id']} · {self._format_date(item.get('started_at'))}"
            facts = [
                (ft.Icons.TUNE_ROUNDED, item.get("profile") or "—"),
                (ft.Icons.DEVICES_ROUNDED, f"{item.get('host_count', 0)} {tr('devices')}"),
                (ft.Icons.LOCK_OPEN_ROUNDED, f"{item.get('open_port_count', 0)} {tr('open ports')}"),
            ]
            color = RED if item.get("risk_level") == "high" else (
                AMBER if item.get("risk_level") == "medium" else PURPLE)
        elif category == "assets":
            title = item.get("alias") or item.get("detected_name") or item.get("address")
            subtitle = f"#{item.get('device_id')} · {item.get('address') or '—'}"
            facts = [
                (ft.Icons.MEMORY_ROUNDED, item.get("mac") or "No MAC"),
                (ft.Icons.LABEL_OUTLINE_ROUNDED, item.get("device_type") or "unknown"),
                (ft.Icons.VERIFIED_USER_OUTLINED, item.get("trust_status") or "new"),
            ]
            color = BLUE
        elif category == "quality":
            title = item.get("gateway") or tr("Quality check")
            subtitle = f"#{item['id']} · {self._format_date(item.get('ts'))}"
            latency = item.get("latency_ms")
            loss = item.get("loss_percent")
            facts = [
                (ft.Icons.CABLE_ROUNDED, item.get("interface") or "All"),
                (ft.Icons.TIMER_OUTLINED,
                 f"{latency:.1f} ms" if latency is not None else tr("Unavailable")),
                (ft.Icons.SIGNAL_CELLULAR_ALT_ROUNDED,
                 f"{loss:.0f}% {tr('loss')}" if loss is not None else tr("Unavailable")),
            ]
            color = AMBER
        elif category == "profiles":
            title = item.get("name") or f"Profile #{item['id']}"
            subtitle = f"#{item['id']} · {item.get('target') or '—'}"
            facts = [
                (ft.Icons.RADAR_ROUNDED, item.get("profile") or "—"),
                (ft.Icons.UPDATE_ROUNDED, self._format_date(item.get("updated_at"))),
            ]
            color = GREEN
        elif category == "schedules":
            title = item.get("name") or f"Schedule #{item['id']}"
            subtitle = f"#{item['id']} · {item.get('target') or '—'}"
            facts = [
                (ft.Icons.TIMER_OUTLINED, f"{item.get('interval_minutes', 0)} min"),
                (ft.Icons.EVENT_AVAILABLE_ROUNDED, self._format_date(item.get("next_run"))),
                (ft.Icons.POWER_SETTINGS_NEW_ROUNDED,
                 tr("Enabled") if item.get("enabled") else tr("Disabled")),
            ]
            color = PURPLE
        else:
            title = item.get("title") or f"Event #{item['id']}"
            subtitle = f"#{item['id']} · {self._format_date(item.get('ts'))}"
            facts = [
                (ft.Icons.MONITOR_HEART_ROUNDED, f"Session #{item.get('session_id') or '—'}"),
                (ft.Icons.CATEGORY_OUTLINED, item.get("event_type") or "event"),
                (ft.Icons.PRIORITY_HIGH_ROUNDED, item.get("severity") or "info"),
            ]
            color = RED if item.get("severity") == "error" else (
                AMBER if item.get("severity") == "warning" else CYAN)
        return title, subtitle, facts, color

    def _render_records(self):
        if not self._records_column:
            return
        query = (self._search.value or "").strip().lower() if self._search else ""
        visible = [item for item in self._records
                   if not query or query in " ".join(str(value) for value in item.values()).lower()]
        self._visible_ids = [self._record_id(item) for item in visible]
        controls = []
        for item in visible:
            record_id = self._record_id(item)
            title, subtitle, facts, color = self._record_content(item)
            protected = (
                self.category == "sessions" and self.state is not None
                and self.state.capturing and self.state.session_id == record_id
            )

            def on_checked(event, rid=record_id):
                if event.control.value:
                    self.selected.add(rid)
                else:
                    self.selected.discard(rid)
                self._update_selection_state()

            facts_row = ft.Row([
                ft.Row([ft.Icon(icon, color=MUTED, size=13),
                        ft.Text(str(value), color=DIM, size=9)], spacing=4)
                for icon, value in facts
            ], spacing=14, wrap=True, run_spacing=4)
            controls.append(ft.Container(
                content=ft.Row([
                    ft.Checkbox(
                        value=record_id in self.selected, disabled=protected,
                        fill_color=color, on_change=on_checked,
                        tooltip="Active capture session" if protected else "Select record",
                    ),
                    ft.Container(width=4, height=48, bgcolor=color, border_radius=3),
                    ft.Column([
                        ft.Row([
                            ft.Text(str(title), color=TEXT, size=11,
                                    weight=ft.FontWeight.W_600, expand=True,
                                    overflow=ft.TextOverflow.ELLIPSIS),
                            ft.Text(tr("ACTIVE") if protected else "", color=GREEN,
                                    size=8, weight=ft.FontWeight.W_700),
                        ], spacing=6),
                        ft.Text(str(subtitle), color=MUTED, size=9),
                        facts_row,
                    ], spacing=3, expand=True),
                    ft.IconButton(
                        ft.Icons.DELETE_OUTLINE_ROUNDED, icon_color=RED,
                        icon_size=18, disabled=protected, tooltip="Delete record",
                        on_click=lambda e, rid=record_id: self._confirm_delete({rid}),
                    ),
                ], spacing=9, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=tint(color, .035), border=ft.Border.all(1, BORDER),
                border_radius=9, padding=8,
            ))
        self._records_column.controls = controls or [self._empty]
        self._update_selection_state(update=False)
        self._safe_update(self._records_column)

    def _update_selection_state(self, update=True):
        if self._delete_button:
            self._delete_button.disabled = not self.selected
        if self._selection_text:
            self._selection_text.value = tr(f"{len(self.selected)} selected")
        if self._select_all:
            selectable = set(self._visible_ids)
            self._select_all.value = bool(selectable and selectable <= self.selected)
        if update:
            for control in (self._delete_button, self._selection_text, self._select_all):
                self._safe_update(control)

    @property
    def _backup_directory(self) -> Path:
        return self.db.path.parent / "backups"

    def _refresh_backups(self, selected: Path | None = None):
        if self._backup_dropdown is None:
            return
        self._backup_directory.mkdir(parents=True, exist_ok=True)
        backups = sorted(self._backup_directory.glob("*.db"),
                         key=lambda path: path.stat().st_mtime, reverse=True)
        self._backup_dropdown.options = [
            ft.DropdownOption(str(path), f"{path.name} · {self._format_bytes(path.stat().st_size)}")
            for path in backups
        ]
        values = {str(path) for path in backups}
        requested = str(selected) if selected else self._backup_dropdown.value
        self._backup_dropdown.value = requested if requested in values else None
        self._set_restore_enabled(update=False)
        self._safe_update(self._backup_dropdown)

    def _set_restore_enabled(self, update=True):
        if self._restore_button is not None:
            capturing = bool(self.state and self.state.capturing)
            self._restore_button.disabled = not bool(
                self._backup_dropdown and self._backup_dropdown.value
            ) or capturing
            if update:
                self._safe_update(self._restore_button)

    def _set_operation_status(self, text: str, color=GREEN):
        if self._operation_status is not None:
            self._operation_status.value = text
            self._operation_status.color = color
            self._safe_update(self._operation_status)

    def _create_backup(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        target = self._backup_directory / f"netpulse_backup_{stamp}.db"
        result = self.db.backup(target)
        self._refresh_backups(result)
        self._set_operation_status(f"Backup created: {result}")
        return result

    def _handle_backup(self):
        try:
            return self._create_backup()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self._set_operation_status(f"Backup failed: {exc}", RED)
            return None

    def _export_all(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = PROJECT_ROOT / "exports" / f"netpulse_all_data_{stamp}.zip"
        result = self.db.export_all_data(
            target, extra_files=[DEFAULT_SETTINGS_PATH, DEFAULT_LOG_PATH]
        )
        self._set_operation_status(f"All data exported: {result}")
        return result

    def _handle_export(self):
        try:
            return self._export_all()
        except (OSError, sqlite3.Error, ValueError) as exc:
            self._set_operation_status(f"Export failed: {exc}", RED)
            return None

    def _confirm_restore(self):
        page = self._page[0] if self._page else None
        value = self._backup_dropdown.value if self._backup_dropdown else None
        if page is None or not value or (self.state and self.state.capturing):
            return

        def cancel(event=None):
            close_dialog(page)

        def confirm(event=None):
            close_dialog(page)
            try:
                self._perform_restore(Path(value))
            except (OSError, sqlite3.Error, ValueError) as exc:
                self._set_operation_status(f"Restore failed: {exc}", RED)

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Restore database backup?", color=TEXT,
                          weight=ft.FontWeight.W_700),
            content=ft.Column([
                ft.Text(Path(value).name, color=AMBER, selectable=True),
                ft.Text("The current database will be backed up first. The selected copy "
                        "will then replace it after an integrity check.", color=DIM, size=11),
            ], tight=True, spacing=8),
            actions=[ft.TextButton("CANCEL", on_click=cancel),
                     ft.Button(content="RESTORE", icon=ft.Icons.RESTORE_ROUNDED,
                               color=AMBER, bgcolor=tint(AMBER, .13), on_click=confirm)],
            bgcolor=CARD,
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    def _perform_restore(self, source: Path) -> Path:
        safety = self.db.restore(source, self._backup_directory)
        self.selected.clear()
        self.refresh()
        self._refresh_backups()
        self._set_operation_status(
            f"Database restored. Safety backup: {safety}", AMBER
        )
        return safety

    def refresh(self):
        summary = self.db.storage_summary()
        if self._summary_values:
            for key in ("sessions", "scans", "assets", "quality"):
                self._summary_values[key].value = f"{summary.get(key, 0):,}"
            self._summary_values["bytes"].value = self._format_bytes(summary.get("bytes", 0))
        self._records = self._load_records()
        current_ids = {self._record_id(item) for item in self._records}
        self.selected.intersection_update(current_ids)
        self._render_records()
        self._refresh_backups()
        for value in self._summary_values.values():
            self._safe_update(value)

    def _confirm_delete(self, ids: set[int] | None = None):
        targets = set(ids or self.selected)
        page = self._page[0] if self._page else None
        if not targets or page is None:
            return

        def cancel(event=None):
            close_dialog(page)

        def confirm(event=None):
            close_dialog(page)
            self._perform_delete(targets)

        label = (SINGULAR_CATEGORIES[self.category] if len(targets) == 1
                 else CATEGORIES[self.category][0])
        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=RED, size=21),
                ft.Text("Delete saved data?", color=TEXT,
                        weight=ft.FontWeight.W_700),
            ], spacing=8),
            content=ft.Column([
                ft.Text(f"{len(targets)} {tr(label).lower()}", color=RED, size=13,
                        weight=ft.FontWeight.W_700),
                ft.Text("This action cannot be undone. Related records will also be removed.",
                        color=DIM, size=11),
            ], spacing=8, tight=True),
            actions=[
                ft.TextButton("CANCEL", on_click=cancel),
                ft.Button(content="DELETE", icon=ft.Icons.DELETE_FOREVER_ROUNDED,
                          color=RED, bgcolor=tint(RED, .14), on_click=confirm),
            ],
            bgcolor=CARD,
        )
        translate_tree(dialog, get_language())
        open_dialog(page, dialog)

    def _perform_delete(self, targets: set[int]) -> int:
        removed = self.db.delete_saved_records(self.category, list(targets))
        self.selected.difference_update(targets)
        self.refresh()
        return removed

    def on_mount(self):
        self.refresh()

    def set_viewport(self, width: float, height: float):
        content_width = snap(max(300.0, width - 28.0))
        content_height = snap(max(420.0, height - 28.0))
        columns = 5 if content_width >= 1050 else 3 if content_width >= 650 else 2
        key = (columns, content_width, content_height)
        if key == self._layout_key or not self._summary_cards:
            return
        self._layout_key = key
        widths = split(content_width, columns, 10)
        for index, item in enumerate(self._summary_cards):
            item.width = widths[index % len(widths)]
        for item in (self._toolbar_card, self._records_card):
            item.width = content_width
        self._records_card.height = max(260.0, content_height - 295.0)
        if content_width < 650:
            self._toolbar_row.wrap = True
            self._category_dropdown.width = min(260.0, content_width - 24.0)
            self._search.expand = False
            self._search.width = min(360.0, content_width - 24.0)
        else:
            self._toolbar_row.wrap = False
            self._category_dropdown.width = 220
            self._search.expand = True
            self._search.width = None

    @staticmethod
    def _safe_update(control):
        if control is None:
            return
        try:
            control.update()
        except (AssertionError, RuntimeError):
            pass
