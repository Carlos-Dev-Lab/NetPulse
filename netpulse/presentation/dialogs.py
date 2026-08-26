"""Single entry point for opening and closing Flet dialogs.

Flet 0.85 replaced the mutable ``Page.dialog`` attribute with the explicit
``show_dialog``/``pop_dialog`` pair. Assigning ``page.dialog`` on a real 0.85
page silently creates an unused attribute, so the dialog never becomes visible.
Routing every call site through these helpers keeps that regression from
returning and still supports the legacy attribute for older embeddings.
"""

import flet as ft


def supports_modern_dialog_api(page) -> bool:
    """Report whether *page* exposes the Flet 0.85 dialog API."""
    return hasattr(page, "show_dialog") and hasattr(page, "pop_dialog")


def _safe_update(page) -> None:
    update = getattr(page, "update", None)
    if update is None:
        return
    try:
        update()
    except Exception:
        pass


def open_dialog(page, dialog: ft.AlertDialog) -> None:
    """Display *dialog* on *page* regardless of the installed Flet version."""
    if page is None or dialog is None:
        return
    if hasattr(page, "show_dialog"):
        page.show_dialog(dialog)
        return
    page.dialog = dialog
    dialog.open = True
    _safe_update(page)


def close_dialog(page, dialog: ft.AlertDialog | None = None) -> None:
    """Dismiss the dialog currently shown on *page*."""
    if page is None:
        return
    if hasattr(page, "pop_dialog"):
        page.pop_dialog()
        return
    target = dialog if dialog is not None else getattr(page, "dialog", None)
    if target is not None:
        target.open = False
    _safe_update(page)
