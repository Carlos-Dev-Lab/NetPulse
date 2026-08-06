"""
NetPulse — Color System & UI Helpers
Dark glassmorphism theme, compatible with Flet 0.85+
"""
import flet as ft

# ── Palette ──────────────────────────────────────────────────────────────────
BG      = "#060A12"
SURFACE = "#0A111F"
CARD    = "#0D1728"

CYAN    = "#00D4FF"
GREEN   = "#00FF88"
RED     = "#FF4558"
AMBER   = "#FFB820"
PURPLE  = "#A855F7"
BLUE    = "#3B82F6"

TEXT    = "#EAF6FF"
DIM     = "#91A9BA"
MUTED   = "#587087"
BORDER  = "#1A3048"

PROTO_COLORS: dict = {
    "TCP":   CYAN,
    "UDP":   PURPLE,
    "HTTPS": BLUE,
    "HTTP":  AMBER,
    "DNS":   GREEN,
    "ICMP":  RED,
    "OTHER": MUTED,
}
PROTO_LIST = list(PROTO_COLORS.keys())

APPEARANCE_THEMES = {
    "netpulse": {"bg": BG, "surface": SURFACE, "card": CARD, "border": BORDER},
    "midnight": {"bg": "#050B18", "surface": "#091427", "card": "#0E1C33", "border": "#203B5B"},
    "graphite": {"bg": "#0D0F13", "surface": "#14171D", "card": "#1B1F27", "border": "#343B48"},
    "black": {"bg": "#000000", "surface": "#07090C", "card": "#0E1116", "border": "#252A33"},
}

APPEARANCE_ACCENTS = {
    "cyan": CYAN, "blue": BLUE, "green": GREEN, "purple": PURPLE, "amber": AMBER,
}


def appearance_palette(theme: str, accent: str) -> dict:
    palette = dict(APPEARANCE_THEMES.get(theme, APPEARANCE_THEMES["netpulse"]))
    palette["accent"] = APPEARANCE_ACCENTS.get(accent, CYAN)
    return palette


def recolor_tree(control, old_palette: dict, new_palette: dict) -> None:
    """Replace palette colors on mounted Flet controls in-place."""
    if control is None:
        return

    def replace(value):
        if not isinstance(value, str):
            return value
        upper = value.upper()
        for key in ("bg", "surface", "card", "border", "accent"):
            old = old_palette[key].upper()
            new = new_palette[key].upper()
            if upper == old:
                return new
            if len(upper) == 9 and upper.endswith(old.lstrip("#")):
                return upper[:3] + new.lstrip("#")
        return value

    for attr in (
        "bgcolor", "color", "icon_color", "focused_border_color", "border_color",
        "cursor_color", "fill_color", "indicator_color", "active_color",
        "selected_icon_color", "shadow_color",
    ):
        try:
            value = getattr(control, attr, None)
            changed = replace(value)
            if changed != value:
                setattr(control, attr, changed)
        except (AttributeError, TypeError, ValueError):
            pass
    for attr in ("content", "title", "subtitle", "leading", "trailing", "icon"):
        child = getattr(control, attr, None)
        if child is not None and not isinstance(child, (str, int, float, bool)):
            recolor_tree(child, old_palette, new_palette)
    for attr in ("controls", "actions", "destinations", "rows", "cells"):
        children = getattr(control, attr, None)
        if children:
            for child in list(children):
                recolor_tree(child, old_palette, new_palette)


def proto_color(p: str) -> str:
    return PROTO_COLORS.get(p, MUTED)


def tint(color: str, opacity: float) -> str:
    """Return a Flet-compatible translucent color (#AARRGGBB)."""
    return ft.Colors.with_opacity(opacity, color)


# ── Theme factory ─────────────────────────────────────────────────────────────
def make_theme(accent: str = CYAN, surface: str = SURFACE,
               density: ft.VisualDensity = ft.VisualDensity.STANDARD) -> ft.Theme:
    """Flet 0.85 compatible theme — uses color_scheme_seed only."""
    return ft.Theme(
        color_scheme_seed=accent,
        visual_density=density,
        color_scheme=ft.ColorScheme(
            primary=accent,
            secondary=GREEN,
            on_primary="#000000",
            on_surface=TEXT,
            surface=surface,
        ),
    )


# ── Reusable builders ─────────────────────────────────────────────────────────
def card(content, padding=14, glow: str | None = None, **kw) -> ft.Container:
    # Colour communicates category; glow is deliberately restrained so that
    # alerts and live actions remain the strongest elements on screen.
    return ft.Container(
        content=content,
        padding=padding,
        bgcolor=CARD,
        border_radius=14,
        border=ft.Border.all(1, tint(glow, .16) if glow else BORDER),
        shadow=ft.BoxShadow(
            blur_radius=18,
            color=tint(glow, .05) if glow else tint("#000000", .21),
            offset=ft.Offset(0, 6),
        ),
        **kw,
    )


def section_title(text: str, size: int = 13) -> ft.Text:
    return ft.Text(text, size=size, color=TEXT,
                   weight=ft.FontWeight.W_600)


def view_heading(title: str, subtitle: str, icon, accent: str = CYAN) -> ft.Container:
    """Compact, reusable heading that gives every workspace a clear purpose."""
    return ft.Container(
        content=ft.Row([
            ft.Container(
                content=ft.Icon(icon, color=accent, size=22),
                width=42, height=42, alignment=ft.Alignment.CENTER,
                bgcolor=tint(accent, .08), border_radius=11,
                border=ft.Border.all(1, tint(accent, .19)),
            ),
            ft.Container(
                content=ft.Column([
                    ft.Text(title, size=17, color=TEXT, weight=ft.FontWeight.W_700),
                    ft.Text(subtitle, size=10, color=MUTED),
                ], spacing=1, alignment=ft.MainAxisAlignment.CENTER),
                expand=True,
            ),
            ft.Container(width=34, height=2, bgcolor=accent, border_radius=2),
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        height=54,
        alignment=ft.Alignment.CENTER,
        padding=ft.padding.Padding.only(left=2, right=2, top=2, bottom=2),
    )


def badge(text: str, color: str) -> ft.Container:
    return ft.Container(
        content=ft.Text(text, size=10, color=color, weight=ft.FontWeight.W_700),
        bgcolor=tint(color, .13),
        border_radius=5,
        padding=ft.padding.Padding.symmetric(horizontal=6, vertical=2),
        border=ft.Border.all(1, tint(color, .33)),
    )
