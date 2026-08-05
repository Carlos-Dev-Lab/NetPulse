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


def proto_color(p: str) -> str:
    return PROTO_COLORS.get(p, MUTED)


def tint(color: str, opacity: float) -> str:
    """Return a Flet-compatible translucent color (#AARRGGBB)."""
    return ft.Colors.with_opacity(opacity, color)


# ── Theme factory ─────────────────────────────────────────────────────────────
def make_theme() -> ft.Theme:
    """Flet 0.85 compatible theme — uses color_scheme_seed only."""
    return ft.Theme(
        color_scheme_seed=CYAN,
        color_scheme=ft.ColorScheme(
            primary=CYAN,
            secondary=GREEN,
            on_primary="#000000",
            on_surface=TEXT,
            surface=SURFACE,
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
