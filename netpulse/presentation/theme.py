"""
NetPulse — Color System & UI Helpers
Dark glassmorphism theme, compatible with Flet 0.85+
"""
import sys

import flet as ft

# ── Palette ──────────────────────────────────────────────────────────────────
# Surfaces form a deliberate elevation ladder: every step is at least a 1.09
# contrast ratio and background to card clears 1.19, so cards read as cards
# instead of dissolving into one dark mass.
BG      = "#05090F"
SURFACE = "#0B1526"
CARD    = "#122139"

CYAN    = "#00D4FF"
GREEN   = "#00FF88"
RED     = "#FF4558"
AMBER   = "#FFB820"
# 232 deg instead of 217 deg: the HTTPS chip was only 27 deg from the TCP cyan
# and 8 deg from the neutral chip, which made the packet table hard to scan.
BLUE    = "#7082F7"
PURPLE  = "#B268F8"

TEXT    = "#EAF6FF"
DIM     = "#91A9BA"
# Near-neutral grey at 11% saturation. The old #587087 was a blue at 3.2:1 on a
# card - below the 4.5:1 floor for the 8-12 px labels it is used for - and it sat
# between the cyan and blue chips on the hue wheel.
MUTED   = "#808E99"
BORDER  = "#26456A"

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

# Roles swapped when the appearance changes. ``accent`` is appended by
# ``appearance_palette`` because it comes from a separate selector.
PALETTE_ROLES = (
    "bg", "surface", "card", "border", "text", "dim", "muted",
    "cyan", "green", "red", "amber", "purple", "blue",
)

# Dark themes share the neon status palette; light themes need darker, denser
# variants so status colour stays legible on a bright surface.
_DARK_INK = {"text": TEXT, "dim": DIM, "muted": MUTED}
_DARK_STATUS = {"cyan": CYAN, "green": GREEN, "red": RED,
                "amber": AMBER, "purple": PURPLE, "blue": BLUE}
# Light themes keep the same hue wheel so a protocol keeps its identity, but
# every value is solved against the darkest light surface, not against white.
_LIGHT_INK = {"text": "#102943", "dim": "#3F5770", "muted": "#5E6973"}
_LIGHT_STATUS = {"cyan": "#007188", "green": "#007740", "red": "#C82131",
                 "amber": "#8B5F00", "purple": "#8C3AD9", "blue": "#4358E0"}

APPEARANCE_THEMES = {
    "netpulse": {"bg": BG, "surface": SURFACE, "card": CARD, "border": BORDER,
                 **_DARK_INK, **_DARK_STATUS, "light": False},
    "midnight": {"bg": "#050B18", "surface": "#0A1830", "card": "#12243F",
                 "border": "#2C4E76", **_DARK_INK, **_DARK_STATUS, "light": False},
    "graphite": {"bg": "#0B0D11", "surface": "#161A21", "card": "#20252F",
                 "border": "#414A5A", **_DARK_INK, **_DARK_STATUS, "light": False},
    # Pure black leaves little room for the first step, so the surface is
    # lifted just enough to keep the header and rail readable as a plane.
    "black": {"bg": "#000000", "surface": "#0D1017", "card": "#171D28",
              "border": "#363E4D", **_DARK_INK, **_DARK_STATUS, "light": False},
    "daylight": {"bg": "#E3EAF3", "surface": "#F3F7FC", "card": "#FFFFFF",
                 "border": "#AABCD1", **_LIGHT_INK, **_LIGHT_STATUS, "light": True},
    "paper": {"bg": "#EDE7DA", "surface": "#FAF7F1", "card": "#FFFFFF",
              "border": "#C2B7A2", **_LIGHT_INK, **_LIGHT_STATUS, "light": True},
}

# The accent paints chrome: the brand mark, the rail indicator, section
# headings, focus rings. Green, amber and red are reserved for state, so they
# are no longer offered - a green rail reads as "everything succeeded" and an
# amber one as a standing warning. These values are the accent's own, never
# shared with a semantic role.
APPEARANCE_ACCENTS = {
    "cyan": "#00D4FF", "blue": "#448AFA", "violet": "#C361ED",
    "magenta": "#F542AA", "slate": "#748FA6",
}
LIGHT_ACCENTS = {
    "cyan": "#00687E", "blue": "#065DE8", "violet": "#A219DD",
    "magenta": "#C70A78", "slate": "#516A7F",
}
# Choices from before green and amber were retired.
LEGACY_ACCENTS = {"green": "cyan", "amber": "magenta", "purple": "violet"}


def appearance_palette(theme: str, accent: str) -> dict:
    """Return every colour role for one theme and accent combination."""
    palette = dict(APPEARANCE_THEMES.get(theme, APPEARANCE_THEMES["netpulse"]))
    table = LIGHT_ACCENTS if palette.get("light") else APPEARANCE_ACCENTS
    accent = LEGACY_ACCENTS.get(accent, accent)
    palette["accent"] = table.get(accent, table["cyan"])
    return palette


def recolor_tree(control, old_palette: dict, new_palette: dict, seen=None) -> None:
    """Replace palette colors on Flet controls in-place.

    ``seen`` lets one repaint span several roots — the layout plus the view
    wrappers Flet has not mounted yet — without swapping a shared control twice.
    """
    if control is None:
        return
    if seen is None:
        seen = set()
    if id(control) in seen:
        return
    seen.add(id(control))

    # Text and status roles matter as much as the surfaces: a light theme needs
    # dark ink and denser status colours, otherwise the workspace turns into
    # white-on-white the moment the operator leaves the dark presets.
    # ``accent`` is deliberately absent. It shares its value with a semantic
    # role (the brand cyan is also the TCP cyan), so mapping it by colour
    # repainted every data chip too - and anything rendered afterwards came
    # back in the original colour, leaving two colours for one meaning on
    # screen. Chrome follows the accent through ``accented``/``apply_accent``.
    roles = tuple(role for role in PALETTE_ROLES
                  if role in old_palette and role in new_palette)

    def replace(value):
        if not isinstance(value, str):
            return value
        upper = value.upper()
        for key in roles:
            old = old_palette[key].upper()
            new = new_palette[key].upper()
            if old == new:
                continue
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
            recolor_tree(child, old_palette, new_palette, seen)
    for attr in ("controls", "actions", "destinations", "rows", "cells"):
        children = getattr(control, attr, None)
        if children:
            for child in list(children):
                recolor_tree(child, old_palette, new_palette, seen)


# Controls whose colour is the accent rather than a meaning. Registering them
# is what lets the accent change without touching a single data colour.
_ACCENTED: list = []


def accented(control, attr: str = "color", alpha: float | None = None):
    """Mark one control attribute as following the accent. Returns the control."""
    _ACCENTED.append((control, attr, alpha))
    return control


def apply_accent(color: str) -> None:
    """Repaint every registered chrome control with *color*."""
    for control, attr, alpha in _ACCENTED:
        try:
            setattr(control, attr, tint(color, alpha) if alpha is not None else color)
        except (AttributeError, TypeError, ValueError):
            pass


def clear_accent_registry() -> None:
    """Drop registered controls. Used when a workspace is rebuilt, and by tests."""
    _ACCENTED.clear()


def selectable_content(control: ft.Control) -> ft.SelectionArea:
    """Provide one continuous native selection scope for an entire view."""
    return ft.SelectionArea(content=control, expand=True)


def selectable_dialog_content(dialog: ft.AlertDialog) -> None:
    """Allow conventional drag selection across all text in a dialog body."""
    def contains_form_control(node, seen=None) -> bool:
        if node is None:
            return False
        seen = seen or set()
        if id(node) in seen:
            return False
        seen.add(id(node))
        form_types = (
            ft.TextField, ft.Dropdown, ft.Checkbox, ft.Switch, ft.Radio,
            ft.RadioGroup, ft.Slider, ft.RangeSlider,
        )
        if isinstance(node, form_types):
            return True
        for attr in ("content", "controls", "leading", "trailing", "rows", "cells"):
            child = getattr(node, attr, None)
            if isinstance(child, (list, tuple)):
                if any(contains_form_control(item, seen) for item in child):
                    return True
            elif child is not None and not isinstance(child, (str, int, float, bool)):
                if contains_form_control(child, seen):
                    return True
        return False

    if (dialog.content is not None
            and not isinstance(dialog.content, ft.SelectionArea)
            and not contains_form_control(dialog.content)):
        dialog.content = ft.SelectionArea(content=dialog.content)


# Protocol badges, the donut and the bar chart all resolve their colour at
# refresh time, so they only follow the theme if the lookup does.
PROTO_ROLES = {
    "TCP": "cyan", "UDP": "purple", "HTTPS": "blue", "HTTP": "amber",
    "DNS": "green", "ICMP": "red", "OTHER": "muted",
}
_ACTIVE_PALETTE: dict = appearance_palette("netpulse", "cyan")

# Views build rows on every refresh from these module-level names. Rebinding
# them is what keeps content rendered *after* a theme change on the new palette;
# ``recolor_tree`` can only reach controls that already exist.
PALETTE_CONSTANTS = {
    "BG": "bg", "SURFACE": "surface", "CARD": "card", "BORDER": "border",
    "TEXT": "text", "DIM": "dim", "MUTED": "muted",
    "CYAN": "cyan", "GREEN": "green", "RED": "red",
    "AMBER": "amber", "PURPLE": "purple", "BLUE": "blue",
}
PALETTE_CONSUMERS = (
    "netpulse.presentation.theme",
    "netpulse.presentation.views",
    "netpulse.presentation.application_traffic",
    "netpulse.presentation.charts",
    "netpulse.presentation.app",
)


def set_active_palette(palette: dict) -> None:
    """Record the palette every colour lookup should resolve against."""
    _ACTIVE_PALETTE.clear()
    _ACTIVE_PALETTE.update(palette)
    for name, role in PROTO_ROLES.items():
        PROTO_COLORS[name] = _ACTIVE_PALETTE.get(role, PROTO_COLORS[name])
    for module_name in PALETTE_CONSUMERS:
        module = sys.modules.get(module_name)
        if module is None:
            continue
        for constant, role in PALETTE_CONSTANTS.items():
            value = palette.get(role)
            if isinstance(value, str) and value and hasattr(module, constant):
                setattr(module, constant, value)


def active_palette() -> dict:
    return dict(_ACTIVE_PALETTE)


def proto_color(p: str) -> str:
    role = PROTO_ROLES.get(p)
    if role:
        return _ACTIVE_PALETTE.get(role, PROTO_COLORS.get(p, MUTED))
    return PROTO_COLORS.get(p, _ACTIVE_PALETTE.get("muted", MUTED))


def tint(color: str, opacity: float) -> str:
    """Return a Flet-compatible translucent color (#AARRGGBB)."""
    return ft.Colors.with_opacity(opacity, color)


# ── Theme factory ─────────────────────────────────────────────────────────────
def make_theme(accent: str = CYAN, surface: str = SURFACE,
               density: ft.VisualDensity = ft.VisualDensity.STANDARD,
               palette: dict | None = None) -> ft.Theme:
    """Flet 0.85 compatible theme built from one appearance palette."""
    palette = palette or {}
    text = palette.get("text", TEXT)
    secondary = palette.get("green", GREEN)
    light = bool(palette.get("light"))
    return ft.Theme(
        color_scheme_seed=accent,
        visual_density=density,
        color_scheme=ft.ColorScheme(
            primary=accent,
            secondary=secondary,
            # Buttons paint their label with ``on_primary``; a light theme uses
            # saturated accents, so the label has to flip to white.
            on_primary="#FFFFFF" if light else "#000000",
            on_surface=text,
            surface=surface,
        ),
    )


def theme_mode(palette: dict | None) -> ft.ThemeMode:
    """Map an appearance palette to the Flet brightness it expects."""
    return ft.ThemeMode.LIGHT if (palette or {}).get("light") else ft.ThemeMode.DARK


# ── Reusable builders ─────────────────────────────────────────────────────────
def card(content, padding=14, **kw) -> ft.Container:
    """A card frame. Structural, never chromatic.

    Cards used to tint their border and shadow with a per-card accent, so a
    single screen showed five or six different frame colours and the eye read
    the chrome before the data. The frame is now uniform: colour lives in the
    content, where it encodes something.
    """
    return ft.Container(
        content=content,
        padding=padding,
        bgcolor=CARD,
        border_radius=14,
        border=ft.Border.all(1, BORDER),
        shadow=ft.BoxShadow(
            blur_radius=18,
            color=tint("#000000", .21),
            offset=ft.Offset(0, 6),
        ),
        **kw,
    )


def section_title(text: str, size: int = 13, icon=None,
                  color: str | None = None):
    """Section heading, optionally prefixed by a Material icon.

    Card headings used to mix emoji with Material icons, which reads as two
    different design languages on the same screen. Passing ``icon`` keeps every
    heading on the Material set and lets the icon carry the accent colour.
    """
    label = ft.Text(text, size=size, color=TEXT, weight=ft.FontWeight.W_600)
    if icon is None:
        return label
    return ft.Row(
        [ft.Icon(icon, color=color or CYAN, size=size + 3), label],
        spacing=7, vertical_alignment=ft.CrossAxisAlignment.CENTER, tight=True,
    )


def view_heading(title: str, subtitle: str, icon, accent: str = CYAN) -> ft.Container:
    """Compact, reusable heading that gives every workspace a clear purpose.

    The icon, its plate and the end rule are chrome, so they are registered to
    follow the accent instead of being swapped by colour value.
    """
    glyph = accented(ft.Icon(icon, color=accent, size=22))
    plate = accented(
        ft.Container(
            content=glyph,
            width=42, height=42, alignment=ft.Alignment.CENTER,
            bgcolor=tint(accent, .08), border_radius=11,
            border=ft.Border.all(1, tint(accent, .19)),
        ),
        "bgcolor", .08,
    )
    rule = accented(ft.Container(width=34, height=2, bgcolor=accent,
                                 border_radius=2), "bgcolor")
    return ft.Container(
        content=ft.Row([
            plate,
            ft.Container(
                content=ft.Column([
                    ft.Text(title, size=17, color=TEXT, weight=ft.FontWeight.W_700),
                    ft.Text(subtitle, size=10, color=MUTED),
                ], spacing=1, alignment=ft.MainAxisAlignment.CENTER),
                expand=True,
            ),
            rule,
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
