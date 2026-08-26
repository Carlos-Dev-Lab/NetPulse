"""Reusable canvas-based chart components."""

import math
from typing import Optional

import flet as ft
import flet.canvas as cv

from .theme import (
    AMBER, BG, BORDER, CARD, CYAN, DIM, GREEN, MUTED, PURPLE, RED, TEXT,
)
from .i18n import tr

# Canvas shapes are rebuilt from Python on every repaint, so they cannot rely on
# the recoloured control tree. This module-level palette is what the drawing
# code reads; ``apply_palette`` swaps it when the appearance changes.
_PALETTE = {
    "bg": BG, "surface": BG, "card": CARD, "border": BORDER,
    "text": TEXT, "dim": DIM, "muted": MUTED,
}


def apply_palette(palette: dict) -> None:
    """Point chart drawing at a new appearance palette."""
    for role in _PALETTE:
        value = palette.get(role)
        if isinstance(value, str) and value:
            _PALETTE[role] = value


def active_palette() -> dict:
    """Expose the palette the canvases currently draw with."""
    return dict(_PALETTE)


def _role(name: str) -> str:
    return _PALETTE[name]


def _remap(color: str, mapping: dict) -> str:
    """Translate one series colour through an old-hex to new-hex mapping."""
    if not isinstance(color, str):
        return color
    return mapping.get(color.upper(), color)


def _hex_to_rgb(h: str):
    h = h.lstrip("#")[:6]
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _rgba(color: str, alpha: float = 1.0) -> str:
    """Convert #RRGGBB to flet rgba string."""
    r, g, b = _hex_to_rgb(color)
    a = int(alpha * 255)
    return f"#{a:02X}{r:02X}{g:02X}{b:02X}"


class LineChartCanvas:
    """Line chart drawn on flet.canvas.Canvas — plain Python helper class."""

    PAD_L, PAD_R, PAD_T, PAD_B = 44, 12, 10, 28

    def __init__(self, color_a: str = CYAN, color_b: str = GREEN,
                 label_a: str = "IN", label_b: str = "OUT",
                 n_points: int = 60, height: int = 180):
        self.W = 600
        self._color_a = color_a
        self._color_b = color_b
        self._label_a = label_a
        self._label_b = label_b
        self._n = n_points
        self.H = height
        self._data_a: list = [0.0] * n_points
        self._data_b: list = [0.0] * n_points
        self._canvas: Optional[cv.Canvas] = None
        # Build widget immediately — embed self.widget in layouts
        self._canvas = cv.Canvas(shapes=self._build_shapes(), expand=True)
        self.widget = ft.Container(
            content=self._canvas, height=self.H, expand=True,
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
        )

    def update_data(self, data_a: list, data_b: list):
        self._data_a = list(data_a)[-self._n:]
        self._data_b = list(data_b)[-self._n:]
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def recolor(self, mapping: dict) -> None:
        """Move both series onto the new appearance palette."""
        self._color_a = _remap(self._color_a, mapping)
        self._color_b = _remap(self._color_b, mapping)
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def resize(self, width: float, height: float) -> None:
        """Resize both the container and the canvas coordinate system."""
        self.W = max(220.0, float(width))
        self.H = max(110.0, float(height))
        self.widget.width = self.W
        self.widget.height = self.H
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def _build_shapes(self) -> list:
        shapes = []
        W, H = self.W, self.H
        pl, pr, pt, pb = self.PAD_L, self.PAD_R, self.PAD_T, self.PAD_B
        cw = W - pl - pr
        ch = H - pt - pb

        all_vals = self._data_a + self._data_b
        max_v = max(all_vals) if all_vals else 1
        max_v = max(max_v, 0.1)

        def px(i): return pl + (i / (self._n - 1)) * cw
        def py(v): return pt + ch - (v / max_v) * ch

        # Grid lines (horizontal)
        for k in range(1, 5):
            y = pt + ch * (1 - k / 4)
            shapes.append(cv.Line(
                pl, y, W - pr, y,
                paint=ft.Paint(color=_rgba(_role("border"), 0.6), stroke_width=0.5),
            ))
            v_label = max_v * k / 4
            shapes.append(cv.Text(
                x=2, y=y - 7,
                value=f"{v_label:.0f}" if max_v > 10 else f"{v_label:.1f}",
                style=ft.TextStyle(size=9, color=_role("muted")),
            ))

        # Area fill + line for series A
        if len(self._data_a) >= 2:
            path_a = cv.Path(
                elements=[cv.Path.MoveTo(px(0), py(self._data_a[0]))]
                + [cv.Path.LineTo(px(i), py(self._data_a[i]))
                   for i in range(1, len(self._data_a))]
                + [cv.Path.LineTo(px(len(self._data_a) - 1), pt + ch),
                   cv.Path.LineTo(px(0), pt + ch),
                   cv.Path.Close()],
                paint=ft.Paint(
                    color=_rgba(self._color_a, 0.1),
                    style=ft.PaintingStyle.FILL,
                ),
            )
            shapes.append(path_a)
            shapes.append(cv.Path(
                elements=[cv.Path.MoveTo(px(0), py(self._data_a[0]))]
                + [cv.Path.LineTo(px(i), py(self._data_a[i]))
                   for i in range(1, len(self._data_a))],
                paint=ft.Paint(
                    color=self._color_a,
                    stroke_width=2,
                    style=ft.PaintingStyle.STROKE,
                    stroke_cap=ft.StrokeCap.ROUND,
                    stroke_join=ft.StrokeJoin.ROUND,
                ),
            ))

        # Area fill + line for series B
        if len(self._data_b) >= 2:
            path_b = cv.Path(
                elements=[cv.Path.MoveTo(px(0), py(self._data_b[0]))]
                + [cv.Path.LineTo(px(i), py(self._data_b[i]))
                   for i in range(1, len(self._data_b))]
                + [cv.Path.LineTo(px(len(self._data_b) - 1), pt + ch),
                   cv.Path.LineTo(px(0), pt + ch),
                   cv.Path.Close()],
                paint=ft.Paint(
                    color=_rgba(self._color_b, 0.1),
                    style=ft.PaintingStyle.FILL,
                ),
            )
            shapes.append(path_b)
            shapes.append(cv.Path(
                elements=[cv.Path.MoveTo(px(0), py(self._data_b[0]))]
                + [cv.Path.LineTo(px(i), py(self._data_b[i]))
                   for i in range(1, len(self._data_b))],
                paint=ft.Paint(
                    color=self._color_b,
                    stroke_width=2,
                    style=ft.PaintingStyle.STROKE,
                    stroke_cap=ft.StrokeCap.ROUND,
                    stroke_join=ft.StrokeJoin.ROUND,
                ),
            ))

        # Axes
        shapes.append(cv.Line(pl, pt, pl, pt + ch,
                              paint=ft.Paint(color=_role("border"), stroke_width=1)))
        shapes.append(cv.Line(pl, pt + ch, W - pr, pt + ch,
                              paint=ft.Paint(color=_role("border"), stroke_width=1)))

        if not any(self._data_a) and not any(self._data_b):
            shapes.append(cv.Text(
                x=max(pl + 8, W / 2 - 38), y=max(pt + 8, H / 2 - 8),
                value=tr("WAITING FOR TRAFFIC"),
                style=ft.TextStyle(size=10, color=_role("muted")),
            ))

        return shapes

    # widget is built in __init__, no build() needed


class SparklineCanvas:
    """Tiny sparkline for the header bar."""
    W = 80
    H = 24

    def __init__(self, color: str = CYAN, n_points: int = 30):
        self._color = color
        self._n = n_points
        self._data: list = [0.0] * n_points
        self._canvas = cv.Canvas(shapes=[], width=self.W, height=self.H)
        self.widget = ft.Container(
            content=self._canvas, width=self.W, height=self.H,
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
        )

    def update_data(self, data: list):
        self._data = list(data)[-self._n:]
        self._canvas.shapes = self._build_shapes()

    def recolor(self, mapping: dict) -> None:
        self._color = _remap(self._color, mapping)
        self._canvas.shapes = self._build_shapes()

    def _build_shapes(self) -> list:
        shapes = []
        W, H = self.W, self.H
        pad = 2
        cw, ch = W - pad * 2, H - pad * 2
        n = self._n
        max_v = max(self._data) if self._data else 1
        max_v = max(max_v, 0.01)

        def px(i): return pad + (i / (n - 1)) * cw
        def py(v): return pad + ch - (v / max_v) * ch

        if len(self._data) >= 2:
            # Area
            shapes.append(cv.Path(
                elements=[cv.Path.MoveTo(px(0), py(self._data[0]))]
                + [cv.Path.LineTo(px(i), py(self._data[i])) for i in range(1, len(self._data))]
                + [cv.Path.LineTo(px(len(self._data) - 1), H),
                   cv.Path.LineTo(px(0), H), cv.Path.Close()],
                paint=ft.Paint(color=_rgba(self._color, 0.15), style=ft.PaintingStyle.FILL),
            ))
            # Line
            shapes.append(cv.Path(
                elements=[cv.Path.MoveTo(px(0), py(self._data[0]))]
                + [cv.Path.LineTo(px(i), py(self._data[i])) for i in range(1, len(self._data))],
                paint=ft.Paint(
                    color=self._color, stroke_width=1.5,
                    style=ft.PaintingStyle.STROKE,
                    stroke_cap=ft.StrokeCap.ROUND,
                    stroke_join=ft.StrokeJoin.ROUND,
                ),
            ))
        return shapes


class BarChartCanvas:
    """Bar chart drawn on flet.canvas.Canvas — plain Python helper class."""

    PAD_L, PAD_R, PAD_T, PAD_B = 40, 10, 10, 24

    def __init__(self, labels: list, colors: list, height: int = 180):
        self.W = 500
        self._labels = labels
        self._colors = colors
        self.H = height
        self._values: list = [0.0] * len(labels)
        self._canvas: Optional[cv.Canvas] = None
        self._canvas = cv.Canvas(shapes=self._build_shapes(), expand=True)
        self.widget = ft.Container(
            content=self._canvas, height=self.H, expand=True,
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
        )

    def update_data(self, values: list):
        self._values = list(values)
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def recolor(self, mapping: dict) -> None:
        self._colors = [_remap(color, mapping) for color in self._colors]
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def resize(self, width: float, height: float) -> None:
        """Resize both the container and the canvas coordinate system."""
        self.W = max(240.0, float(width))
        self.H = max(120.0, float(height))
        self.widget.width = self.W
        self.widget.height = self.H
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def _build_shapes(self) -> list:
        shapes = []
        W, H = self.W, self.H
        pl, pr, pt, pb = self.PAD_L, self.PAD_R, self.PAD_T, self.PAD_B
        cw = W - pl - pr
        ch = H - pt - pb

        n = len(self._labels)
        max_v = max(self._values) if self._values else 1
        max_v = max(max_v, 1)

        bar_w = (cw / n) * 0.55
        gap   = cw / n

        # Horizontal grid
        for k in range(1, 4):
            y = pt + ch * (1 - k / 3)
            shapes.append(cv.Line(pl, y, W - pr, y,
                                  paint=ft.Paint(color=_rgba(_role("border"), 0.5), stroke_width=0.4)))
            shapes.append(cv.Text(x=2, y=y - 7,
                                  value=f"{int(max_v * k / 3)}",
                                  style=ft.TextStyle(size=9, color=_role("muted"))))

        # Bars
        for i, (lbl, clr, val) in enumerate(zip(self._labels, self._colors, self._values)):
            bx = pl + i * gap + gap / 2 - bar_w / 2
            bh = (val / max_v) * ch if max_v > 0 else 0
            by = pt + ch - bh

            # Shadow/glow
            if bh > 2:
                shapes.append(cv.Rect(
                    bx - 2, by - 2, bar_w + 4, bh + 4,
                    border_radius=5,
                    paint=ft.Paint(color=_rgba(clr, 0.12), style=ft.PaintingStyle.FILL),
                ))
                # Gradient bar (bottom to top: dim → bright)
                shapes.append(cv.Rect(
                    bx, by, bar_w, bh,
                    border_radius=4,
                    paint=ft.Paint(
                        gradient=ft.LinearGradient(
                            begin=ft.Alignment(0, 1),
                            end=ft.Alignment(0, -1),
                            colors=[_rgba(clr, 0.5), clr],
                        ),
                        style=ft.PaintingStyle.FILL,
                    ),
                ))

            # Label
            shapes.append(cv.Text(
                x=bx + bar_w / 2 - len(lbl) * 3.2,
                y=pt + ch + 5,
                value=lbl,
                style=ft.TextStyle(size=9, color=_role("dim")),
            ))
            # Value
            if val > 0:
                shapes.append(cv.Text(
                    x=bx + bar_w / 2 - 10,
                    y=by - 14,
                    value=f"{int(val):,}",
                    style=ft.TextStyle(size=9, color=clr),
                ))

        # Axes
        shapes.append(cv.Line(pl, pt, pl, pt + ch,
                              paint=ft.Paint(color=_role("border"), stroke_width=1)))
        shapes.append(cv.Line(pl, pt + ch, W - pr, pt + ch,
                              paint=ft.Paint(color=_role("border"), stroke_width=1)))
        return shapes

    # widget is built in __init__, no build() needed


class PieChartCanvas:
    """Pie/donut chart drawn on flet.canvas.Canvas — plain Python helper class."""

    SIZE = 180

    def __init__(self):
        self._sections: list = []   # [(label, value, color)]
        self._canvas: Optional[cv.Canvas] = None
        self._canvas = cv.Canvas(shapes=self._build_shapes(),
                                 width=self.SIZE, height=self.SIZE)
        self.widget = ft.Container(
            content=self._canvas, width=self.SIZE, height=self.SIZE,
        )

    def update_data(self, sections: list):
        self._sections = sections
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def recolor(self, mapping: dict) -> None:
        self._sections = [(label, value, _remap(color, mapping))
                          for label, value, color in self._sections]
        if self._canvas:
            self._canvas.shapes = self._build_shapes()

    def resize(self, size: float) -> None:
        """Keep the donut square while adapting it to the available card."""
        self.SIZE = max(120.0, float(size))
        self.widget.width = self.SIZE
        self.widget.height = self.SIZE
        if self._canvas:
            self._canvas.width = self.SIZE
            self._canvas.height = self.SIZE
            self._canvas.shapes = self._build_shapes()

    def _build_shapes(self) -> list:
        shapes = []
        S = self.SIZE
        cx, cy = S / 2, S / 2
        r_outer = S / 2 - 10
        r_inner = r_outer * 0.45

        total = sum(v for _, v, _ in self._sections) or 1
        angle = -math.pi / 2   # start from top

        if not self._sections:
            shapes.extend([
                cv.Circle(
                    cx, cy, r_outer,
                    paint=ft.Paint(
                        color=_role("border"), stroke_width=12,
                        style=ft.PaintingStyle.STROKE,
                    ),
                ),
                cv.Text(
                    x=cx - 23, y=cy - 7, value=tr("NO DATA"),
                    style=ft.TextStyle(size=10, color=_role("muted")),
                ),
            ])
            return shapes

        for lbl, val, clr in self._sections:
            sweep = (val / total) * 2 * math.pi
            if sweep < 0.02:
                angle += sweep
                continue

            mid = angle + sweep / 2
            # Slight outward nudge on the slice
            nudge = 4
            dx, dy = math.cos(mid) * nudge, math.sin(mid) * nudge

            # Arc path approximation using many line segments
            steps = max(int(sweep / (math.pi / 30)), 3)
            pts = []
            for k in range(steps + 1):
                a = angle + sweep * k / steps
                pts.append((cx + dx + math.cos(a) * r_outer,
                             cy + dy + math.sin(a) * r_outer))

            elements = [cv.Path.MoveTo(cx + dx, cy + dy)]
            elements.append(cv.Path.LineTo(pts[0][0], pts[0][1]))
            for px2, py2 in pts[1:]:
                elements.append(cv.Path.LineTo(px2, py2))
            # Inner arc (reverse)
            inner_pts = []
            for k in range(steps + 1):
                a = angle + sweep * (steps - k) / steps
                inner_pts.append((cx + dx + math.cos(a) * r_inner,
                                   cy + dy + math.sin(a) * r_inner))
            for px2, py2 in inner_pts:
                elements.append(cv.Path.LineTo(px2, py2))
            elements.append(cv.Path.Close())

            shapes.append(cv.Path(
                elements=elements,
                paint=ft.Paint(color=clr, style=ft.PaintingStyle.FILL),
            ))
            # Border stroke
            shapes.append(cv.Path(
                elements=elements,
                paint=ft.Paint(
                    color=_role("bg"), stroke_width=2,
                    style=ft.PaintingStyle.STROKE,
                ),
            ))

            # Label at midpoint outside
            label_r = r_outer + 14
            lx = cx + math.cos(mid) * label_r - len(lbl) * 3
            ly = cy + math.sin(mid) * label_r - 5
            shapes.append(cv.Text(
                x=max(2, min(S - 30, lx)),
                y=max(2, min(S - 12, ly)),
                value=lbl,
                style=ft.TextStyle(size=9, color=clr, weight=ft.FontWeight.W_600),
            ))

            angle += sweep

        # Center hole background
        steps = 48
        inner_pts = [
            (cx + math.cos(angle + 2 * math.pi * k / steps) * r_inner,
             cy + math.sin(angle + 2 * math.pi * k / steps) * r_inner)
            for k in range(steps + 1)
        ]
        el = [cv.Path.MoveTo(*inner_pts[0])]
        for p in inner_pts[1:]:
            el.append(cv.Path.LineTo(*p))
        el.append(cv.Path.Close())
        shapes.append(cv.Path(elements=el,
                              paint=ft.Paint(color=_role("card"), style=ft.PaintingStyle.FILL)))

        return shapes

    # widget is built in __init__, no build() needed


