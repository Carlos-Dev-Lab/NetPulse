"""Interactive radial topology map used by the Network workspace."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

import flet as ft

from netpulse.domain.topology import TopologyNode, TopologySegment
from .i18n import tr
from .theme import (
    AMBER, BG, BLUE, BORDER, CARD, CYAN, DIM, GREEN, MUTED, PURPLE, RED,
    SURFACE, TEXT, tint,
)


# One node draws its icon, its badge and a two-line label plate inside this
# box. Two boxes closer than this on both axes overlap on screen.
NODE_WIDTH = 124.0
NODE_HEIGHT = 126.0
# The box is anchored so the icon sits on the device coordinate and the label
# hangs below it, which is why it is not vertically centred on that point.
NODE_TOP = 48.0
NODE_BOTTOM = NODE_HEIGHT - NODE_TOP
# Base radii of the first ring. The map frame is roughly two and a half
# times wider than it is tall, so the figure is an ellipse of about the same
# proportion and grows mostly sideways: height is the axis that runs out.
RING_X = 420.0
RING_Y = 170.0
# How much of a growth step goes into the vertical radius.
RING_Y_GAIN = .45
# How much wider each ring is than the one inside it, when the figure is built
# from the hub outwards. Below about .8 two neighbouring rings sit closer than
# one label box is tall.
RING_GROWTH = .85
# The frame the figure is shaped for: wide and short.
FRAME_ASPECT = 2.6
# The smallest canvas, used while a scan has only a handful of devices.
MIN_CANVAS_WIDTH = 920.0
MIN_CANVAS_HEIGHT = 500.0
# The floor for the automatic fit, and the same floor the zoom-out button
# reaches: at this size the labels are small but every device is on screen,
# which beats hiding a third of the network off the edges of the frame.
# Compact desktop windows can leave only ~550 px beside the node detail card.
# A 21-host subnet needs roughly 0.34x to keep its outer labels inside that
# frame; the previous 0.50 floor deliberately cropped both sides.
MIN_FIT_ZOOM = .3
# The height of the map surface and of the detail panel beside it.
PANEL_HEIGHT = 520.0

# Connection table columns. The Spanish headings ("Destino", "Protocolo") are
# longer than the English source strings, and at the previous 8 px body size
# the whole table read as a caption rather than as data.
COL_ADDRESS = 150.0
COL_PROTOCOL = 84.0
COL_PORT = 66.0
COL_STATUS = 96.0
# What the fixed columns plus their gaps need before "Service" gets any room.
TABLE_MIN_WIDTH = (COL_ADDRESS * 2 + COL_PROTOCOL + COL_PORT + COL_STATUS
                   + 8 * 5 + 120 + 20)


@dataclass(slots=True)
class MapDevice:
    node: TopologyNode
    host: object
    x: float
    y: float


class NetworkTopologyMap:
    """A theme-aware, zoomable topology surface with device details."""

    def __init__(self, segments: list[TopologySegment], hosts_by_address: dict,
                 on_select, on_edit, on_explain):
        self.segments = segments
        self.hosts_by_address = hosts_by_address
        self.on_select = on_select
        self.on_edit = on_edit
        self.on_explain = on_explain
        self.protocol = "ALL"
        self.zoom = 1.0
        self.pan_x = 0.0
        self.pan_y = 0.0
        self.selected_address = ""
        self.width = 1000.0
        self.canvas_width = MIN_CANVAS_WIDTH
        self.canvas_height = MIN_CANVAS_HEIGHT
        # True once the operator has used the zoom controls, after which a
        # window resize must not silently move the map under their hands.
        self._zoom_touched = False
        self._devices = self._layout_devices()
        self._hub = self._find_hub()
        self._map_stack: ft.Stack | None = None
        self._zoom_readout: ft.Text | None = None
        self._map_frame: ft.Container | None = None
        self._details: ft.Container | None = None
        self._table: ft.Column | None = None
        self._table_body: ft.Column | None = None
        self._filter_buttons: dict[str, ft.Button] = {}
        self.control = self._build()

    def _find_hub(self) -> MapDevice | None:
        for role in ("router", "local", "device"):
            for item in self._devices:
                if item.node.role == role:
                    return item
        return None

    @staticmethod
    def satellite_offsets(count: int) -> list[tuple[float, float]]:
        """Offsets from the hub for ``count`` satellites, never overlapping.

        The map used to place every satellite on one of two fixed rings inside
        a fixed 920x500 canvas. From nine devices on, the 124x126 label boxes
        started to sit on top of each other: hostnames were painted over
        neighbouring icons and, past a dozen devices, over each other.

        Two families of arrangement are tried. One fills a wide outer ring and
        works inwards, which is compact while a scan is small; the other starts
        tight and adds wider rings around it, which holds up better once a
        subnet answers with twenty or more devices. Whichever needs the least
        shrinking to sit in a frame of ``FRAME_ASPECT`` wins, and nothing is
        ever returned with an overlap in it.
        """
        if count <= 0:
            return []
        best, best_cost = None, None
        for candidate in NetworkTopologyMap._candidates(count):
            width = max(abs(x) for x, _ in candidate) * 2 + NODE_WIDTH
            height = max(abs(y) for _, y in candidate) * 2 + NODE_HEIGHT
            cost = max(width / FRAME_ASPECT, height)
            if best_cost is None or cost < best_cost:
                best, best_cost = candidate, cost
        if best is not None:
            return best
        # A sweep that answers with a hundred devices needs rings wider than
        # either family explores. Growing every radius together always
        # separates them in the end, and the viewer zooms out to what comes
        # back.
        scale = 18.0
        while scale < 90.0:
            offsets = NetworkTopologyMap._inward_rings(count, scale, 30)
            if len(offsets) == count and not NetworkTopologyMap._collides(offsets):
                return offsets
            scale += 2.0
        return NetworkTopologyMap._inward_rings(count, 90.0, 30)

    @staticmethod
    def _candidates(count: int):
        """Every non-overlapping arrangement worth comparing for ``count``."""
        # Widest ring first: one knob is how far it is pushed out, the other is
        # how many devices it is allowed to carry before a ring starts inside
        # it. Filling each ring to its limit makes one very wide figure; a
        # lower cap spreads the same devices over rounder rings.
        for cap in range(4, 30):
            scale = 1.0
            while scale < 18.0:
                offsets = NetworkTopologyMap._inward_rings(count, scale, cap)
                if len(offsets) == count and not NetworkTopologyMap._collides(offsets):
                    yield offsets
                    break  # a larger radius only costs more at this ring size
                scale += .05 if scale < 4.0 else .2
        scale = 1.0
        while scale < 8.0:
            offsets = NetworkTopologyMap._outward_rings(count, scale)
            if len(offsets) == count and not NetworkTopologyMap._collides(offsets):
                yield offsets
                break
            scale += .05

    @staticmethod
    def _inward_rings(count: int, scale: float,
                      cap: int = 30) -> list[tuple[float, float]]:
        """Fill the outermost ring first, then tighter ones inside it."""
        offsets: list[tuple[float, float]] = []
        remaining, ring = count, 0
        while remaining > 0 and ring <= 9:
            # Strictly decreasing and never zero: a floor made every ring past
            # the third share one radius, so their nodes landed on top of each
            # other on very large scans.
            shrink = 1.0 / (1.0 + .55 * ring)
            ring_x = RING_X * scale * shrink
            ring_y = RING_Y * (1.0 + (scale - 1.0) * RING_Y_GAIN) * shrink
            # A ring can only hold as many boxes as its vertical travel keeps
            # apart; the horizontal radius is never the binding constraint.
            capacity = min(remaining,
                           max(4, min(cap, int(2 * math.pi * ring_y / NODE_HEIGHT))))
            offsets += NetworkTopologyMap._ring(capacity, ring_x, ring_y, ring)
            remaining -= capacity
            ring += 1
        return offsets

    @staticmethod
    def _outward_rings(count: int, scale: float) -> list[tuple[float, float]]:
        """Fill a tight ring around the hub, then wider ones around that."""
        offsets: list[tuple[float, float]] = []
        remaining, ring = count, 0
        while remaining > 0 and ring < 12:
            factor = (1.0 + RING_GROWTH * ring) * scale
            ring_x, ring_y = RING_X * factor, RING_Y * factor
            capacity = min(remaining,
                           max(3, int(2 * math.pi * ring_y / NODE_HEIGHT)))
            offsets += NetworkTopologyMap._ring(capacity, ring_x, ring_y, ring)
            remaining -= capacity
            ring += 1
        return offsets

    @staticmethod
    def _ring(capacity: int, ring_x: float, ring_y: float,
              ring: int) -> list[tuple[float, float]]:
        # Odd rings sit half a step around so they fall between the nodes of
        # the ring next to them.
        shift = .5 if ring % 2 else 0.0
        return [
            (math.cos(angle) * ring_x, math.sin(angle) * ring_y)
            for angle in (
                -math.pi / 2 + 2 * math.pi * (index + shift) / capacity
                for index in range(capacity)
            )
        ]

    @staticmethod
    def _collides(offsets: list[tuple[float, float]]) -> bool:
        points = [(0.0, 0.0)] + offsets
        for i, (ax, ay) in enumerate(points):
            for bx, by in points[i + 1:]:
                if abs(ax - bx) < NODE_WIDTH and abs(ay - by) < NODE_HEIGHT:
                    return True
        return False

    def _layout_devices(self) -> list[MapDevice]:
        flat = [node for segment in self.segments for node in segment.nodes]
        if not flat:
            self.canvas_width, self.canvas_height = MIN_CANVAS_WIDTH, MIN_CANVAS_HEIGHT
            return []
        hub_index = next((i for i, node in enumerate(flat) if node.role == "router"),
                         next((i for i, node in enumerate(flat) if node.role == "local"), 0))
        hub = flat.pop(hub_index)
        offsets = self.satellite_offsets(len(flat))
        reach_x = max([abs(x) for x, _ in offsets] or [0.0])
        reach_y = max([abs(y) for _, y in offsets] or [0.0])
        self.canvas_width = max(MIN_CANVAS_WIDTH, (reach_x + NODE_WIDTH / 2) * 2 + 20)
        self.canvas_height = max(
            MIN_CANVAS_HEIGHT, reach_y * 2 + NODE_TOP + NODE_BOTTOM + 20)
        # The box hangs below its device coordinate, so centring the hub on
        # half the canvas pushed the lowest ring of labels past the bottom
        # edge. The drawable band is what gets centred instead.
        centre_x = self.canvas_width / 2
        centre_y = (self.canvas_height - NODE_TOP - NODE_BOTTOM) / 2 + NODE_TOP
        result = [MapDevice(hub, self.hosts_by_address[hub.address], centre_x, centre_y)]
        for node, (dx, dy) in zip(flat, offsets):
            result.append(MapDevice(node, self.hosts_by_address[node.address],
                                    centre_x + dx, centre_y + dy))
        return result

    @staticmethod
    def _device_icon(item: MapDevice):
        host = item.host
        label = f"{item.node.label} {getattr(host, 'os_name', '')}".lower()
        if item.node.role == "router":
            return ft.Icons.ROUTER_ROUNDED
        if any(word in label for word in ("server", "servidor", "nas", "database")):
            return ft.Icons.DNS_ROUNDED
        if any(word in label for word in ("phone", "mobile", "móvil", "android", "ios")):
            return ft.Icons.SMARTPHONE_ROUNDED
        if any(word in label for word in ("iot", "camera", "tv", "printer")):
            return ft.Icons.WIFI_TETHERING_ROUNDED
        return ft.Icons.COMPUTER_ROUNDED

    @staticmethod
    def _protocol_for(host) -> str:
        services = list(getattr(host, "open_ports", []))
        if not services:
            return "ICMP"
        service = services[0]
        if str(service.protocol).lower() == "udp" or service.name.lower() in {"dns", "domain"}:
            return "UDP"
        return "TCP"

    @staticmethod
    def _protocol_color(protocol: str) -> str:
        return {"TCP": CYAN, "UDP": GREEN, "ICMP": PURPLE}.get(protocol, MUTED)

    def _visible_devices(self):
        if not self._hub:
            return []
        return [item for item in self._devices if item is not self._hub and (
            self.protocol == "ALL" or self._protocol_for(item.host) == self.protocol
        )]

    def _display_geometry(self):
        """Return scale and centring offsets inside the real map viewport."""
        frame_width = self._frame_width()
        scale = self.zoom
        return (
            scale,
            (frame_width - self.canvas_width * scale) / 2,
            (PANEL_HEIGHT - self.canvas_height * scale) / 2,
            frame_width,
        )

    def _connection_controls(self, scale=1.0, offset_x=0.0, offset_y=0.0,
                             frame_width=None):
        frame_width = frame_width or self.canvas_width
        if not self._hub:
            return [ft.Container(left=0, top=0, width=frame_width,
                                 height=PANEL_HEIGHT, bgcolor=BG)]
        controls = [ft.Container(left=0, top=0, width=frame_width,
                                 height=PANEL_HEIGHT, bgcolor=BG)]
        for item in self._visible_devices():
            protocol = self._protocol_for(item.host)
            color = self._protocol_color(protocol)
            selected = item.node.address == self.selected_address
            muted_by_selection = bool(self.selected_address) and not selected
            x1 = offset_x + self._hub.x * scale
            y1 = offset_y + self._hub.y * scale
            x2 = offset_x + item.x * scale
            y2 = offset_y + item.y * scale
            length = math.hypot(x2 - x1, y2 - y1)
            thickness = max(1.0, (4.0 if selected else 2.0) * scale)
            controls.append(ft.Container(
                left=(x1 + x2) / 2 - length / 2,
                top=(y1 + y2) / 2 - thickness / 2,
                width=length, height=thickness,
                bgcolor=tint(color, .34 if muted_by_selection else
                             1.0 if selected else .72),
                border_radius=2,
                rotate=ft.Rotate(
                    angle=math.atan2(y2 - y1, x2 - x1),
                    alignment=ft.Alignment.CENTER,
                ),
            ))
            # A selection ring used to be painted here at r=38. It sat on the
            # canvas, under the node layer, so it cut straight through the
            # "SELECTED" badge and the label plate above it. The node already
            # carries the selection: a thicker border, a wider glow, the badge
            # and a tinted frame.
            # Packet markers make direction and active traffic immediately visible.
            for progress in (.32, .56, .78):
                px = x1 + (x2 - x1) * progress
                py = y1 + (y2 - y1) * progress
                size = max(3.0, (8.0 if selected else 6.0) * scale)
                controls.append(ft.Container(
                    left=px - size / 2, top=py - size / 2,
                    width=size, height=size, border_radius=1,
                    bgcolor=tint(color, .30) if muted_by_selection else color,
                ))
        return controls

    def _node_control(self, item: MapDevice, scale=1.0,
                      offset_x=0.0, offset_y=0.0):
        risk = RED if item.node.risk_level == "high" else AMBER if item.node.risk_level == "medium" else CYAN
        trust = {"authorized": GREEN, "blocked": RED, "new": AMBER}.get(
            item.node.trust_status, BLUE)
        selected = item.node.address == self.selected_address
        node_width = NODE_WIDTH * scale
        node_height = NODE_HEIGHT * scale
        circle = 52.0 * scale
        label_width = 112.0 * scale
        return ft.Container(
            content=ft.Column([
                ft.Stack([
                    ft.Container(
                        content=ft.Icon(self._device_icon(item), color=TEXT,
                                        size=max(9.0, 25.0 * scale)),
                        width=circle, height=circle, border_radius=circle / 2,
                        alignment=ft.Alignment.CENTER,
                        bgcolor=tint(risk, .14),
                        border=ft.Border.all(max(1.0, (3 if selected else 1.4) * scale),
                                             CYAN if selected else risk),
                        shadow=ft.BoxShadow(blur_radius=(26 if selected else 9) * scale,
                                            spread_radius=(3 if selected else 0) * scale,
                                            color=tint(CYAN if selected else risk,
                                                       .52 if selected else .30)),
                    ),
                    ft.Container(width=max(4.0, 10 * scale),
                                 height=max(4.0, 10 * scale),
                                 border_radius=max(2.0, 5 * scale),
                                 bgcolor=trust, right=0, top=1,
                                 border=ft.Border.all(1, SURFACE)),
                ], width=54 * scale, height=54 * scale),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.CHECK_CIRCLE_ROUNDED, color=BG,
                                size=max(5.0, 10 * scale)),
                        ft.Text(tr("SELECTED"), color=BG, size=max(5.0, 7 * scale),
                                weight=ft.FontWeight.W_800),
                    ], spacing=2, alignment=ft.MainAxisAlignment.CENTER),
                    bgcolor=CYAN, border_radius=8,
                    padding=ft.padding.Padding.symmetric(
                        horizontal=max(1.0, 6 * scale), vertical=max(1.0, 2 * scale)),
                    visible=selected,
                ),
                # The connection curves are painted underneath and used to
                # run straight through the address and the hostname, which
                # left both unreadable on every theme. A plate in the canvas
                # colour separates the label from whatever crosses behind it.
                ft.Container(
                    content=ft.Column([
                        ft.Text(item.node.address, color=TEXT, size=max(5.5, 10 * scale),
                                weight=ft.FontWeight.W_700, font_family="monospace",
                                width=label_width, text_align=ft.TextAlign.CENTER,
                                no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                        ft.Text(item.node.label, color=DIM, size=max(5.0, 9 * scale),
                                width=label_width,
                                overflow=ft.TextOverflow.ELLIPSIS,
                                text_align=ft.TextAlign.CENTER, no_wrap=True),
                    ], spacing=0, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=tint(BG, .88), border_radius=6,
                    padding=ft.padding.Padding.symmetric(
                        horizontal=max(1.0, 5 * scale), vertical=max(1.0, 2 * scale)),
                ),
            ], spacing=max(0.0, 2 * scale),
               horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            left=offset_x + item.x * scale - node_width / 2,
            top=offset_y + item.y * scale - NODE_TOP * scale,
            width=node_width, height=node_height,
            alignment=ft.Alignment.CENTER, ink=True, border_radius=10,
            padding=max(1.0, 4 * scale) if selected else 0,
            bgcolor=tint(CYAN, .10) if selected else None,
            border=ft.Border.all(1.5, CYAN) if selected else None,
            shadow=(ft.BoxShadow(blur_radius=22 * scale, color=tint(CYAN, .32))
                    if selected else None),
            # .58 pushed the hostname under a readable contrast on the light
            # themes, where the ink is dark on a bright canvas rather than the
            # other way round.
            opacity=(.72 if self.selected_address and not selected and
                     item is not self._hub else 1.0),
            data=item.node.address,
            tooltip=(f"{item.node.address} · {tr(item.node.role.title())} · "
                     f"{tr('Risk')}: {tr(item.node.risk_level.title())}"),
            on_click=lambda e, address=item.node.address: self.select(address),
        )

    def _build_map_stack(self):
        # Flet Desktop 0.85 can turn Canvas.content into an opaque Material-grey
        # surface after a scaled canvas is constrained by a small window. It
        # reports no Python exception and drops both shapes and overlay nodes.
        # Native positioned controls avoid that platform-view failure while
        # preserving selection, theme changes, protocol filters and zoom.
        # InteractiveViewer and a transformed oversized Stack both become an
        # opaque Material-grey platform surface in Flet Desktop at 900x620.
        # Project every coordinate into a Stack that is exactly the viewport
        # size instead. Nodes remain native clickable controls; zoom rebuilds
        # the geometry around the centre without ever allocating an oversized
        # compositing layer.
        scale, offset_x, offset_y, frame_width = self._display_geometry()
        self._map_stack = ft.Stack([
            *self._connection_controls(scale, offset_x, offset_y, frame_width),
            *[self._node_control(item, scale, offset_x, offset_y)
              for item in self._devices],
        ], width=frame_width, height=PANEL_HEIGHT,
           clip_behavior=ft.ClipBehavior.HARD_EDGE)
        return self._map_stack

    def _apply_zoom(self):
        """Push ``self.zoom`` onto the transform, its box and the readout."""
        if self._zoom_readout is not None:
            self._zoom_readout.value = f"{int(round(self.zoom * 100))}%"
            self._safe_update(self._zoom_readout)

    def _toolbar(self):
        buttons = []
        for protocol, color in (("ALL", CYAN), ("TCP", CYAN), ("UDP", GREEN), ("ICMP", PURPLE)):
            button = ft.Button(
                content=tr("All") if protocol == "ALL" else protocol,
                icon=ft.Icons.HUB_ROUNDED if protocol == "ALL" else None,
                color=color, bgcolor=tint(color, .16 if protocol == "ALL" else .05),
                on_click=lambda e, value=protocol: self.set_protocol(value),
                height=34,
            )
            self._filter_buttons[protocol] = button
            buttons.append(button)
        return ft.Row([
            # These three were literal Spanish, so an operator on the English
            # interface got a Spanish toolbar over an English map.
            ft.Text(tr("View"), color=DIM, size=11, weight=ft.FontWeight.W_600),
            *buttons,
            ft.Container(expand=True),
            self._legend(CYAN, "Host"), self._legend(GREEN, "Online"),
            self._legend(RED, "Risk"),
        ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    @staticmethod
    def _legend(color, label):
        return ft.Row([
            ft.Container(width=9, height=9, border_radius=5, bgcolor=color),
            ft.Text(tr(label), color=DIM, size=10),
        ], spacing=4)

    def _fit_zoom(self) -> float:
        """The zoom at which the whole figure fits the frame, within reason.

        Height is what actually runs out: the frame is fixed at ``PANEL_HEIGHT``
        while the figure grows with the device count. Fitting on width alone
        left the lowest ring of nodes clipped off the bottom of the surface.
        """
        frame_width = max(320.0, self._frame_width())
        return max(MIN_FIT_ZOOM, min(1.0,
                                     frame_width / self.canvas_width,
                                     (PANEL_HEIGHT - 2) / self.canvas_height))

    def _frame_width(self) -> float:
        compact = self.width < 780
        return self.width if compact else max(430.0, self.width - 310.0)

    def _zoom(self, delta):
        self._zoom_touched = True
        self.zoom = max(MIN_FIT_ZOOM, min(1.65, self.zoom + delta))
        self._refresh_content()

    def _map_panel(self):
        viewer = self._build_map_stack()
        compact = self.width < 780
        panel_width = self.width if compact else max(430.0, self.width - 310.0)
        # Built here rather than inline so the zoom controls can rewrite it;
        # the readout used to be frozen at whatever it read when the map was
        # first drawn.
        self._zoom_readout = ft.Text(f"{int(round(self.zoom * 100))}%", color=DIM,
                                     size=9, text_align=ft.TextAlign.CENTER)
        zoom_bar = ft.Container(
            content=ft.Column([
                ft.IconButton(ft.Icons.ADD_ROUNDED, icon_color=TEXT, icon_size=18,
                              tooltip=tr("Zoom in"), on_click=lambda e: self._zoom(.15)),
                self._zoom_readout,
                ft.IconButton(ft.Icons.REMOVE_ROUNDED, icon_color=TEXT, icon_size=18,
                              tooltip=tr("Zoom out"), on_click=lambda e: self._zoom(-.15)),
                ft.IconButton(ft.Icons.CENTER_FOCUS_STRONG_ROUNDED, icon_color=CYAN,
                              icon_size=17, tooltip=tr("Reset zoom"),
                              on_click=lambda e: self._reset_zoom()),
            ], spacing=0, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=tint(SURFACE, .96), border=ft.Border.all(1, BORDER),
            border_radius=8, right=10, bottom=10, padding=2,
        )
        self._map_frame = ft.Container(
            # Expanded inside the wrapping compact row produces Flutter's grey
            # error surface even though the surrounding Container has an
            # explicit size. Give the overlay stack the same concrete bounds.
            content=ft.Stack([viewer, zoom_bar], width=panel_width,
                             height=PANEL_HEIGHT),
            bgcolor=BG, border=ft.Border.all(1, BORDER), border_radius=10,
            width=panel_width, height=PANEL_HEIGHT, expand=False,
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
        )
        return self._map_frame

    def _reset_zoom(self):
        self._zoom_touched = False
        self.zoom = self._fit_zoom()
        self.pan_x = self.pan_y = 0.0
        self._refresh_content()

    def _detail_panel(self, item: MapDevice | None):
        panel_width = self.width if self.width < 780 else 300
        if item is None:
            return ft.Container(
                content=ft.Column([
                    ft.Icon(ft.Icons.TOUCH_APP_ROUNDED, color=CYAN, size=28),
                    ft.Text(tr("Select a node"), color=TEXT, size=14,
                            weight=ft.FontWeight.W_600, text_align=ft.TextAlign.CENTER),
                    ft.Text(tr("Choose any device in the map to inspect its identity and services."),
                            color=DIM, size=11, text_align=ft.TextAlign.CENTER),
                ], spacing=9, horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                   alignment=ft.MainAxisAlignment.CENTER),
                bgcolor=SURFACE, border=ft.Border.all(1, BORDER), border_radius=10,
                width=panel_width, height=PANEL_HEIGHT, padding=14,
            )
        host, node = item.host, item.node
        risk = RED if node.risk_level == "high" else AMBER if node.risk_level == "medium" else CYAN
        services = list(getattr(host, "open_ports", []))
        rows = [
            self._kv("IP", node.address),
            self._kv("Hostname", getattr(host, "hostname", "") or "—"),
            self._kv(tr("Type"), tr(node.role.title())),
            self._kv(tr("Operating system"), getattr(host, "os_name", "") or "—"),
            self._kv("MAC", getattr(host, "mac", "") or "—"),
            # "Active" already means a capture session in the catalog, and
            # its Spanish form is feminine there.
            self._kv(tr("Status"), tr("Online"), GREEN),
        ]
        ports = [ft.Container(
            content=ft.Row([
                ft.Container(width=8, height=8, border_radius=4, bgcolor=GREEN),
                ft.Text(f"{service.port}/{service.protocol}", color=TEXT, size=10,
                        width=82, font_family="monospace"),
                ft.Text(service.name or "unknown", color=DIM, size=10, expand=True,
                        overflow=ft.TextOverflow.ELLIPSIS),
            ], spacing=6), padding=ft.padding.Padding.symmetric(vertical=3),
            ink=True, border_radius=5,
            on_click=lambda e, address=node.address, service=service:
                self.on_explain(address, service),
        ) for service in services[:6]]
        if not ports:
            ports = [ft.Text(tr("No open ports in this scan profile"), color=DIM,
                             size=10)]
        return ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Container(content=ft.Icon(self._device_icon(item), color=TEXT, size=23),
                                 width=44, height=44, border_radius=22,
                                 bgcolor=tint(risk, .13), border=ft.Border.all(1.5, risk),
                                 alignment=ft.Alignment.CENTER),
                    ft.Column([
                        ft.Text(node.address, color=TEXT, size=13,
                                weight=ft.FontWeight.W_700, font_family="monospace",
                                no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                        ft.Text(node.label, color=DIM, size=10, no_wrap=True,
                                overflow=ft.TextOverflow.ELLIPSIS),
                    ], spacing=2, expand=True),
                    ft.IconButton(ft.Icons.EDIT_NOTE_ROUNDED, icon_color=CYAN, icon_size=17,
                                  tooltip=tr("Edit device inventory"),
                                  on_click=lambda e: self.on_edit(node.address)),
                ], spacing=7),
                ft.Divider(color=BORDER, height=10),
                ft.Text(tr("INFORMATION"), color=CYAN, size=10,
                        weight=ft.FontWeight.W_700),
                *rows,
                ft.Divider(color=BORDER, height=12),
                ft.Text(tr("OPEN PORTS"), color=TEXT, size=10,
                        weight=ft.FontWeight.W_700),
                *ports,
            ], spacing=6, scroll=ft.ScrollMode.AUTO),
            bgcolor=SURFACE, border=ft.Border.all(1, BORDER), border_radius=10,
            width=panel_width, height=PANEL_HEIGHT, padding=12,
        )

    @staticmethod
    def _kv(label, value, color=TEXT):
        return ft.Row([
            ft.Text(label, color=MUTED, size=10, width=96),
            # Hostnames, MAC addresses and OS strings are routinely wider than
            # the panel, so the full value stays reachable as a tooltip.
            ft.Text(str(value), color=color, size=10, expand=True, no_wrap=True,
                    overflow=ft.TextOverflow.ELLIPSIS, tooltip=str(value)),
        ], spacing=5, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    def _connections_table(self):
        header = ft.Container(
            content=ft.Row([
                ft.Text(tr("Origin"), color=DIM, size=10, width=COL_ADDRESS),
                ft.Text(tr("Destination"), color=DIM, size=10, width=COL_ADDRESS),
                ft.Text(tr("Protocol"), color=DIM, size=10, width=COL_PROTOCOL),
                ft.Text(tr("Port"), color=DIM, size=10, width=COL_PORT),
                ft.Text(tr("Status"), color=DIM, size=10, width=COL_STATUS),
                ft.Text(tr("Service"), color=DIM, size=10, expand=True),
            ], spacing=8), bgcolor=tint(CYAN, .045), padding=8,
        )
        rows = []
        if self._hub:
            for item in self._visible_devices():
                services = list(getattr(item.host, "open_ports", [])) or [None]
                for service in services[:2]:
                    protocol = self._protocol_for(item.host)
                    port = str(service.port) if service else "—"
                    service_name = service.name if service else tr("Host discovery")
                    rows.append(ft.Container(
                        content=ft.Row([
                            ft.Text(self._hub.node.address, color=DIM, size=10,
                                    width=COL_ADDRESS, font_family="monospace"),
                            ft.Text(item.node.address, color=TEXT, size=10,
                                    width=COL_ADDRESS, font_family="monospace"),
                            ft.Text(protocol, color=self._protocol_color(protocol),
                                    size=10, width=COL_PROTOCOL,
                                    weight=ft.FontWeight.W_700),
                            ft.Text(port, color=TEXT, size=10, width=COL_PORT),
                            ft.Row([ft.Container(width=8, height=8, border_radius=4,
                                                 bgcolor=GREEN),
                                    ft.Text(tr("Open"), color=GREEN, size=10)],
                                   spacing=4, width=COL_STATUS),
                            ft.Text(service_name, color=DIM, size=10, expand=True,
                                    no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                        ], spacing=8), padding=8,
                        bgcolor=tint(CYAN, .028) if len(rows) % 2 == 0 else SURFACE,
                        on_click=lambda e, address=item.node.address: self.select(address),
                    ))
        # Keep the heading visible and confine long scan results to their own
        # wheel-scroll area instead of making the complete Map tab taller.
        self._table = ft.Column(
            rows or [ft.Container(
                content=ft.Text(tr("No connections match this filter."),
                                color=DIM, size=11),
                padding=10,
            )],
            spacing=0,
            height=184,
            scroll=ft.ScrollMode.ALWAYS,
        )
        self._table_body = ft.Column(
            [header, self._table], spacing=0,
            width=max(TABLE_MIN_WIDTH, self.width - 22.0),
        )
        return ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Text(tr("CONNECTIONS DISCOVERED"), color=TEXT, size=11,
                            weight=ft.FontWeight.W_700),
                    ft.Container(expand=True),
                    ft.Text(datetime.now().strftime("%H:%M:%S"), color=MUTED, size=10,
                            font_family="monospace"),
                ], spacing=6),
                ft.Row([self._table_body], scroll=ft.ScrollMode.AUTO),
            ], spacing=0),
            bgcolor=SURFACE, border=ft.Border.all(1, BORDER), border_radius=10,
            padding=10, height=252,
        )

    def _build(self):
        self._details = self._detail_panel(None)
        return ft.Column([
            self._toolbar(),
            ft.Row([self._map_panel(), self._details], spacing=10,
                   vertical_alignment=ft.CrossAxisAlignment.START),
            self._connections_table(),
        ], spacing=10)

    def set_protocol(self, protocol: str):
        self.protocol = protocol
        for name, button in self._filter_buttons.items():
            color = self._protocol_color(name) if name != "ALL" else CYAN
            button.bgcolor = tint(color, .16 if name == protocol else .05)
        self._refresh_content()

    def select(self, address: str):
        self.selected_address = address
        self.on_select(address)
        self._refresh_content()

    def _refresh_content(self):
        if not self.control:
            return
        item = next((device for device in self._devices
                     if device.node.address == self.selected_address), None)
        row = self.control.controls[1]
        self._map_frame = self._map_panel()
        self._details = self._detail_panel(item)
        row.controls = [self._map_frame, self._details]
        self.control.controls[2] = self._connections_table()
        # Selection and filtering rebuild these panels after the last window
        # resize. Reapply the current compact geometry before Flet serializes
        # the wrapping row, otherwise Expanded produces a grey error surface.
        self.resize(self.width)
        self._safe_update(self.control)

    def resize(self, width: float):
        previous_width = self.width
        previous_zoom = self.zoom
        self.width = width
        compact = width < 780
        if not self._zoom_touched:
            self.zoom = self._fit_zoom()
            self._apply_zoom()
        layout = self.control.controls[1]
        # Flet Desktop 0.85 renders a large Stack as an opaque grey error
        # surface when it is a child of Row(wrap=True). A real Column is the
        # compact layout; the wide layout remains a Row.
        if compact and not isinstance(layout, ft.Column):
            layout = ft.Column([self._map_frame, self._details], spacing=10)
            self.control.controls[1] = layout
        elif not compact and not isinstance(layout, ft.Row):
            layout = ft.Row([self._map_frame, self._details], spacing=10,
                            vertical_alignment=ft.CrossAxisAlignment.START)
            self.control.controls[1] = layout
        self._map_frame.width = width if compact else max(430.0, width - 310.0)
        self._map_frame.expand = False
        self._map_frame.content.width = self._map_frame.width
        self._map_frame.content.height = PANEL_HEIGHT
        self._details.width = width if compact else 300
        if (abs(previous_width - self.width) > .5 or
                abs(previous_zoom - self.zoom) > .001):
            self._map_frame.content.controls[0] = self._build_map_stack()
            self._safe_update(self._map_frame)
        # Below its minimum the connection table clipped its own last columns
        # instead of offering them; from there on it scrolls sideways.
        if self._table_body is not None:
            self._table_body.width = max(TABLE_MIN_WIDTH, width - 22.0)

    @staticmethod
    def _safe_update(control):
        try:
            control.update()
        except (AssertionError, RuntimeError):
            pass
