"""Desktop reflow regressions.

Every view recomputes its own widths from the central viewport. Two classes of
defect used to slip through and were only visible once a window was resized by
hand: fractional sizes, which made the 1 px card borders land between device
pixels, and rows whose children were computed one pixel wider than the row, so
a pair of fields wrapped onto separate lines. Both are cheap to assert here.
"""

import unittest

import flet as ft

from netpulse.domain.state import AppState
from netpulse.presentation.theme import split
from netpulse.presentation.views import (
    ChartsView, DashboardView, HistoryView, LocalPortsView, PacketsView,
    ProcessView, SettingsView,
)

# Navigation rail plus its divider: what ``main_content`` reports back.
RAIL = 105
HEADER_AND_STATUS = 90

# Flet Desktop reports logical pixels, and Windows DPI scaling makes most of
# them fractional: a maximized 2560x1600 screen at 150 % hands the centre pane
# 1601.666… px, not a round number. The fractional entries are the ones that
# used to break the reflow, so they belong in the table.
SIZES = [(1920, 1080), (1706.6666666666667, 996.0), (1600, 900), (1440, 900),
         (1366, 768), (1280.5, 720.25), (1280, 720), (1080, 660), (900, 620)]


def walk(control):
    yield control
    for name in ("content", "controls"):
        value = getattr(control, name, None)
        children = value if isinstance(value, list) else [value]
        for child in children:
            if isinstance(child, ft.Control):
                yield from walk(child)


def rows_with_a_fixed_width(control):
    """Yield every ``Row`` the reflow gave an explicit width."""
    for node in walk(control):
        if isinstance(node, ft.Row) and node.width is not None:
            yield node


def build_views():
    state = AppState()
    return {
        "dashboard": DashboardView(state),
        "ports": LocalPortsView([None]),
        "packets": PacketsView(state, [None]),
        "charts": ChartsView(state, [None], None),
        "history": HistoryView(None),
        "apps": ProcessView(state, [None]),
        "settings": SettingsView(state),
    }


class GeometryTests(unittest.TestCase):
    def test_every_computed_size_is_a_whole_pixel(self):
        for window_width, window_height in SIZES:
            width = window_width - RAIL
            height = window_height - HEADER_AND_STATUS
            for name, view in build_views().items():
                root = view.build()
                view.set_viewport(width, height)
                for control in walk(root):
                    for attribute in ("width", "height"):
                        value = getattr(control, attribute, None)
                        if value is None:
                            continue
                        self.assertEqual(
                            value, round(value),
                            f"{name}.{type(control).__name__}.{attribute} "
                            f"is {value!r} at {window_width}x{window_height}",
                        )

    def test_no_row_is_wider_than_the_space_it_was_given(self):
        """Children must fit their row at every viewport, fractions included.

        ``snap`` rounds to the nearest pixel. Applied to the viewport itself
        that rounds *up*: a 1601.666 px pane became a 1574 px row inside a
        1573.666 px parent. Every responsive row here is a ``Row(wrap=True)``,
        which is a Flutter ``Wrap``, so a third of a pixel of overflow pushed a
        whole card onto the next line and the maximized dashboard lost a
        column. Nothing may exceed the width it was handed.
        """
        for window_width, window_height in SIZES:
            width = window_width - RAIL
            height = window_height - HEADER_AND_STATUS
            for name, view in build_views().items():
                root = view.build()
                view.set_viewport(width, height)
                self.assertLessEqual(width - 28.0, width, name)
                for row in rows_with_a_fixed_width(root):
                    self.assertLessEqual(
                        row.width, width - 28.0,
                        f"{name} row is wider than the pane "
                        f"at {window_width}x{window_height}",
                    )
                    sized = [c for c in row.controls
                             if getattr(c, "width", None) is not None]
                    if len(sized) != len(row.controls):
                        continue  # an expanding child absorbs the remainder
                    total = (sum(c.width for c in sized)
                             + row.spacing * (len(sized) - 1))
                    overflow = total - row.width
                    if overflow <= 0:
                        continue
                    # Some rows stack on purpose in the narrow layouts, and a
                    # deliberate stack overflows by at least one whole column.
                    # An accidental one overflows by a pixel or a fraction of
                    # one, which still costs a full card in a ``Wrap``.
                    self.assertGreaterEqual(
                        overflow, min(c.width for c in sized),
                        f"{name} row children overflow by {overflow} px at "
                        f"{window_width}x{window_height}: too little to be a "
                        f"deliberate stack, enough to drop a column",
                    )

    def test_split_fills_the_row_exactly(self):
        for total in (1233, 1787, 975, 767):
            for count in (1, 2, 3, 4, 5):
                widths = split(float(total), count, 12)
                self.assertEqual(len(widths), count)
                self.assertEqual(sum(widths) + 12 * (count - 1), total)
                self.assertLessEqual(max(widths) - min(widths), 1)

    def test_history_detail_cards_never_expand_inside_wrapping_row(self):
        view = HistoryView(None)
        root = view.build()
        view.set_viewport(760, 560)

        self.assertTrue(view._detail_row.wrap)
        self.assertTrue(all(not control.expand for control in view._detail_row.controls))
        self.assertTrue(all(control.bgcolor is not None for control in view._detail_row.controls))

    def test_alert_thresholds_stay_on_one_line(self):
        view = SettingsView(AppState())
        view.build()
        for window_width, window_height in SIZES:
            view.set_viewport(window_width - RAIL, window_height - HEADER_AND_STATUS)
            row = view._alert_fields_row
            if row.width == view._bw_field.width:
                continue  # stacked on purpose in the narrow layouts
            self.assertLessEqual(
                view._bw_field.width + view._pps_field.width + row.spacing,
                row.width,
                f"threshold fields overflow their row at {window_width}px",
            )

    def test_capture_and_storage_fields_share_one_measure(self):
        view = SettingsView(AppState())
        view.build()
        view.set_viewport(1920 - RAIL, 1080 - HEADER_AND_STATUS)
        self.assertEqual(view._language_dropdown.width, view._interface_dropdown.width)
        self.assertEqual(view._retention_dropdown.width, view._interface_dropdown.width)

    def test_settings_columns_end_flush_with_the_intro_card(self):
        view = SettingsView(AppState())
        view.build()
        view.set_viewport(1920 - RAIL, 1080 - HEADER_AND_STATUS)
        left, right = view._settings_columns
        self.assertEqual(left.width + right.width + view._settings_body.spacing,
                         view._cards[0].width)

    def test_dashboard_chart_pair_fills_the_row(self):
        view = DashboardView(AppState())
        view.build()
        view.set_viewport(1920 - RAIL, 1080 - HEADER_AND_STATUS)
        trend, mix = view._chart_cards
        self.assertEqual(trend.width + mix.width + 12, view._responsive_rows[2].width)
        self.assertGreater(trend.width, mix.width)


if __name__ == "__main__":
    unittest.main()
