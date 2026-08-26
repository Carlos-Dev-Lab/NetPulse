"""Run the NetPulse Windows desktop application."""

import flet as ft

from netpulse.logging_setup import configure_logging
from netpulse.presentation.app import main


def run() -> None:
    """Entry point for ``python -m netpulse`` and the ``netpulse`` script."""
    configure_logging()
    ft.run(main, view=ft.AppView.FLET_APP)


if __name__ == "__main__":
    run()
