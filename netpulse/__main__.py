"""Run the NetPulse Windows desktop application."""

import flet as ft

from netpulse.presentation.app import main


ft.run(main, view=ft.AppView.FLET_APP)
