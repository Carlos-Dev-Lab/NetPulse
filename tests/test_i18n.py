import unittest
import flet as ft

from netpulse.presentation.i18n import set_language, tr, translate_tree


class I18nTests(unittest.TestCase):
    def tearDown(self):
        set_language("en")

    def test_static_and_dynamic_spanish_translations(self):
        set_language("es")
        self.assertEqual(tr("Packet explorer"), "Explorador de paquetes")
        self.assertEqual(tr("WAITING FOR TRAFFIC"), "ESPERANDO TRÁFICO")
        self.assertEqual(
            tr("Completed in 2.4s · 3 devices"),
            "Completado en 2.4s · 3 dispositivos",
        )
        self.assertEqual(tr("Quick ports"), "Puertos rápidos")
        self.assertEqual(tr("AUTHORIZED"), "AUTORIZADO")
        self.assertEqual(tr("Why: Telnet transmite datos"),
                         "Motivo: Telnet transmite datos")
        self.assertEqual(
            tr("Every 60 min · quick · next 2026-08-05 12:00"),
            "Cada 60 min · quick · próxima 2026-08-05 12:00",
        )
        self.assertEqual(
            tr("86/100 · GOOD · 14 points deducted"),
            "86/100 · BUENA · 14 puntos descontados",
        )
        self.assertEqual(tr("DATABASE  ( SQLite )"), "BASE DE DATOS  ( SQLite )")
        self.assertEqual(
            tr("Capture history retention"), "Retención del historial de capturas",
        )
        self.assertEqual(
            tr("Keeping every capture session."),
            "Se conservan todas las sesiones de captura.",
        )
        self.assertEqual(
            tr("Run as Administrator  →  scripts/start.bat"),
            "Ejecutar como administrador  →  scripts/start.bat",
        )

    def test_language_switch_is_reversible(self):
        self.assertEqual(tr("Settings", "es"), "Ajustes")
        self.assertEqual(tr("Ajustes", "en"), "Settings")
        self.assertEqual(
            tr("Completado en 2.4s · 3 dispositivos", "en"),
            "Completed in 2.4s · 3 devices",
        )
        self.assertEqual(tr("AUTORIZADO", "en"), "AUTHORIZED")
        self.assertEqual(tr("Motivo: Telnet transmite datos", "en"),
                         "Why: Telnet transmite datos")
        self.assertEqual(
            tr("Cada 60 min · quick · próxima 2026-08-05 12:00", "en"),
            "Every 60 min · quick · next 2026-08-05 12:00",
        )

    def test_translation_reaches_accordions_dialog_actions_and_tooltips(self):
        dialog = ft.AlertDialog(
            title=ft.Text("Save scan profile"),
            content=ft.ExpansionTile(
                title=ft.Text("NETWORK HEALTH DETAILS"),
                subtitle=ft.Text("Run a scan to calculate network health."),
                controls=[ft.IconButton(icon=ft.Icons.DELETE, tooltip="Delete schedule")],
            ),
            actions=[ft.TextButton("Cancel"), ft.Button(content="Save profile")],
        )

        translate_tree(dialog, "es")

        self.assertEqual(dialog.title.value, "Guardar perfil de análisis")
        self.assertIsInstance(dialog.content, ft.SelectionArea)
        content = dialog.content.content
        self.assertEqual(content.title.value, "DETALLE DE SALUD DE LA RED")
        self.assertEqual(content.subtitle.value,
                         "Ejecuta un análisis para calcular la salud de la red.")
        self.assertEqual(content.controls[0].tooltip, "Eliminar programación")
        self.assertEqual(dialog.actions[0].content, "Cancelar")
        self.assertEqual(dialog.actions[1].content, "Guardar perfil")

    def test_translation_handles_frozen_tab_controls(self):
        tabs = ft.TabBar(tabs=[
            ft.Tab(label="Scan"),
            ft.Tab(label=ft.Text("Assets")),
        ])

        translate_tree(tabs, "es")

        # Before mounting, Flet still permits a raw string update. NetPulse
        # uses a Text label so it remains translatable after Tab is frozen.
        self.assertEqual(tabs.tabs[0].label, "Escaneo")
        self.assertEqual(tabs.tabs[1].label.value, "Activos")

    def test_selected_option_keys_survive_translation(self):
        """A Dropdown value is an option key, not prose.

        Translating it detached the control from its own options: the capture
        interface selector and the packet filters rendered as empty fields
        because "All" had become "Todos", which matches no option.
        """
        dropdown = ft.Dropdown(
            label="Interface", value="All",
            options=[ft.DropdownOption("All", "All interfaces")],
        )

        translate_tree(dropdown, "es")

        self.assertEqual(dropdown.value, "All")
        self.assertEqual(dropdown.label, "Interfaz")
        self.assertEqual(dropdown.options[0].key, "All")
        self.assertEqual(dropdown.options[0].text, "Todas las interfaces")

    def test_typed_text_is_never_translated(self):
        field = ft.TextField(label="Target networks", value="All")

        translate_tree(field, "es")

        self.assertEqual(field.value, "All")
        self.assertEqual(field.label, "Redes objetivo")

    def test_data_table_headings_are_translated(self):
        table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("Time")),
                ft.DataColumn(ft.Text("Src IP")),
            ],
            rows=[ft.DataRow(cells=[
                ft.DataCell(ft.Text("Unavailable")),
                ft.DataCell(ft.Text("10.0.0.1")),
            ])],
        )

        translate_tree(table, "es")

        self.assertEqual(table.columns[0].label.value, "Hora")
        self.assertEqual(table.columns[1].label.value, "IP origen")
        self.assertEqual(table.rows[0].cells[0].content.value, "No disponible")


if __name__ == "__main__":
    unittest.main()
