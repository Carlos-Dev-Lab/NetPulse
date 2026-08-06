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
        self.assertEqual(
            tr("netpulse.db  ·  same folder as main.py"),
            "netpulse.db  ·  carpeta de datos de la aplicación",
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
        self.assertEqual(dialog.content.title.value, "DETALLE DE SALUD DE LA RED")
        self.assertEqual(dialog.content.subtitle.value,
                         "Ejecuta un análisis para calcular la salud de la red.")
        self.assertEqual(dialog.content.controls[0].tooltip, "Eliminar programación")
        self.assertEqual(dialog.actions[0].content, "Cancelar")
        self.assertEqual(dialog.actions[1].content, "Guardar perfil")


if __name__ == "__main__":
    unittest.main()
