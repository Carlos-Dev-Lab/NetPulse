import unittest

from netpulse.presentation.i18n import set_language, tr


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

    def test_language_switch_is_reversible(self):
        self.assertEqual(tr("Settings", "es"), "Ajustes")
        self.assertEqual(tr("Ajustes", "en"), "Settings")
        self.assertEqual(
            tr("Completado en 2.4s · 3 dispositivos", "en"),
            "Completed in 2.4s · 3 devices",
        )


if __name__ == "__main__":
    unittest.main()
