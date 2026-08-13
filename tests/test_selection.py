import unittest

import flet as ft

from netpulse.presentation.theme import selectable_content


class SelectionTests(unittest.TestCase):
    def test_view_content_is_wrapped_in_native_selection_area(self):
        dynamic_results = ft.Column([ft.Text("172.26.4.18 · puerto 445")])

        selection = selectable_content(dynamic_results)

        self.assertIsInstance(selection, ft.SelectionArea)
        self.assertIs(selection.content, dynamic_results)
        self.assertTrue(selection.expand)
        self.assertFalse(dynamic_results.controls[0].selectable)

        # New results remain inside the same selection scope.
        new_result = ft.Text("Actualizado · 115 puertos")
        dynamic_results.controls.append(new_result)
        self.assertIs(selection.content.controls[-1], new_result)

    def test_modal_translation_enables_selection_without_extra_actions(self):
        from netpulse.presentation.i18n import translate_tree

        title = ft.Text("Detalle del dispositivo")
        body = ft.Column([ft.Text("IP: 172.26.4.18"), ft.Text("Puerto: 445/TCP")])
        close = ft.TextButton("Cerrar")
        dialog = ft.AlertDialog(title=title, content=body, actions=[close])

        translate_tree(dialog, "es")

        self.assertIsInstance(dialog.content, ft.SelectionArea)
        self.assertIs(dialog.content.content, body)
        self.assertFalse(body.controls[0].selectable)
        self.assertEqual(dialog.actions, [close])


if __name__ == "__main__":
    unittest.main()
