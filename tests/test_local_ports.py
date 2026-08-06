import socket
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import psutil

from netpulse.services.local_ports import list_local_listeners


class LocalPortTests(unittest.TestCase):
    @patch("netpulse.services.local_ports.psutil.Process")
    @patch("netpulse.services.local_ports.psutil.net_connections")
    def test_lists_only_listeners_with_process_exposure_and_risk(self, connections, process):
        connections.return_value = [
            SimpleNamespace(
                type=socket.SOCK_STREAM, status=psutil.CONN_LISTEN,
                laddr=SimpleNamespace(ip="0.0.0.0", port=445),
                family=socket.AF_INET, pid=120,
            ),
            SimpleNamespace(
                type=socket.SOCK_STREAM, status=psutil.CONN_ESTABLISHED,
                laddr=SimpleNamespace(ip="127.0.0.1", port=50000),
                family=socket.AF_INET, pid=121,
            ),
            SimpleNamespace(
                type=socket.SOCK_DGRAM, status=psutil.CONN_NONE,
                laddr=SimpleNamespace(ip="127.0.0.1", port=5353),
                family=socket.AF_INET, pid=122,
            ),
        ]
        process.return_value.name.side_effect = lambda: "servicio.exe"

        result = list_local_listeners()

        self.assertEqual(len(result), 2)
        smb = next(item for item in result if item.port == 445)
        self.assertEqual(smb.process, "servicio.exe")
        self.assertEqual(smb.exposure, "all_interfaces")
        self.assertEqual(smb.risk_level, "high")
        local = next(item for item in result if item.port == 5353)
        self.assertEqual(local.protocol, "UDP")
        self.assertEqual(local.exposure, "local")

    @patch("netpulse.services.local_ports.psutil.net_connections",
           side_effect=psutil.AccessDenied())
    def test_permission_error_returns_safe_empty_result(self, _connections):
        self.assertEqual(list_local_listeners(), [])


if __name__ == "__main__":
    unittest.main()
