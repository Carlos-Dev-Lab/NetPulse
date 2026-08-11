import unittest
from unittest.mock import patch

from netpulse.infrastructure.sniffer import Sniffer


class _FakeAsyncSniffer:
    last_kwargs = None

    def __init__(self, **kwargs):
        type(self).last_kwargs = kwargs
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


class SnifferTests(unittest.TestCase):
    def test_all_uses_active_interfaces_instead_of_scapy_default(self):
        sniffer = Sniffer()
        with (
            patch("scapy.all.AsyncSniffer", _FakeAsyncSniffer),
            patch.object(
                Sniffer,
                "_active_capture_interfaces",
                return_value=["Wi-Fi 2", "vEthernet (Default Switch)"],
            ),
            patch("netpulse.infrastructure.sniffer._port_pid_mapper.start"),
            patch("netpulse.infrastructure.sniffer._port_pid_mapper.stop"),
        ):
            try:
                sniffer.start()
                self.assertEqual(
                    _FakeAsyncSniffer.last_kwargs["iface"],
                    ["Wi-Fi 2", "vEthernet (Default Switch)"],
                )
            finally:
                sniffer.stop()

    def test_named_interface_remains_explicit(self):
        sniffer = Sniffer()
        with (
            patch("scapy.all.AsyncSniffer", _FakeAsyncSniffer),
            patch.object(Sniffer, "_resolve_iface", return_value="Wi-Fi 2"),
            patch("netpulse.infrastructure.sniffer._port_pid_mapper.start"),
            patch("netpulse.infrastructure.sniffer._port_pid_mapper.stop"),
        ):
            try:
                sniffer.start("Wi-Fi 2")
                self.assertEqual(_FakeAsyncSniffer.last_kwargs["iface"], "Wi-Fi 2")
            finally:
                sniffer.stop()


if __name__ == "__main__":
    unittest.main()
