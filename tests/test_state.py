from datetime import datetime
import unittest

from netpulse.domain.models import Packet
from netpulse.domain.state import AppState


class RecordingEnricher:
    def __init__(self):
        self.ips = []

    def enqueue(self, ip):
        self.ips.append(ip)


class AppStateTests(unittest.TestCase):
    def test_process_aggregates_traffic_and_ip_deltas(self):
        enricher = RecordingEnricher()
        state = AppState(ip_enricher=enricher)
        packets = [
            Packet(datetime.now(), "IN", "HTTPS", "1.1.1.1", "10.0.0.2", 443, 5000, 1000, "1.1.1.1"),
            Packet(datetime.now(), "OUT", "DNS", "10.0.0.2", "8.8.8.8", 5001, 53, 200, "8.8.8.8", 42, "browser.exe"),
        ]

        result = state.process(packets, 1.0)

        self.assertEqual(result["bytes_in"], 1000)
        self.assertEqual(result["bytes_out"], 200)
        self.assertEqual(state.total_pkts, 2)
        self.assertEqual(state.last_ip_deltas["1.1.1.1"], {"b": 1000, "p": 1})
        self.assertEqual(state.proc_traffic["browser.exe"], {"b": 200, "p": 1})
        app = state.app_traffic["42:browser.exe"]
        self.assertEqual(app["bytes_out"], 200)
        self.assertEqual(app["bytes_in"], 0)
        self.assertAlmostEqual(app["rate_out"], 200 / 1024)
        self.assertEqual(app["protocols"], {"DNS": 1})
        self.assertEqual(app["destinations"]["8.8.8.8"]["ports"], {53})
        self.assertEqual(enricher.ips, ["1.1.1.1", "8.8.8.8"])

    def test_empty_interval_resets_current_rates(self):
        state = AppState()
        state.cur_pps = 12

        self.assertEqual(state.process([], 1.0), {})
        self.assertEqual(state.cur_pps, 0)
        self.assertEqual(state.last_ip_deltas, {})

    def test_application_records_rate_history_and_spike_direction(self):
        state = AppState()
        now = datetime.now()
        state.process([
            Packet(now, "IN", "HTTPS", "1.1.1.1", "10.0.0.2",
                   443, 5000, 102_400, "1.1.1.1", 7, "game.exe"),
        ], 1.0)
        app = state.app_traffic["7:game.exe"]

        self.assertEqual(app["peak_rate"], 100.0)
        self.assertEqual(len(app["spike_events"]), 1)
        self.assertEqual(app["spike_events"][0]["rate_in"], 100.0)

        state.process([], 1.0)
        self.assertEqual(app["rate_in"], 0.0)
        self.assertEqual(len(app["rate_history"]), 2)


if __name__ == "__main__":
    unittest.main()
