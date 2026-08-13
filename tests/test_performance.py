import unittest
from types import SimpleNamespace

from netpulse.services.performance import (
    QualityResult, adapter_capacity, checks_needed_for_trend, classify_quality,
    default_gateway, measure_quality, quality_trend,
    parse_ping_latencies,
)


class _Connection:
    def close(self):
        pass


class _RouteSocket:
    def connect(self, endpoint):
        self.endpoint = endpoint

    def getsockname(self):
        return ("192.168.1.25", 50000)

    def close(self):
        pass


class PerformanceTests(unittest.TestCase):
    def test_parses_english_and_spanish_ping_without_summary_numbers(self):
        output = "Reply from 1.1.1.1: time=12ms\nRespuesta: tiempo<1ms\nLost = 0"
        self.assertEqual(parse_ping_latencies(output), [12.0, 1.0])

    def test_gateway_uses_lowest_metric_valid_default_route(self):
        output = "0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.20 25\n0.0.0.0 0.0.0.0 10.0.0.1 10.0.0.2 5"
        runner = lambda *a, **k: SimpleNamespace(stdout=output)
        self.assertEqual(default_gateway(runner), "10.0.0.1")

    def test_measurement_requires_three_replies_before_classifying(self):
        runner = lambda *a, **k: SimpleNamespace(stdout="Reply: time=10ms\nReply: time=11ms")
        result = measure_quality("192.168.1.1", command_runner=runner,
                                 resolver=lambda *a, **k: [],
                                 connector=lambda *a, **k: _Connection())
        self.assertEqual(classify_quality(result)[0], "INSUFFICIENT DATA")
        self.assertIsNone(result.loss_percent)

    def test_stable_and_degraded_results_use_explicit_thresholds(self):
        stable = QualityResult("gw", 4, 4, 8, 2, 0, 20, True)
        degraded = QualityResult("gw", 4, 3, 120, 35, 25, 20, True)
        self.assertEqual(classify_quality(stable)[0], "STABLE")
        self.assertEqual(classify_quality(degraded)[0], "REVIEW")

    def test_trend_requires_five_valid_checks_and_detects_sustained_degradation(self):
        self.assertEqual(quality_trend([])[0], "INSUFFICIENT DATA")
        rows = [
            {"received": 4, "latency_ms": value}
            for value in (42, 40, 10, 11, 9)
        ]
        self.assertEqual(quality_trend(rows)[0], "DEGRADING")

    def test_one_action_fills_missing_trend_baseline_checks(self):
        valid = {"received": 4, "latency_ms": 10.0}
        invalid = {"received": 2, "latency_ms": 10.0}

        self.assertEqual(checks_needed_for_trend([]), 5)
        self.assertEqual(checks_needed_for_trend([valid, valid, invalid]), 3)
        self.assertEqual(checks_needed_for_trend([valid] * 5), 1)

    def test_capacity_uses_routed_adapter_instead_of_fastest_virtual_adapter(self):
        from unittest.mock import patch

        physical = SimpleNamespace(isup=True, speed=1000)
        virtual = SimpleNamespace(isup=True, speed=4294)
        address = lambda value: SimpleNamespace(address=value)
        with patch("netpulse.services.performance.psutil.net_if_stats", return_value={
            "Ethernet": physical, "vEthernet (Default Switch)": virtual,
        }), patch("netpulse.services.performance.psutil.net_if_addrs", return_value={
            "Ethernet": [address("192.168.1.25")],
            "vEthernet (Default Switch)": [address("172.20.0.1")],
        }):
            result = adapter_capacity("All", "192.168.1.1",
                                      socket_factory=lambda *args: _RouteSocket())

        self.assertEqual(result["name"], "Ethernet")
        self.assertEqual(result["speed_mbps"], 1000.0)


if __name__ == "__main__":
    unittest.main()
