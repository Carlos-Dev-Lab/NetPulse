"""In-memory aggregation state for a capture session."""

from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Protocol

from .models import Packet


class IpEnricher(Protocol):
    def enqueue(self, ip: str) -> None: ...


class NullIpEnricher:
    def enqueue(self, ip: str) -> None:
        return None


class AppState:
    HIST = 60
    SPARK = 30

    def __init__(self, ip_enricher: IpEnricher | None = None):
        self._ip_enricher = ip_enricher or NullIpEnricher()
        self.capturing   = False
        self.session_id: Optional[int] = None
        self.interface   = "All"

        self.hist_in:  deque = deque([0.0] * self.HIST, maxlen=self.HIST)
        self.hist_out: deque = deque([0.0] * self.HIST, maxlen=self.HIST)
        self.spark_in:  deque = deque([0.0] * self.SPARK, maxlen=self.SPARK)
        self.spark_out: deque = deque([0.0] * self.SPARK, maxlen=self.SPARK)

        self.live: deque = deque(maxlen=500)

        self.total_pkts = 0
        self.bytes_in   = 0
        self.bytes_out  = 0

        self.cur_kbps_in  = 0.0
        self.cur_kbps_out = 0.0
        self.cur_pps      = 0.0
        self.peak_kbps_in  = 0.0
        self.peak_kbps_out = 0.0

        self.proto: Dict[str, int] = defaultdict(int)
        self.top_ips: Dict[str, Dict[str, int]] = {}
        self.last_ip_deltas: Dict[str, Dict[str, int]] = {}
        # Per-process traffic: proc_name -> {"b": bytes, "p": packets}
        self.proc_traffic: Dict[str, Dict[str, int]] = {}
        # Detailed application telemetry keyed by pid and process name. The
        # legacy proc_traffic aggregate remains available to older consumers.
        self.app_traffic: Dict[str, Dict] = {}

        # System metrics (polled from psutil in update_loop)
        self.sys_cpu   = 0.0   # %
        self.sys_ram   = 0.0   # %
        self.spark_cpu: deque = deque([0.0] * self.SPARK, maxlen=self.SPARK)
        self.spark_ram: deque = deque([0.0] * self.SPARK, maxlen=self.SPARK)

        # Alert config
        self.alert_bw_thresh   = 0.0   # KB/s, 0 = disabled
        self.alert_pps_thresh  = 0.0   # pkt/s, 0 = disabled
        self._alert_bw_fired   = False
        self._alert_pps_fired  = False

    def process(self, pkts: List[Packet], dt: float) -> Dict:
        dt = max(dt, 0.01)
        self.last_ip_deltas = {}
        for app in self.app_traffic.values():
            app["tick_in"] = app["tick_out"] = 0
            app["tick_packets"] = 0
            app["rate_in"] = app["rate_out"] = 0.0
            app["rate_pps"] = 0.0
        if not pkts:
            self._update_application_rates(dt)
            self.cur_kbps_in = self.cur_kbps_out = self.cur_pps = 0.0
            self.hist_in.append(0.0)
            self.hist_out.append(0.0)
            self.spark_in.append(0.0)
            self.spark_out.append(0.0)
            return {}

        bi = bo = pi = po = 0
        pd: Dict[str, int] = defaultdict(int)

        for p in pkts:
            self.live.append(p)
            self.total_pkts += 1
            pd[p.protocol] += 1
            self.proto[p.protocol] += 1
            tip = self.top_ips.setdefault(p.remote, {"b": 0, "p": 0})
            tip["b"] += p.size
            tip["p"] += 1
            delta = self.last_ip_deltas.setdefault(p.remote, {"b": 0, "p": 0})
            delta["b"] += p.size
            delta["p"] += 1
            # Per-process tracking
            if p.proc_name:
                tp = self.proc_traffic.setdefault(p.proc_name, {"b": 0, "p": 0})
                tp["b"] += p.size
                tp["p"] += 1
                app_key = f"{p.pid or 0}:{p.proc_name.lower()}"
                app = self.app_traffic.setdefault(app_key, {
                    "key": app_key, "pid": p.pid, "name": p.proc_name,
                    "b": 0, "p": 0, "bytes_in": 0, "bytes_out": 0,
                    "packets_in": 0, "packets_out": 0,
                    "tick_in": 0, "tick_out": 0,
                    "rate_in": 0.0, "rate_out": 0.0,
                    "tick_packets": 0, "rate_pps": 0.0,
                    "peak_rate": 0.0, "peak_pps": 0.0, "average_rate": 0.0,
                    "rate_samples": 0, "rate_history": deque(maxlen=150),
                    "spike_events": deque(maxlen=30), "last_spike": None,
                    "first_seen": p.ts, "last_seen": p.ts,
                    "protocols": {}, "destinations": {},
                })
                app["b"] += p.size
                app["p"] += 1
                app["last_seen"] = p.ts
                direction = "in" if p.direction == "IN" else "out"
                app[f"bytes_{direction}"] += p.size
                app[f"packets_{direction}"] += 1
                app[f"tick_{direction}"] += p.size
                app["tick_packets"] += 1
                app["protocols"][p.protocol] = app["protocols"].get(p.protocol, 0) + 1
                remote_port = p.sport if p.direction == "IN" else p.dport
                destination = app["destinations"].setdefault(p.remote, {
                    "ip": p.remote, "bytes_in": 0, "bytes_out": 0,
                    "packets": 0, "ports": set(), "protocols": set(),
                    "first_seen": p.ts, "last_seen": p.ts,
                })
                destination[f"bytes_{direction}"] += p.size
                destination["packets"] += 1
                destination["last_seen"] = p.ts
                if remote_port:
                    destination["ports"].add(int(remote_port))
                destination["protocols"].add(p.protocol)
            if p.direction == "IN":
                bi += p.size; pi += 1; self.bytes_in += p.size
            else:
                bo += p.size; po += 1; self.bytes_out += p.size
            # Enqueue geo lookup for remote IPs
            if p.remote and p.remote not in ("", "0.0.0.0"):
                self._ip_enricher.enqueue(p.remote)

        self._update_application_rates(dt)

        self.cur_kbps_in  = bi / 1024 / dt
        self.cur_kbps_out = bo / 1024 / dt
        self.cur_pps      = len(pkts) / dt

        self.peak_kbps_in  = max(self.peak_kbps_in,  self.cur_kbps_in)
        self.peak_kbps_out = max(self.peak_kbps_out, self.cur_kbps_out)

        self.hist_in.append(self.cur_kbps_in)
        self.hist_out.append(self.cur_kbps_out)
        self.spark_in.append(self.cur_kbps_in)
        self.spark_out.append(self.cur_kbps_out)

        return {"bytes_in": bi, "bytes_out": bo,
                "pkts_in": pi, "pkts_out": po, **pd}

    def _update_application_rates(self, dt: float) -> None:
        """Update per-application live rates and evidence-backed spike events."""
        now = datetime.now()
        for app in self.app_traffic.values():
            app["rate_in"] = app["tick_in"] / 1024 / dt
            app["rate_out"] = app["tick_out"] / 1024 / dt
            app["rate_pps"] = app["tick_packets"] / dt
            total_rate = app["rate_in"] + app["rate_out"]
            previous_average = app["average_rate"]
            is_spike = (
                total_rate >= 25.0
                and total_rate >= max(25.0, previous_average * 3.0)
                and (
                    app["last_spike"] is None
                    or (now - app["last_spike"]).total_seconds() >= 5
                )
            )
            if is_spike:
                app["spike_events"].append({
                    "ts": now, "rate": total_rate,
                    "rate_in": app["rate_in"], "rate_out": app["rate_out"],
                    "baseline": previous_average,
                })
                app["last_spike"] = now
            app["peak_rate"] = max(app["peak_rate"], total_rate)
            app["peak_pps"] = max(app["peak_pps"], app["rate_pps"])
            app["rate_samples"] += 1
            # Exponential moving average follows normal usage without letting
            # one burst permanently redefine the baseline.
            alpha = .08
            app["average_rate"] = (
                total_rate if app["rate_samples"] == 1
                else previous_average * (1 - alpha) + total_rate * alpha
            )
            app["rate_history"].append({
                "ts": now, "in": app["rate_in"], "out": app["rate_out"],
                "pps": app["rate_pps"],
            })

    def check_alerts(self) -> list:
        """Return list of (title, msg) alert tuples that just triggered."""
        alerts = []
        total_bw = self.cur_kbps_in + self.cur_kbps_out
        if self.alert_bw_thresh > 0:
            if total_bw >= self.alert_bw_thresh and not self._alert_bw_fired:
                alerts.append(("⚡ Bandwidth Alert",
                                f"Traffic {total_bw:.1f} KB/s exceeds threshold {self.alert_bw_thresh:.0f} KB/s"))
                self._alert_bw_fired = True
            elif total_bw < self.alert_bw_thresh * 0.8:
                self._alert_bw_fired = False
        if self.alert_pps_thresh > 0:
            if self.cur_pps >= self.alert_pps_thresh and not self._alert_pps_fired:
                alerts.append(("🚨 Packet Rate Alert",
                                f"{self.cur_pps:.0f} pkt/s exceeds threshold {self.alert_pps_thresh:.0f} pkt/s"))
                self._alert_pps_fired = True
            elif self.cur_pps < self.alert_pps_thresh * 0.8:
                self._alert_pps_fired = False
        return alerts

    def reset(self):
        self.capturing = False; self.session_id = None
        self.hist_in  = deque([0.0] * self.HIST, maxlen=self.HIST)
        self.hist_out = deque([0.0] * self.HIST, maxlen=self.HIST)
        self.spark_in  = deque([0.0] * self.SPARK, maxlen=self.SPARK)
        self.spark_out = deque([0.0] * self.SPARK, maxlen=self.SPARK)
        self.live.clear()
        self.total_pkts = self.bytes_in = self.bytes_out = 0
        self.cur_kbps_in = self.cur_kbps_out = self.cur_pps = 0.0
        self.peak_kbps_in = self.peak_kbps_out = 0.0
        self.proto.clear()
        self.top_ips.clear()
        self.last_ip_deltas.clear()
        self.proc_traffic.clear()
        self.app_traffic.clear()
        self._alert_bw_fired = False
        self._alert_pps_fired = False
