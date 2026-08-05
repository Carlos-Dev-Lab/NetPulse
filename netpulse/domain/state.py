"""In-memory aggregation state for a capture session."""

from collections import defaultdict, deque
from typing import Dict, List, Protocol

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
        if not pkts:
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
            if p.direction == "IN":
                bi += p.size; pi += 1; self.bytes_in += p.size
            else:
                bo += p.size; po += 1; self.bytes_out += p.size
            # Enqueue geo lookup for remote IPs
            if p.remote and p.remote not in ("", "0.0.0.0"):
                self._ip_enricher.enqueue(p.remote)

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
        self._alert_bw_fired = False
        self._alert_pps_fired = False


# ════════════════════════════════════════════════════════════════════════
# VIEWS
# ════════════════════════════════════════════════════════════════════════

# ── 1. DASHBOARD ────────────────────────────────────────────────────────
