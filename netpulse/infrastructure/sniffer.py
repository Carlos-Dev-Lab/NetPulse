"""
NetPulse — Packet Sniffer
Async background capture via Scapy + Npcap.
Requires: Administrator privileges on Windows.
"""
import queue
import ipaddress
import time
import threading
import psutil
from datetime import datetime
from typing import Optional, List, Dict

from netpulse.domain.models import Packet


# ── Data model ────────────────────────────────────────────────────────────────
# ── Port → PID mapper ─────────────────────────────────────────────────────────
class PortPidMapper:
    """
    Thread-safe mapper: local_port (int) → (pid, proc_name).
    Refreshes the psutil connection table in a background daemon thread
    every REFRESH_INTERVAL seconds, keeping lookups lock-free and fast.
    """
    REFRESH_INTERVAL = 2.0   # seconds

    def __init__(self):
        self._map: Dict[int, tuple] = {}   # port -> (pid, name)
        self._running = False
        self._thread = None

    def start(self):
        if not self._running:
            self._running = True
            # Build first map immediately so we have data right away
            self._refresh()
            self._thread = threading.Thread(target=self._refresh_loop, daemon=True)
            self._thread.start()

    def stop(self):
        self._running = False
        self._thread = None

    def lookup(self, port: Optional[int]) -> tuple:
        """Return (pid, proc_name) for given local port, or (None, '')."""
        if not port:
            return (None, "")
        # Lock-free lookup (GIL-safe dictionary lookup)
        return self._map.get(port, (None, ""))

    def _refresh_loop(self):
        while self._running:
            time.sleep(self.REFRESH_INTERVAL)
            if self._running:
                self._refresh()

    def _refresh(self):
        """Rebuild port→pid map from active connections."""
        new_map: Dict[int, tuple] = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr and conn.pid:
                    lport = conn.laddr.port
                    try:
                        name = psutil.Process(conn.pid).name()
                    except Exception:
                        name = f"pid:{conn.pid}"
                    new_map[lport] = (conn.pid, name)
        except Exception:
            pass
        self._map = new_map


# Module-level singleton used by Sniffer
_port_pid_mapper = PortPidMapper()


# ── Network helpers ───────────────────────────────────────────────────────────
def local_ips() -> set:
    """Return all IPv4 addresses assigned to this machine."""
    ips = {"127.0.0.1", "::1", "0.0.0.0"}
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family.name == "AF_INET":
                    ips.add(a.address)
    except Exception:
        pass
    return ips


def list_interfaces() -> List[Dict]:
    """Return a list of non-loopback IPv4 network interfaces."""
    out: List[Dict] = []
    try:
        st = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family.name == "AF_INET" and not a.address.startswith("127."):
                    out.append({
                        "name": name,
                        "ip":   a.address,
                        "up":   st[name].isup if name in st else False,
                    })
                    break
    except Exception:
        pass
    return out or [{"name": "Default", "ip": "0.0.0.0", "up": True}]


# Module-level scapy cache
_scapy_imported = False
IP, TCP, UDP, ICMP, DNS = None, None, None, None, None


def _import_scapy():
    global _scapy_imported, IP, TCP, UDP, ICMP, DNS
    if not _scapy_imported:
        from scapy.all import IP as scapy_IP, TCP as scapy_TCP, UDP as scapy_UDP, ICMP as scapy_ICMP, DNS as scapy_DNS
        IP, TCP, UDP, ICMP, DNS = scapy_IP, scapy_TCP, scapy_UDP, scapy_ICMP, scapy_DNS
        _scapy_imported = True


# ── Sniffer ───────────────────────────────────────────────────────────────────
class Sniffer:
    """Async packet sniffer. Requires Npcap and Administrator on Windows."""

    _MAX_Q = 200_000

    def __init__(self):
        self._q: queue.Queue[Packet] = queue.Queue(maxsize=self._MAX_Q)
        self._raw_q: queue.Queue = queue.Queue(maxsize=self._MAX_Q)
        self._sniff = None
        self._local: set = local_ips()
        self._worker_thread: Optional[threading.Thread] = None
        self._worker_running = False

    # ── Public ────────────────────────────────────────────────────────────
    @property
    def running(self) -> bool:
        return self._sniff is not None and self._sniff.running

    def start(self, iface_name: Optional[str] = None):
        """Start async capture on one interface or all active interfaces."""
        from scapy.all import AsyncSniffer   # noqa – imported lazily

        # Clear queues
        while not self._q.empty():
            try:
                self._q.get_nowait()
            except queue.Empty:
                break
        while not self._raw_q.empty():
            try:
                self._raw_q.get_nowait()
            except queue.Empty:
                break

        self._local = local_ips()
        _port_pid_mapper.start()

        self._worker_running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

        kw: dict = {"prn": self._cb, "store": False, "filter": "ip"}

        if iface_name and iface_name.lower() != "all":
            resolved = self._resolve_iface(iface_name)
            if resolved:
                kw["iface"] = resolved
        else:
            # On Scapy/Windows, omitting ``iface`` captures only on Scapy's
            # default adapter.  That adapter can be a disconnected Ethernet
            # device even while Wi-Fi is carrying all traffic.  Explicitly
            # provide every usable, active adapter to preserve the UI's
            # advertised "All" semantics.
            active = self._active_capture_interfaces()
            if active:
                kw["iface"] = active

        self._sniff = AsyncSniffer(**kw)
        self._sniff.start()

    def stop(self):
        if self._sniff and self._sniff.running:
            try:
                self._sniff.stop()
            except Exception:
                pass
        self._sniff = None

        self._worker_running = False
        if self._worker_thread:
            try:
                self._worker_thread.join(timeout=1.0)
            except Exception:
                pass
            self._worker_thread = None

        _port_pid_mapper.stop()

    def drain(self, max_n: int = 30_000) -> List[Packet]:
        """Pull up to *max_n* packets from the internal queue."""
        out: List[Packet] = []
        for _ in range(max_n):
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        return out

    # ── Private ───────────────────────────────────────────────────────────
    @staticmethod
    def _resolve_iface(name: str) -> Optional[str]:
        """Map a psutil interface name → Scapy (Npcap) interface name."""
        try:
            from scapy.arch.windows import get_windows_if_list
            name_l = name.lower()
            for wi in get_windows_if_list():
                desc = (wi.get("description") or "").lower()
                wname = (wi.get("name") or "").lower()
                if name_l in desc or name_l in wname:
                    return wi["name"]
        except Exception:
            pass
        return name   # fallback: pass as-is

    @classmethod
    def _active_capture_interfaces(cls) -> List[str]:
        """Return Scapy names for active adapters with a usable IPv4 address."""
        interfaces: List[str] = []
        try:
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                if not stats.get(name) or not stats[name].isup:
                    continue
                usable = False
                for address in addrs:
                    if address.family.name != "AF_INET":
                        continue
                    ip = ipaddress.ip_address(address.address)
                    if not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified:
                        usable = True
                        break
                if usable:
                    resolved = cls._resolve_iface(name)
                    if resolved and resolved not in interfaces:
                        interfaces.append(resolved)
        except Exception:
            return []
        return interfaces

    def _cb(self, pkt):
        try:
            if self._raw_q.full():          # drop oldest if overflowing
                try:
                    self._raw_q.get_nowait()
                except queue.Empty:
                    pass
            self._raw_q.put_nowait(pkt)
        except Exception:
            pass

    def _worker_loop(self):
        _import_scapy()
        while self._worker_running:
            try:
                pkt = self._raw_q.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                p = self._parse(pkt)
                if p is None:
                    continue
                if self._q.full():          # drop oldest if overflowing
                    try:
                        self._q.get_nowait()
                    except queue.Empty:
                        pass
                self._q.put_nowait(p)
            except Exception:
                pass

    def _parse(self, pkt) -> Optional[Packet]:
        try:
            if not pkt.haslayer(IP):
                return None

            ip   = pkt[IP]
            src, dst = ip.src, ip.dst
            size = len(pkt)
            is_out   = src in self._local
            direction = "OUT" if is_out else "IN"
            remote    = dst if is_out else src

            proto = "OTHER"
            sport = dport = None
            info = ""

            if pkt.haslayer(TCP):
                t = pkt[TCP]
                sport, dport = t.sport, t.dport
                if 443 in (sport, dport):
                    proto = "HTTPS"
                    info = "Encrypted TLS traffic"
                elif 80 in (sport, dport):
                    proto = "HTTP"
                    info = "Unencrypted HTTP traffic"
                else:
                    proto = "TCP"
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                sport, dport = u.sport, u.dport
                proto = "DNS" if (53 in (sport, dport) or pkt.haslayer(DNS)) else "UDP"
                if proto == "DNS" and pkt.haslayer(DNS):
                    try:
                        dns = pkt[DNS]
                        if dns.qr == 0 and dns.qd and getattr(dns.qd, "qname", None):
                            query = dns.qd.qname.decode(errors="replace").rstrip(".")
                            info = f"DNS query: {query}"
                        elif dns.qr == 1:
                            info = "DNS response"
                    except Exception:
                        info = "DNS traffic"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            # Map local port → process
            local_port = sport if is_out else dport
            pid, proc_name = _port_pid_mapper.lookup(local_port)

            return Packet(
                ts=datetime.now(), direction=direction, protocol=proto,
                src=src, dst=dst, sport=sport, dport=dport,
                size=size, remote=remote,
                pid=pid, proc_name=proc_name,
                info=info,
            )
        except Exception:
            return None
