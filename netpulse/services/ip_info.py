"""Asynchronous reverse-DNS and geolocation enrichment."""

import ipaddress
import json
import socket as _socket
import threading
import urllib.request
from typing import Dict


def cc_to_flag(cc: str) -> str:
    """Convert ISO 3166-1 alpha-2 country code to flag emoji. E.g. 'US' -> '🇺🇸'"""
    if not cc or len(cc) != 2:
        return "🏳️"   # white flag fallback
    try:
        return chr(0x1F1E6 + ord(cc[0].upper()) - ord('A')) + \
               chr(0x1F1E6 + ord(cc[1].upper()) - ord('A'))
    except Exception:
        return ""


class IpInfoCache:
    """
    Thread-safe cache that resolves for each IP:
      • Reverse DNS hostname  (socket.gethostbyaddr)
      • Country + city + flag  (ip-api.com, free tier)
      • ASN + organisation    (ip-api.com same call)
    Lookups run in daemon threads so the UI is never blocked.
    """

    def __init__(self):
        # ip -> {"domain": str, "geo": str, "flag": str, "asn": str, "cc": str}
        self._cache: Dict[str, Dict[str, str]] = {}
        self._pending: set = set()
        self._lock = threading.Lock()

    # ── Public ───────────────────────────────────────────────────────
    def get_domain(self, ip: str) -> str:
        with self._lock:
            return self._cache.get(ip, {}).get("domain", "")

    def get_geo(self, ip: str) -> str:
        with self._lock:
            return self._cache.get(ip, {}).get("geo", "")

    def get_flag(self, ip: str) -> str:
        with self._lock:
            return self._cache.get(ip, {}).get("flag", "")

    def get_asn(self, ip: str) -> str:
        with self._lock:
            return self._cache.get(ip, {}).get("asn", "")

    def get_cc(self, ip: str) -> str:
        with self._lock:
            return self._cache.get(ip, {}).get("cc", "")

    def get_label(self, ip: str) -> str:
        """
        Returns a rich one-line label:
          🇺🇸 cdn.cloudflare.com · Miami, US · AS13335 Cloudflare
        Parts that are empty are omitted.
        """
        with self._lock:
            d = self._cache.get(ip, {})
        flag   = d.get("flag", "")
        domain = d.get("domain", "")
        geo    = d.get("geo", "")
        asn    = d.get("asn", "")
        parts = []
        if flag:   parts.append(flag)
        if domain: parts.append(domain)
        if geo:    parts.append(geo)
        if asn:    parts.append(asn)
        return "  ".join(parts)

    def get_short_label(self, ip: str) -> str:
        """Compact: flag + domain (or geo) only."""
        with self._lock:
            d = self._cache.get(ip, {})
        flag   = d.get("flag", "")
        domain = d.get("domain", "") or d.get("geo", "")
        if flag and domain:
            return f"{flag} {domain}"
        return flag or domain

    def enqueue(self, ip: str):
        """Start async lookup if ip not cached/pending yet."""
        with self._lock:
            if ip in self._cache or ip in self._pending:
                return
            self._pending.add(ip)
        threading.Thread(target=self._lookup, args=(ip,), daemon=True).start()

    # ── Private ───────────────────────────────────────────────────────
    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
            return not address.is_global
        except ValueError:
            return False

    def _lookup(self, ip: str):
        domain = ""
        geo    = ""
        flag   = ""
        asn    = ""
        cc     = ""

        if self._is_private(ip):
            domain = "local"
            geo    = "Local Network"
            flag   = "🏠"
        else:
            # 1. Reverse DNS
            try:
                hostname = _socket.gethostbyaddr(ip)[0]
                parts = hostname.rstrip(".").split(".")
                domain = ".".join(parts[-3:]) if len(parts) > 3 else hostname
            except Exception:
                domain = ""

            # 2. Geo + ASN (ip-api.com, free, max 45 req/min)
            try:
                req = urllib.request.Request(
                    f"http://ip-api.com/json/{ip}"
                    f"?fields=status,city,countryCode,as,org",
                    headers={"User-Agent": "NetPulse/1.0"},
                )
                with urllib.request.urlopen(req, timeout=4) as r:
                    data = json.loads(r.read())
                if data.get("status") == "success":
                    city   = data.get("city", "")
                    cc     = data.get("countryCode", "")
                    geo    = f"{city}, {cc}" if city else cc
                    flag   = cc_to_flag(cc)
                    as_raw = data.get("as", "")    # e.g. "AS13335 Cloudflare"
                    org    = data.get("org", "")
                    asn_num  = as_raw.split(" ")[0] if as_raw else ""
                    org_name = org or (" ".join(as_raw.split(" ")[1:]) if as_raw else "")
                    # Truncate long org names
                    if len(org_name) > 22:
                        org_name = org_name[:20] + "…"
                    asn = f"{asn_num} {org_name}".strip() if asn_num else ""
            except Exception:
                pass

        with self._lock:
            self._cache[ip] = {
                "domain": domain, "geo": geo,
                "flag": flag, "asn": asn, "cc": cc,
            }
            self._pending.discard(ip)


geo_cache = IpInfoCache()
