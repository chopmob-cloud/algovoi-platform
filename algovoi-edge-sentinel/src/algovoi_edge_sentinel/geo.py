"""Pluggable IP -> {country, asn} resolution.

The edge layer is deliberately data-source-agnostic: a :class:`GeoProvider` is injected, exactly as the
signing key and the store are. A deployment plugs in a MaxMind GeoLite2 / IP2Location-backed provider;
tests and local validation use :class:`InMemoryGeoProvider` built from a small CIDR fixture (no external
fetch — the project rule is local-only validation). Longest-prefix match wins.
"""
from __future__ import annotations

import ipaddress
from typing import Protocol


class GeoProvider(Protocol):
    def resolve(self, ip: str) -> dict:
        """Return ``{"country": <ISO-3166 alpha-2 or None>, "asn": <int or None>}`` for ``ip``."""
        ...


class InMemoryGeoProvider:
    """Resolve from an in-memory CIDR table. ``entries`` is a list of ``{"cidr", "country", "asn"}``.
    Longest-prefix match wins; unknown IPs resolve to ``{country: None, asn: None}``."""

    def __init__(self, entries: list[dict]) -> None:
        self._nets: list[tuple] = []
        for e in entries:
            net = ipaddress.ip_network(e["cidr"], strict=False)
            self._nets.append((net, e.get("country"), e.get("asn")))
        # longest prefix first so the first containing match is the most specific
        self._nets.sort(key=lambda t: t[0].prefixlen, reverse=True)

    def resolve(self, ip: str) -> dict:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"country": None, "asn": None}
        for net, country, asn in self._nets:
            if addr.version == net.version and addr in net:
                return {"country": country, "asn": asn}
        return {"country": None, "asn": None}


def ip_in_any(ip: str, cidrs) -> bool:
    """True iff ``ip`` falls in any CIDR in ``cidrs`` (used by allow/deny-CIDR rules)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


__all__ = ["GeoProvider", "InMemoryGeoProvider", "ip_in_any"]
