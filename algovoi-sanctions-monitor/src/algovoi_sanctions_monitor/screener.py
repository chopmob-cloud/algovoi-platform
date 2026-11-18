"""
The screening interface. Identical in shape to algovoi-compliance-gate's Screener, so the *same*
injected screener a customer already runs for point-in-time screening plugs straight into the monitor.

A screener maps a subject (network + address) to a categorical verdict ALLOW / REFER / DENY. It is the
plug point for *your* sanctions source (the AlgoVoi live OFSI/OFAC/EU cache, a commercial feed, or your
own list). The monitor never ships a sanctions list; it re-runs your screener on a schedule and signs
the deltas.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

SCREEN_RESULTS = ("ALLOW", "REFER", "DENY")


@dataclass
class ScreenResult:
    """A categorical screening verdict. Reasons stay categorical -- never the matched list/entity name."""
    result: str                      # ALLOW | REFER | DENY
    provider_did: str
    risk_score: float | None = None
    reasons: list[str] | None = None


@runtime_checkable
class Screener(Protocol):
    async def screen(self, *, network: str, address: str, context: dict | None = None) -> ScreenResult: ...


class AllowAllScreener:
    """Reference screener: everything passes. For wiring/tests."""

    def __init__(self, provider_did: str = "did:web:screener.example") -> None:
        self.provider_did = provider_did

    async def screen(self, *, network: str, address: str, context: dict | None = None) -> ScreenResult:
        return ScreenResult(result="ALLOW", provider_did=self.provider_did)


class DenylistScreener:
    """Reference screener backed by a mutable deny/refer set -- lets a subject *become* sanctioned between
    sweeps, which is the whole point of continuous monitoring."""

    def __init__(self, *, deny: set[str] | None = None, refer: set[str] | None = None,
                 provider_did: str = "did:web:screener.example") -> None:
        self.deny = set(deny or ())
        self.refer = set(refer or ())
        self.provider_did = provider_did

    async def screen(self, *, network: str, address: str, context: dict | None = None) -> ScreenResult:
        if address in self.deny:
            return ScreenResult(result="DENY", provider_did=self.provider_did, reasons=["listed"])
        if address in self.refer:
            return ScreenResult(result="REFER", provider_did=self.provider_did, reasons=["review"])
        return ScreenResult(result="ALLOW", provider_did=self.provider_did)
