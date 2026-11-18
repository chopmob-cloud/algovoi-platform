"""
Pluggable screening backend — you inject your sanctions/PEP/AML provider; the Gate certifies its verdict.

The Gate never performs the sanctions data lookup itself (that's a third-party data problem). Implement
:class:`Screener` over your provider and return a categorical verdict. Two bundled reference screeners
(``AllowAllScreener``, ``DenylistScreener``) run out of the box for tests and simple deployments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

SCREEN_RESULTS = {"ALLOW", "REFER", "DENY"}


@dataclass
class ScreenResult:
    result: str                                  # ALLOW | REFER | DENY
    provider_did: str
    risk_score: int | None = None                # optional 0..1000 (milliunits)
    reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.result not in SCREEN_RESULTS:
            raise ValueError(f"result must be one of {sorted(SCREEN_RESULTS)}")


@runtime_checkable
class Screener(Protocol):
    async def screen(self, *, network: str, address: str,
                     amount_microusd: int | None = None, context: dict | None = None) -> ScreenResult: ...


class AllowAllScreener:
    """Always ALLOW. For tests/demos only — never a real compliance posture."""

    def __init__(self, provider_did: str = "did:web:screener.example.com") -> None:
        self.provider_did = provider_did

    async def screen(self, *, network: str, address: str, amount_microusd=None, context=None) -> ScreenResult:
        return ScreenResult(result="ALLOW", provider_did=self.provider_did)


class DenylistScreener:
    """Simple in-memory list screener: addresses on ``deny`` → DENY, on ``refer`` → REFER, else ALLOW.

    Useful as a thin reference or to layer a local block/allow list above your real provider.
    """

    def __init__(self, *, deny: set[str] | None = None, refer: set[str] | None = None,
                 provider_did: str = "did:web:screener.example.com") -> None:
        self.deny = {a.lower() for a in (deny or set())}
        self.refer = {a.lower() for a in (refer or set())}
        self.provider_did = provider_did

    async def screen(self, *, network: str, address: str, amount_microusd=None, context=None) -> ScreenResult:
        a = address.lower()
        if a in self.deny:
            return ScreenResult(result="DENY", provider_did=self.provider_did, reasons=["denylist"])
        if a in self.refer:
            return ScreenResult(result="REFER", provider_did=self.provider_did, reasons=["referlist"])
        return ScreenResult(result="ALLOW", provider_did=self.provider_did)
