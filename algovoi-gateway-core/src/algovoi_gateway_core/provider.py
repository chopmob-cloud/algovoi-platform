"""The ChainProvider contract: one per-chain add-on implements this, the core engine drives it.

A chain add-on (``algovoi-gateway-<chain>``) ships a single class implementing
:class:`ChainProvider` and registers it under the ``algovoi_gateway.providers`` entry-point
group, keyed by network. ``pip install algovoi-gateway-base`` then makes Base available to the
core with no code change.

Phase 1 is the receive-and-verify surface (everything except ``sign_and_pay``). Payout/custody
(:meth:`ChainProvider.sign_and_pay`) is Phase 3 and is optional: a provider may raise
``NotImplementedError`` until custody is wired, and the engine reports the chain as
receive-only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class PaymentRequest:
    """What the merchant asks for. No PII; the payer is identified only on-chain."""
    network: str                       # e.g. "base", "algorand"
    asset: str                         # e.g. "USDC" (the settlement asset on that network)
    amount_minor: int                  # integer minor units (no floats on the wire)
    pay_to: str                        # the receiving address the payer must settle to
    reference: str                     # merchant order ref / memo
    expires_at_ms: int | None = None
    authorized_by_ref: str | None = None   # optional Spend Guardrail decision_ref that authorized this


@dataclass
class SettlementObservation:
    """What the provider observed on-chain for a request. ``settled`` is the gate."""
    settled: bool
    network: str
    tx_id: str | None = None
    asset: str | None = None
    amount_minor: int | None = None
    pay_to: str | None = None
    payer: str | None = None           # the on-chain sender (recorded only as an address)
    confirmations: int | None = None
    finalized: bool | None = None      # provider's finality call (chain-specific)
    observed_at_ms: int | None = None
    reason: str = "pending"            # "settled" | "pending" | "underpaid" | "wrong_asset" | ...


@dataclass
class ChainInfo:
    network: str
    display_name: str
    assets: tuple[str, ...]            # settlement assets this provider verifies
    finality_seconds: int              # nominal time to finality
    supports_payout: bool = False      # Phase 3: can sign + broadcast


@runtime_checkable
class ChainProvider(Protocol):
    """One blockchain's gateway behaviour. Implemented by an ``algovoi-gateway-<chain>`` add-on."""

    def info(self) -> ChainInfo: ...

    async def new_receive_address(self, req: PaymentRequest) -> str:
        """Return (or derive) the address the payer should settle to. For account-model chains
        this is typically the configured merchant address plus the reference as a memo; for
        UTXO/derivation chains it may derive a unique address per intent."""
        ...

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        """Query the chain for a settlement matching ``req`` (asset, amount, pay_to, finality).
        Read-only: needs an RPC endpoint, never a private key."""
        ...

    async def sign_and_pay(self, *, network: str, asset: str, amount_minor: int,
                           pay_to: str, reference: str) -> str:
        """Phase 3 (custody): sign and broadcast an outbound payment, return the tx id.
        Requires the operator's key custody for this chain. May raise NotImplementedError."""
        ...


# ── Provider registry (entry-point discovery) ────────────────────────────────

_REGISTRY: dict[str, ChainProvider] = {}


def register(network: str, provider: ChainProvider) -> None:
    _REGISTRY[network.lower()] = provider


def get(network: str) -> ChainProvider:
    p = _REGISTRY.get(network.lower())
    if p is None:
        raise UnknownNetworkError(f"no provider installed for network {network!r}; "
                                  f"pip install algovoi-gateway-{network.lower()}")
    return p


def installed() -> list[ChainInfo]:
    return [p.info() for p in _REGISTRY.values()]


def load_entry_point_providers() -> int:
    """Discover and register every provider published under the
    ``algovoi_gateway.providers`` entry-point group. Returns how many were loaded."""
    try:
        from importlib.metadata import entry_points
    except Exception:  # pragma: no cover
        return 0
    n = 0
    eps = entry_points()
    group = eps.select(group="algovoi_gateway.providers") if hasattr(eps, "select") \
        else eps.get("algovoi_gateway.providers", [])  # py<3.10 fallback
    for ep in group:
        try:
            factory = ep.load()
            provider = factory() if callable(factory) else factory
            register(ep.name, provider)
            n += 1
        except Exception:  # noqa: BLE001 -- a broken plugin must not stop the others
            continue
    return n


class UnknownNetworkError(ValueError):
    pass


__all__ = [
    "PaymentRequest", "SettlementObservation", "ChainInfo", "ChainProvider",
    "register", "get", "installed", "load_entry_point_providers", "UnknownNetworkError",
]
