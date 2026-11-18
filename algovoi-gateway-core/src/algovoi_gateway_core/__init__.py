"""algovoi-gateway-core — a self-hostable, chain-agnostic payment gateway engine.

Install the core plus one ``algovoi-gateway-<chain>`` add-on per blockchain you accept. Each
chain add-on implements one :class:`ChainProvider` and registers via entry points. The engine
creates payment intents, watches settlement, and emits signed, no-PII, CCC-ingestable
settlement receipts. Custody/payout is per-chain and optional (Phase 3).

Commercial product. The crypto core is ``substrate2``.
"""
from __future__ import annotations

from algovoi_gateway_core.engine import GatewayEngine
from algovoi_gateway_core.provider import (
    ChainInfo,
    ChainProvider,
    PaymentRequest,
    SettlementObservation,
    UnknownNetworkError,
    get,
    installed,
    load_entry_point_providers,
    register,
)
from algovoi_gateway_core.receipt import ENTRY_TYPE, SettlementLedger

__version__ = "0.1.3"

# discover any installed chain add-ons on import
load_entry_point_providers()

__all__ = [
    "GatewayEngine", "ChainProvider", "ChainInfo", "PaymentRequest", "SettlementObservation",
    "SettlementLedger", "ENTRY_TYPE", "register", "get", "installed",
    "load_entry_point_providers", "UnknownNetworkError", "__version__",
]
