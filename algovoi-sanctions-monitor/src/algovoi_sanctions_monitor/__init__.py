"""
algovoi-sanctions-monitor — continuous sanctions monitoring as signed, no-PII delta evidence.

Point-in-time screening (Compliance Gate) confirms a counterparty is clean *now*. Designations change.
This keeps a watchlist, re-screens on every sweep, and emits a **Falcon-1024-signed delta receipt** the
moment a verdict changes (clean to hit, hit to cleared, escalation). Receipts carry only
`subject_ref = sha256(network:address)` — no PII — and verify offline. Bring your own screener (the same
interface as Compliance Gate).

Embed::

    from algovoi_sanctions_monitor import SanctionsMonitor, DenylistScreener, verify_monitor_receipt, signing

    pk, sk = signing.generate_keypair()
    screener = DenylistScreener()                     # or the AlgoVoi live OFSI/OFAC/EU screener
    mon = SanctionsMonitor(secret_key=sk, public_key=pk, screener=screener, monitor_did="did:web:acme")

    ref = mon.watch(network="base", address="0x..")
    await mon.sweep()                                  # baseline, no delta

    screener.deny.add("0x..")                          # counterparty becomes sanctioned
    deltas = await mon.sweep()                          # -> one signed "newly_hit" delta receipt
    assert verify_monitor_receipt(deltas[0]["receipt_envelope"], pk).verified

Commercial product — AlgoVoi Commercial Licence v1.0. Included free for every Substrate 2 customer.
"""
from __future__ import annotations

from algovoi_sanctions_monitor import licensing, signing
from algovoi_sanctions_monitor.models import VerifyResult, WatchRecord, WatchStatus
from algovoi_sanctions_monitor.monitor import SanctionsMonitor, subject_ref
from algovoi_sanctions_monitor.screener import (
    SCREEN_RESULTS,
    AllowAllScreener,
    DenylistScreener,
    ScreenResult,
    Screener,
)
from algovoi_sanctions_monitor.verifier import verify_monitor_receipt

__version__ = "0.1.0"

__all__ = [
    "SanctionsMonitor",
    "subject_ref",
    "Screener",
    "ScreenResult",
    "AllowAllScreener",
    "DenylistScreener",
    "SCREEN_RESULTS",
    "verify_monitor_receipt",
    "VerifyResult",
    "WatchStatus",
    "WatchRecord",
    "signing",
    "licensing",
    "__version__",
]
