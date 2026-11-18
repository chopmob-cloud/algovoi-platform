"""
substrate2.receipts.cancellation — cancellation receipt
(USER_REQUESTED / MERCHANT_REQUESTED / COMPLIANCE_TERMINATED / EXPIRED).

From draft-hopley-x402-cancellation-receipt-02 + cancellation_receipt_v1 vectors.
Not derived from v1 source.
"""
from __future__ import annotations

from ..canon import CANON_VERSION
from ._common import (
    ReceiptError,
    require_enum,
    require_int_ms,
    require_jurisdiction_flags,
    require_str,
)

CANCELLATION_REASONS = frozenset({"USER_REQUESTED", "MERCHANT_REQUESTED", "COMPLIANCE_TERMINATED", "EXPIRED"})


class CancellationReceiptError(ReceiptError):
    pass


def build_cancellation_receipt(
    *,
    cancellation_reason: str,
    cancellation_timestamp_ms: int,
    effective_from_ms: int,
    cancellation_provider_did: str,
    mandate_ref: str,
    jurisdiction_flags: list,
    canon_version: str = CANON_VERSION,
) -> dict:
    try:
        cts = require_int_ms("cancellation_timestamp_ms", cancellation_timestamp_ms)
        eff = require_int_ms("effective_from_ms", effective_from_ms)
        if eff < cts:
            raise CancellationReceiptError("effective_from_ms must not be before cancellation_timestamp_ms")
        return {
            "canon_version": require_str("canon_version", canon_version),
            "cancellation_provider_did": require_str("cancellation_provider_did", cancellation_provider_did),
            "cancellation_reason": require_enum("cancellation_reason", cancellation_reason, CANCELLATION_REASONS),
            "cancellation_timestamp_ms": cts,
            "effective_from_ms": eff,
            "jurisdiction_flags": require_jurisdiction_flags(jurisdiction_flags),
            "mandate_ref": require_str("mandate_ref", mandate_ref),
        }
    except ReceiptError as exc:
        raise CancellationReceiptError(str(exc)) from exc


__all__ = ["CANCELLATION_REASONS", "CancellationReceiptError", "build_cancellation_receipt"]
