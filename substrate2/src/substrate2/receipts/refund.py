"""
substrate2.receipts.refund — refund receipt (FULL / PARTIAL / REJECTED).

From draft-hopley-x402-refund-receipt-02 + refund_receipt_v1 vectors. Not derived from v1.
"""
from __future__ import annotations

from ..canon import CANON_VERSION
from ._common import (
    ReceiptError,
    require_amount,
    require_enum,
    require_int_ms,
    require_jurisdiction_flags,
    require_str,
)

REFUND_RESULTS = frozenset({"FULL", "PARTIAL", "REJECTED"})


class RefundReceiptError(ReceiptError):
    pass


def build_refund_receipt(
    *,
    original_payment_ref: str,
    refund_result: str,
    refund_timestamp_ms: int,
    refund_provider_did: str,
    refund_amount: dict,
    jurisdiction_flags: list,
    canon_version: str = CANON_VERSION,
) -> dict:
    try:
        return {
            "canon_version": require_str("canon_version", canon_version),
            "jurisdiction_flags": require_jurisdiction_flags(jurisdiction_flags),
            "original_payment_ref": require_str("original_payment_ref", original_payment_ref),
            "refund_amount": require_amount("refund_amount", refund_amount),
            "refund_provider_did": require_str("refund_provider_did", refund_provider_did),
            "refund_result": require_enum("refund_result", refund_result, REFUND_RESULTS),
            "refund_timestamp_ms": require_int_ms("refund_timestamp_ms", refund_timestamp_ms),
        }
    except ReceiptError as exc:
        raise RefundReceiptError(str(exc)) from exc


__all__ = ["REFUND_RESULTS", "RefundReceiptError", "build_refund_receipt"]
