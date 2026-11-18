"""
substrate2.receipts.compliance — compliance receipt (ALLOW / REFER / DENY).

Implemented from draft-hopley-x402-compliance-receipt-02 (Sections 3-5) and the
compliance_receipt_v1 conformance vectors. The receipt is a six-field object:

    {canon_version, jurisdiction_flags, payer_ref, screen_provider_did,
     screen_result, screen_timestamp_ms}

content_hash = sha256_jcs(receipt). Load-bearing invariants enforced here:
  - screen_result is the closed enumeration {ALLOW, REFER, DENY};
  - screen_timestamp_ms is an epoch-millisecond integer (RFC 3339 strings rejected,
    not coerced — Substrate Rule 2 / 3);
  - jurisdiction_flags is an ordered list of strings (array order is byte-load-bearing);
  - canon_version is an in-band pin (byte-load-bearing).

Public signature preserved from v1 (name/args/return); body independently authored.
Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

from typing import Any

from ..canon import CANON_VERSION

SCREEN_RESULTS = frozenset({"ALLOW", "REFER", "DENY"})


class ComplianceReceiptError(ValueError):
    """Raised when compliance-receipt inputs violate the format discipline."""


def _require_str(field: str, value: Any) -> str:
    if not isinstance(value, str) or value == "":
        raise ComplianceReceiptError(f"{field} must be a non-empty string")
    return value


def _require_int_timestamp_ms(value: Any) -> int:
    # bool is a subclass of int; reject it explicitly. Reject RFC 3339 strings.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ComplianceReceiptError("screen_timestamp_ms must be int (Substrate Rule 1); RFC 3339 strings rejected")
    if value < 0:
        raise ComplianceReceiptError("screen_timestamp_ms must be non-negative")
    return value


def _require_jurisdiction_flags(value: Any) -> list:
    if not isinstance(value, (list, tuple)):
        raise ComplianceReceiptError("jurisdiction_flags must be list of non-empty strings")
    if not all(isinstance(x, str) and x for x in value):
        raise ComplianceReceiptError("jurisdiction_flags entries must be non-empty strings")
    return list(value)


class ComplianceReceipt(dict):
    """A compliance receipt object (dict subclass for typed construction + plain JSON)."""

    @property
    def screen_result(self) -> str:
        return self["screen_result"]


def build_compliance_receipt(
    *,
    payer_ref: str,
    screen_result: str,
    screen_timestamp_ms: int,
    screen_provider_did: str,
    jurisdiction_flags: list,
    canon_version: str = CANON_VERSION,
) -> ComplianceReceipt:
    """Build a validated compliance receipt object (ALLOW / REFER / DENY)."""
    if screen_result not in SCREEN_RESULTS:
        raise ComplianceReceiptError(
            f"screen_result must be one of {SCREEN_RESULTS}, got {screen_result!r}"
        )
    return ComplianceReceipt(
        canon_version=_require_str("canon_version", canon_version),
        jurisdiction_flags=_require_jurisdiction_flags(jurisdiction_flags),
        payer_ref=_require_str("payer_ref", payer_ref),
        screen_provider_did=_require_str("screen_provider_did", screen_provider_did),
        screen_result=screen_result,
        screen_timestamp_ms=_require_int_timestamp_ms(screen_timestamp_ms),
    )


__all__ = ["SCREEN_RESULTS", "ComplianceReceipt", "ComplianceReceiptError", "build_compliance_receipt"]
