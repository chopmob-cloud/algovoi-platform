"""
substrate2.pef — Payment Evidence Frame.

From draft-hopley-x402-payment-evidence-frame-00 + pef_v1 vectors. The frame preimage is:
    {canon_version (URN form), claim_type, frame_provider_did, frame_timestamp_ms,
     pef_version, receipt, receipt_format, receipt_hash}
frame_id = "sha256:" + sha256_jcs(preimage). Not derived from v1 source.
"""
from __future__ import annotations

from typing import Any

from .digest import sha256_jcs

PEF_VERSION = "1"
# PEF pins the canonicalisation rule in URN form (distinct from the bare receipt form).
CANON_VERSION = "urn:x402:canonicalisation:jcs-rfc8785-v1"

RECEIPT_FORMAT = {
    "payment_admission": "compliance-receipt-v1",
    "payment_settlement": "settlement-attestation-v1",
    "payment_cancellation": "cancellation-receipt-v1",
    "payment_refund": "refund-receipt-v1",
    "composite_verdict": "composite-trust-query-v1",
    "payment_execution": "execution-binding-v1",   # keystone execution fact (decision_ref + execution_ref)
}
# CLAIM_TYPES is the claim_type -> receipt_format mapping (indexable by claim_type).
CLAIM_TYPES = RECEIPT_FORMAT

_SIG_KEYS = ("frame_id", "signature")


class PefError(ValueError):
    pass


def _preimage(claim_type: str, receipt: dict, frame_provider_did: str, frame_timestamp_ms: int) -> dict:
    if claim_type not in RECEIPT_FORMAT:
        raise PefError(f"Unknown claim_type: {claim_type!r}")
    if not isinstance(receipt, dict):
        raise TypeError("receipt must be a dict")
    if not isinstance(frame_provider_did, str) or not frame_provider_did:
        raise PefError("frame_provider_did must be a non-empty string")
    if isinstance(frame_timestamp_ms, bool) or not isinstance(frame_timestamp_ms, int) or frame_timestamp_ms < 0:
        raise PefError("frame_timestamp_ms must be a non-negative integer")
    return {
        "canon_version": CANON_VERSION,
        "claim_type": claim_type,
        "frame_provider_did": frame_provider_did,
        "frame_timestamp_ms": frame_timestamp_ms,
        "pef_version": PEF_VERSION,
        "receipt": receipt,
        "receipt_format": RECEIPT_FORMAT[claim_type],
        "receipt_hash": "sha256:" + sha256_jcs(receipt),
    }


def build_pef(
    *,
    claim_type: str,
    receipt: dict,
    frame_provider_did: str,
    frame_timestamp_ms: int,
    signature: Any = None,
) -> dict:
    """Build a Payment Evidence Frame (preimage + frame_id, plus optional signature)."""
    preimage = _preimage(claim_type, receipt, frame_provider_did, frame_timestamp_ms)
    frame = dict(preimage)
    frame["frame_id"] = "sha256:" + sha256_jcs(preimage)
    if signature is not None:
        frame["signature"] = signature
    return frame


def pef_frame_id(frame: dict) -> str:
    """Recompute the frame_id from a frame's preimage portion (excludes frame_id/signature)."""
    preimage = {k: v for k, v in frame.items() if k not in _SIG_KEYS}
    return "sha256:" + sha256_jcs(preimage)


def verify_pef(frame: dict) -> dict:
    """Validate a frame's internal consistency. Returns {"valid": bool, "errors": [str]} (never raises)."""
    errors: list[str] = []
    if frame.get("canon_version") != CANON_VERSION:
        errors.append(f"canon_version mismatch: expected {CANON_VERSION!r}, got {frame.get('canon_version')!r}")
    if frame.get("pef_version") != PEF_VERSION:
        errors.append(f"pef_version mismatch: expected {PEF_VERSION!r}, got {frame.get('pef_version')!r}")
    claim_type = frame.get("claim_type")
    if claim_type not in RECEIPT_FORMAT:
        errors.append(f"Unknown claim_type: {claim_type!r}")
    elif frame.get("receipt_format") != RECEIPT_FORMAT[claim_type]:
        errors.append(
            f"receipt_format mismatch: expected {RECEIPT_FORMAT[claim_type]!r}, got {frame.get('receipt_format')!r}"
        )
    receipt = frame.get("receipt")
    if not isinstance(receipt, dict):
        errors.append("receipt must be an object")
    elif frame.get("receipt_hash") != "sha256:" + sha256_jcs(receipt):
        errors.append("receipt_hash mismatch")
    if frame.get("frame_id") != pef_frame_id(frame):
        errors.append("frame_id mismatch")
    return {"valid": not errors, "errors": errors}


__all__ = [
    "PEF_VERSION", "CANON_VERSION", "RECEIPT_FORMAT", "CLAIM_TYPES", "PefError",
    "build_pef", "pef_frame_id", "verify_pef",
]
