"""
Minimal compliance-receipt builder for the composite binding (bundled, no PII).

A compliance receipt records a **content-addressed** payer reference (sha256 of network:address —
never the cleartext) plus the categorical screen verdict. The proof binds the receipt by hash
(sha256 of its JCS canonical bytes), so a verified proof asserts a specific compliance decision
without exposing any underlying data.
"""
from __future__ import annotations

import hashlib

import rfc8785

SCREEN_RESULTS = {"ALLOW", "REFER", "DENY"}


def build_receipt(
    *,
    network: str,
    recipient: str,
    screen_result: str,
    screen_timestamp_ms: int,
    screen_provider_did: str,
    jurisdiction_flags: list[str] | None = None,
) -> dict:
    if screen_result not in SCREEN_RESULTS:
        raise ValueError(f"screen_result must be one of {sorted(SCREEN_RESULTS)}")
    payer_ref = "sha256:" + hashlib.sha256(f"{network}:{recipient}".encode()).hexdigest()
    return {
        "canon_version": "jcs-rfc8785-v1",
        "jurisdiction_flags": jurisdiction_flags or ["UK", "EU"],
        "payer_ref": payer_ref,
        "screen_provider_did": screen_provider_did,
        "screen_result": screen_result,
        "screen_timestamp_ms": screen_timestamp_ms,
    }


def receipt_hash(receipt: dict) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(receipt)).hexdigest()
