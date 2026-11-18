"""Offline verification of a signed compliance receipt (never raises)."""
from __future__ import annotations

from algovoi_compliance_gate import signing
from algovoi_compliance_gate.models import VerifyResult
from algovoi_compliance_gate.screener import SCREEN_RESULTS


def verify_compliance_receipt(receipt_envelope: str, public_key: bytes) -> VerifyResult:
    """Verify the Falcon signature + structure of a compliance receipt against the gate public key."""
    try:
        payload, sig, kid = signing.open_envelope(receipt_envelope)
    except Exception:  # noqa: BLE001
        return VerifyResult(verified=False, error="malformed receipt envelope")
    if payload.get("canon_version") != "jcs-rfc8785-v1" or payload.get("screen_result") not in SCREEN_RESULTS:
        return VerifyResult(verified=False, kid=kid, error="not a compliance receipt")
    if not signing.verify_payload(payload, sig, public_key):
        return VerifyResult(verified=False, kid=kid, error="signature verification failed")
    return VerifyResult(
        verified=True, screen_result=payload.get("screen_result"), payer_ref=payload.get("payer_ref"),
        screen_provider_did=payload.get("screen_provider_did"), canon_version=payload.get("canon_version"),
        screen_timestamp_ms=payload.get("screen_timestamp_ms"),
        jurisdiction_flags=payload.get("jurisdiction_flags"), kid=kid)
