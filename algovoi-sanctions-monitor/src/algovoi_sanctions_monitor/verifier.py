"""Offline verification of a monitoring delta receipt -- the issuer public key alone is sufficient."""
from __future__ import annotations

from algovoi_sanctions_monitor import signing
from algovoi_sanctions_monitor.models import VerifyResult


def verify_monitor_receipt(receipt_envelope_b64: str, monitor_public_key: bytes) -> VerifyResult:
    """Verify a sanctions-monitor delta receipt from the monitor's Falcon-1024 public key."""
    try:
        payload, sig, _kid = signing.open_envelope(receipt_envelope_b64)
    except Exception:  # noqa: BLE001
        return VerifyResult(verified=False, reason="malformed envelope")
    if payload.get("kind") != "sanctions-monitor-delta":
        return VerifyResult(verified=False, reason="not a sanctions-monitor-delta receipt")
    if not signing.verify_payload(payload, sig, monitor_public_key):
        return VerifyResult(verified=False, reason="signature verification failed")
    return VerifyResult(
        verified=True, reason="ok", receipt=payload,
        receipt_hash=signing.payload_hash(payload),
        subject_ref=payload.get("subject_ref"), transition=payload.get("transition"),
    )
