"""Offline verification of audit-log entries and the tamper-evident chain (pure, never raises)."""
from __future__ import annotations

from algovoi_audit_log import signing
from algovoi_audit_log.models import VerifyChainResult, VerifyEntryResult


def verify_entry(receipt: str, public_key: bytes) -> VerifyEntryResult:
    """Verify a single log entry: envelope + type + Falcon signature + event-hash consistency."""
    try:
        payload, sig, kid = signing.open_envelope(receipt)
    except Exception:  # noqa: BLE001
        return VerifyEntryResult(verified=False, status="invalid",
                                 error_code="INVALID_RECEIPT", error_message="malformed entry envelope")
    if payload.get("type") != "audit_event":
        return VerifyEntryResult(verified=False, status="invalid", kid=kid,
                                 error_code="WRONG_TYPE", error_message="not an audit_event envelope")
    if not signing.verify_payload(payload, sig, public_key):
        return VerifyEntryResult(verified=False, status="invalid", kid=kid,
                                 error_code="TAMPERED_SIGNATURE", error_message="signature verification failed")
    if payload.get("event_hash") != signing.payload_hash(payload.get("event") or {}):
        return VerifyEntryResult(verified=False, status="invalid", kid=kid,
                                 error_code="EVENT_HASH_MISMATCH", error_message="event_hash does not match event")
    return VerifyEntryResult(
        verified=True, status="valid", seq=payload.get("seq"), event_id=payload.get("event_id"),
        event_type=payload.get("event_type"), event_hash=payload.get("event_hash"), actor=payload.get("actor"),
        prev_entry_hash=payload.get("prev_entry_hash"), recorded_at=payload.get("recorded_at"), kid=kid)


def verify_chain(receipts: list[str], public_key: bytes, *,
                 expected_head: dict | None = None) -> VerifyChainResult:
    """Verify the whole append-only chain: each entry signed, sequential, hash-linked, event-consistent.

    A pass proves no entry was altered, inserted, reordered, or back-dated. It does **not**, on its
    own, prove nothing was TRUNCATED: dropping trailing entries yields a shorter chain that still links
    cleanly, so a valid prefix is indistinguishable from the whole unless the expected length and head
    are pinned out-of-band. Pass ``expected_head`` (``{seq_count, last_entry_hash}`` from a head you
    recorded earlier) to detect a removed tail — the verified length and head must then match it.
    """
    prev: str | None = None
    for i, r in enumerate(receipts):
        try:
            payload, sig, _ = signing.open_envelope(r)
        except Exception:  # noqa: BLE001
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="malformed_entry")
        if payload.get("type") != "audit_event":
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="wrong_type")
        if not signing.verify_payload(payload, sig, public_key):
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="bad_signature")
        if payload.get("seq") != i:
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="seq_mismatch")
        if payload.get("prev_entry_hash") != prev:
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="chain_break")
        if payload.get("event_hash") != signing.payload_hash(payload.get("event") or {}):
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="event_hash_mismatch")
        prev = signing.payload_hash(payload)
    # SECURITY (2026-08-19): truncation guard — a clean prefix is not a clean whole. When the caller
    # pins the head it saw earlier, require the length and head to match so a dropped tail is caught.
    if expected_head is not None:
        exp_n = expected_head.get("seq_count")
        exp_head = expected_head.get("last_entry_hash")
        if exp_n is not None and len(receipts) != int(exp_n):
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="length_mismatch", head_entry_hash=prev)
        if exp_head is not None and prev != exp_head:
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="head_mismatch", head_entry_hash=prev)
    return VerifyChainResult(valid=True, length=len(receipts), head_entry_hash=prev)
