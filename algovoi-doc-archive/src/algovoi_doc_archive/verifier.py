"""Offline verification of archive entries and the tamper-evident chain (pure, never raises)."""
from __future__ import annotations

from algovoi_doc_archive import signing
from algovoi_doc_archive.models import VerifyChainResult, VerifyEntryResult


def verify_entry(receipt: str, public_key: bytes) -> VerifyEntryResult:
    """Verify a single archive entry: envelope + type + Falcon signature."""
    try:
        payload, sig, kid = signing.open_envelope(receipt)
    except Exception:  # noqa: BLE001
        return VerifyEntryResult(verified=False, status="invalid",
                                 error_code="INVALID_RECEIPT", error_message="malformed receipt envelope")
    if payload.get("type") != "archive_entry":
        return VerifyEntryResult(verified=False, status="invalid", kid=kid,
                                 error_code="WRONG_TYPE", error_message="not an archive_entry envelope")
    if not signing.verify_payload(payload, sig, public_key):
        return VerifyEntryResult(verified=False, status="invalid", kid=kid,
                                 error_code="TAMPERED_SIGNATURE", error_message="signature verification failed")
    return VerifyEntryResult(
        verified=True, status="valid", entry_id=payload.get("entry_id"), seq=payload.get("seq"),
        doc_hash=payload.get("doc_hash"), title=payload.get("title"), content_type=payload.get("content_type"),
        enc_alg=payload.get("enc_alg"), prev_receipt_hash=payload.get("prev_receipt_hash"),
        kid=kid, archived_at=payload.get("archived_at"))


def verify_chain(receipts: list[str], public_key: bytes, *,
                 expected_head: dict | None = None) -> VerifyChainResult:
    """Verify the whole append-only chain: each entry signed, sequential, and correctly hash-linked.

    A pass proves no entry was altered, inserted, reordered, or back-dated. On its own it does **not**
    prove nothing was TRUNCATED — dropping trailing entries yields a shorter chain that still links
    cleanly. Pass ``expected_head`` (``{seq_count, last_receipt_hash}`` recorded out-of-band) to detect a
    removed tail: the verified length and head must then match it.
    """
    prev: str | None = None
    for i, r in enumerate(receipts):
        try:
            payload, sig, _ = signing.open_envelope(r)
        except Exception:  # noqa: BLE001
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="malformed_entry")
        if payload.get("type") != "archive_entry":
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="wrong_type")
        if not signing.verify_payload(payload, sig, public_key):
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="bad_signature")
        if payload.get("seq") != i:
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="seq_mismatch")
        if payload.get("prev_receipt_hash") != prev:
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="chain_break")
        prev = signing.payload_hash(payload)
    # SECURITY (2026-08-19): truncation guard — a clean prefix is not a clean whole. When the caller
    # pins the head, require length + head to match so a dropped tail is caught.
    #
    # SECURITY (2026-08-14): an anchor that cannot be checked must FAIL, never skip. Guarding each
    # comparison with `if exp_x is not None` meant an empty or partial ``expected_head`` checked
    # nothing and still returned valid=True, so a caller who passed a truncated dict read a green
    # result believing the tail had been pinned. Both fields are now mandatory when an anchor is
    # given, and a malformed value is a refusal rather than a ValueError out of a function
    # documented as "pure, never raises".
    if expected_head is not None:
        exp_n = expected_head.get("seq_count") if isinstance(expected_head, dict) else None
        exp_head = expected_head.get("last_receipt_hash") if isinstance(expected_head, dict) else None
        # An empty archive legitimately has no tail hash (None) with seq_count 0. That is a complete
        # anchor for an empty chain, not an incomplete one: requiring a string there rejected every
        # healthy brand-new store. The same (0, None) shape is also well-formed against a NON-empty
        # chain, where the honest answer is length_mismatch rather than a malformed-anchor complaint,
        # because the anchor's validity and the chain's length are separate questions. Both cases are
        # covered by the type check and the comparisons below, so there is no special case to make:
        # an earlier `empty_anchor_ok` shortcut became dead once this shape was accepted, and was
        # removed rather than left in place looking load-bearing.
        exp_n_ok = isinstance(exp_n, int) and not isinstance(exp_n, bool) and exp_n >= 0
        # Mirror the persisted-head rule: at seq_count 0 the ONLY well-formed tail hash is None. A
        # string there claims an entry that cannot exist, which is malformed rather than a length
        # mismatch, and calling it well-formed made the verifier disagree with Archive.verify_chain
        # about the identical shape.
        if exp_n == 0:
            exp_head_ok = exp_head is None
        else:
            exp_head_ok = isinstance(exp_head, str)
        if not (exp_n_ok and exp_head_ok):
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="incomplete_expected_head", head_receipt_hash=prev)
        if len(receipts) != exp_n:
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="length_mismatch", head_receipt_hash=prev)
        if prev != exp_head:
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="head_mismatch", head_receipt_hash=prev)
    return VerifyChainResult(valid=True, length=len(receipts), head_receipt_hash=prev)
