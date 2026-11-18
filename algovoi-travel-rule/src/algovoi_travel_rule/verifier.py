"""Offline verification of a Travel Rule receipt — signature, plus the data-to-attestation binding."""
from __future__ import annotations

import time

from algovoi_travel_rule import signing
from algovoi_travel_rule.models import VerifyResult
from algovoi_travel_rule.travel_rule import _as_dict


def verify_travel_rule_receipt(receipt_envelope_b64: str, issuer_public_key: bytes, *,
                               expected_signer_kid: str | None = None,
                               max_age_ms: int | None = None,
                               ivms101=None) -> VerifyResult:
    """Verify a Travel Rule receipt offline from the issuing VASP's Falcon-1024 public key.

    SECURITY: a valid signature proves the receipt was signed by ``issuer_public_key`` — it does NOT prove
    that key belongs to the ``originating_vasp_did`` the receipt names (anyone can mint a key and claim any
    DID). The result therefore carries ``signer_kid`` (the kid of the verifying key) and the caller MUST
    confirm that kid is the authorised key for ``receipt['originating_vasp_did']`` out of band. Pass
    ``expected_signer_kid`` (the kid you pinned for the claimed VASP) to have this function enforce it.

    ``max_age_ms`` (optional) rejects a receipt whose ``issued_at_ms`` is older than the window (a stale
    "compliance met" receipt must not be replayed indefinitely). ``ivms101`` (optional) folds the PII-binding
    check into this SINGLE verified call, so the binding is only ever confirmed against a signature-verified
    receipt — never a raw, unauthenticated dict (see :func:`verify_ivms101_binding`).
    """
    try:
        payload, sig, _kid = signing.open_envelope(receipt_envelope_b64)
    except Exception:  # noqa: BLE001
        return VerifyResult(verified=False, reason="malformed envelope")
    if not signing.verify_payload(payload, sig, issuer_public_key):
        return VerifyResult(verified=False, reason="signature verification failed")
    signer_kid = signing.kid_for(issuer_public_key)
    if expected_signer_kid is not None and signer_kid != expected_signer_kid:
        return VerifyResult(verified=False, reason="signer kid does not match the expected VASP key",
                            signer_kid=signer_kid)
    if max_age_ms is not None:
        issued = payload.get("issued_at_ms")
        now_ms = int(time.time() * 1000)
        if not isinstance(issued, int) or issued > now_ms + 60_000 or (now_ms - issued) > int(max_age_ms):
            return VerifyResult(verified=False, reason="receipt outside the freshness window",
                                signer_kid=signer_kid, transfer_ref=payload.get("transfer_ref"))
    if ivms101 is not None and not _binding_ok(payload, ivms101):
        return VerifyResult(verified=False, reason="ivms101 does not match the receipt binding",
                            signer_kid=signer_kid, transfer_ref=payload.get("transfer_ref"))
    return VerifyResult(
        verified=True, reason="ok", receipt=payload,
        receipt_hash=signing.payload_hash(payload), signer_kid=signer_kid,
        applies=bool(payload.get("applies")), transfer_ref=payload.get("transfer_ref"),
    )


def _binding_ok(receipt: dict, ivms101) -> bool:
    h = receipt.get("ivms101_hash")
    if not h:
        return False
    return signing.payload_hash(_as_dict(ivms101)) == h


def verify_ivms101_binding(receipt: dict, ivms101) -> bool:
    """Confirm a received IVMS101 payload is exactly the one the receipt attests.

    The receipt carries `ivms101_hash = sha256(JCS(ivms101))`; a beneficiary VASP that decrypts the
    sealed payload checks it hashes to that value — binding the confidential PII to the signed receipt
    without the receipt ever carrying the PII.

    SECURITY: this only compares hashes — it does NOT verify the receipt's signature. Pass ONLY a receipt
    payload you have already run through :func:`verify_travel_rule_receipt` (or, preferably, pass ``ivms101``
    to that function so the binding is checked against a signature-verified receipt in one call). Calling
    this on a raw, unauthenticated dict proves nothing about authenticity.
    """
    return _binding_ok(receipt, ivms101)
