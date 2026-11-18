"""Offline verification of crypto-agility migration evidence (signature alone is sufficient)."""
from __future__ import annotations

from algovoi_crypto_agility import signing
from algovoi_crypto_agility.models import VerifyResult


def verify_migration_attestation(envelope_b64: str, authority_public_key: bytes) -> VerifyResult:
    """Verify a signature-migration or rewrap-migration attestation from the authority's PQC public key."""
    try:
        payload, sig, _kid = signing.open_envelope(envelope_b64)
    except Exception:  # noqa: BLE001
        return VerifyResult(verified=False, reason="malformed envelope")
    if not signing.verify_payload(payload, sig, authority_public_key):
        return VerifyResult(verified=False, reason="signature verification failed")
    return VerifyResult(verified=True, reason="ok", kind=payload.get("kind"),
                        payload=payload, payload_hash=signing.payload_hash(payload))


def verify_hybrid_envelope(hybrid: dict, authority_public_key: bytes, *,
                           legacy_public_key: bytes | None = None) -> VerifyResult:
    """Verify the authoritative PQC side of a hybrid envelope, and that it covers the stated payload.

    SECURITY (2026-08-19): the ``legacy`` block (``algorithm``/``sig``) lives OUTSIDE the PQC-signed
    payload, so on its own it is unauthenticated and malleable — a verifier must never treat a "verified"
    hybrid envelope as evidence the CLASSICAL signature is valid. When the caller supplies
    ``legacy_public_key`` it is REQUIRING the classical co-signature: the legacy block must be present and
    its signature must verify over the same canonical payload (Ed25519), else this fails closed. Without a
    legacy key the PQC side stays authoritative (unchanged behaviour) and the legacy block is not trusted.
    """
    pqc = hybrid.get("pqc")
    if not isinstance(pqc, str):
        return VerifyResult(verified=False, reason="no pqc envelope")
    try:
        payload, sig, _kid = signing.open_envelope(pqc)
    except Exception:  # noqa: BLE001
        return VerifyResult(verified=False, reason="malformed pqc envelope")
    if payload != hybrid.get("payload"):
        return VerifyResult(verified=False, reason="payload mismatch")
    if not signing.verify_payload(payload, sig, authority_public_key):
        return VerifyResult(verified=False, reason="pqc signature verification failed")
    if legacy_public_key is not None:
        import rfc8785

        from algovoi_crypto_agility.agility import verify_legacy_ed25519
        legacy = hybrid.get("legacy")
        if not isinstance(legacy, dict) or not isinstance(legacy.get("sig"), str):
            return VerifyResult(verified=False, reason="hybrid co-signature required but absent")
        try:
            legacy_sig = signing.b64u_decode(legacy["sig"])
        except Exception:  # noqa: BLE001
            return VerifyResult(verified=False, reason="malformed legacy co-signature")
        if not verify_legacy_ed25519(message=rfc8785.dumps(payload), signature=legacy_sig,
                                     public_key=legacy_public_key):
            return VerifyResult(verified=False, reason="legacy co-signature verification failed")
    return VerifyResult(verified=True, reason="ok", kind="hybrid-envelope",
                        payload=payload, payload_hash=signing.payload_hash(payload))
