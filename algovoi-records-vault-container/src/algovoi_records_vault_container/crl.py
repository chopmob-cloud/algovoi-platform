"""Signed container revocation list (CRL) — offline-verifiable.

A CRL is a Falcon-1024-signed ``acv_revocation_list`` envelope listing revoked ``container_id`` values.
The issuer (the Compliance Command Center) signs it; a recipient's offline extractor verifies the
signature against the issuer public key baked into each container header and refuses to open a revoked
or (when revocation is required) an uncovered container. This mirrors the AlgoVoi revocation-ref
pattern (JCS + Falcon signed refs) without adding a runtime dependency on it.
"""
from __future__ import annotations

from datetime import datetime, timezone

from algovoi_doc_archive import signing

CRL_TYPE = "acv_revocation_list"


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_crl(*, revoked: list[dict], registry: str = "default", updated_at: str | None = None,
              issuer_signer=None, issuer_public_key: bytes | None = None,
              issuer_secret_key: bytes | None = None) -> str:
    """Return a signed CRL envelope (base64url). ``revoked`` = list of
    ``{"container_id", "revoked_at", "reason"}`` (extra keys preserved). Sign with an ``issuer_signer``
    (e.g. the Command Center console signer) or a raw ``issuer_public_key`` + ``issuer_secret_key``."""
    if issuer_signer is not None:
        issuer_public_key = issuer_signer.public_key()
    if issuer_public_key is None or (issuer_signer is None and issuer_secret_key is None):
        raise ValueError("provide issuer_signer, or issuer_public_key + issuer_secret_key")
    payload = {
        "type": CRL_TYPE, "version": "1", "registry": registry,
        "issuer_kid": signing.kid_for(issuer_public_key), "updated_at": updated_at or _iso(),
        "revoked": sorted(revoked, key=lambda r: r.get("container_id", "")),
    }
    return (signing.make_envelope_with(payload, issuer_signer) if issuer_signer is not None
            else signing.make_envelope(payload, issuer_secret_key, issuer_public_key))


def verify_crl(crl_env: str, issuer_public_key: bytes) -> dict | None:
    """Return the validated CRL payload, or ``None`` if the envelope is malformed, not a CRL, or the
    signature does not verify against ``issuer_public_key``."""
    try:
        payload, sig, _ = signing.open_envelope(crl_env)
    except Exception:  # noqa: BLE001
        return None
    if payload.get("type") != CRL_TYPE:
        return None
    if not signing.verify_payload(payload, sig, issuer_public_key):
        return None
    return payload


def is_revoked(container_id: str, crl_env: str, issuer_public_key: bytes) -> bool:
    """True iff ``crl_env`` verifies against ``issuer_public_key`` AND lists ``container_id``.
    A CRL that fails to verify returns False here (the caller decides whether a missing/invalid CRL is
    itself grounds to refuse — see the extractor's ``required`` handling)."""
    payload = verify_crl(crl_env, issuer_public_key)
    if payload is None:
        return False
    return any(r.get("container_id") == container_id for r in payload.get("revoked", []))
