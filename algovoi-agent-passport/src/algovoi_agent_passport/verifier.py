"""Public credential verification: signature, expiry, revocation, and optional assertions."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import rfc8785

from algovoi_agent_passport import hybrid, signing
from algovoi_agent_passport.event_ledger import CANON_VERSION, ENTRY_TYPE
from algovoi_agent_passport.models import VerifyResult
from algovoi_agent_passport.store import PassportStore


def _prefixed(value) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _hybrid_ok(credential: str, payload: dict, mldsa_public_key: bytes | None) -> bool:
    """If the envelope carries an ML-DSA-65 co-signature and a key is supplied, it must verify."""
    if mldsa_public_key is None:
        return True
    # SECURITY (Codex-confirmed 2026-08-19): when a verifier supplies an ML-DSA key it is
    # REQUIRING the hybrid co-signature. sig2 lives outside the signed payload, so a missing
    # or undecodable sig2 must FAIL (was: return True), else an attacker strips sig2 and
    # downgrades hybrid protection to Falcon-only.
    try:
        env = json.loads(signing.b64u_decode(credential))
    except Exception:  # noqa: BLE001
        return False
    if "sig2" not in env:
        return False
    return hybrid.verify_bytes(mldsa_public_key, rfc8785.dumps(payload), signing.b64u_decode(env["sig2"]))


@dataclass
class ChainVerifyResult:
    verified: bool
    count: int = 0
    first_bad_seq: int | None = None
    error: str | None = None


def _is_expired(iso: str | None) -> bool:
    if not iso:
        return True
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return True
    return datetime.now(timezone.utc) >= exp


async def verify_passport(
    credential: str,
    public_key: bytes,
    *,
    store: PassportStore | None = None,
    required_scope: str | None = None,
    expected_agent_did: str | None = None,
    strict: bool = False,
    mldsa_public_key: bytes | None = None,
) -> VerifyResult:
    """Verify a passport credential. Returns a :class:`VerifyResult` (never raises).

    Order: envelope decode -> Falcon signature -> expiry -> revocation (if a store is given)
    -> optional expected_agent_did / required_scope assertions.

    ``strict`` controls what happens when a revocation store is configured but **unreachable**. The
    default (``False``, the open/lite behaviour) fails *open*: the signature and expiry already hold, so
    the credential verifies and the revocation check is skipped. A commercial enforcement gate sets
    ``strict=True`` to fail *closed* — if it cannot confirm the credential is not revoked, it refuses
    (``REVOCATION_UNAVAILABLE``) rather than letting a possibly-revoked credential through.
    """
    try:
        payload, sig, kid = signing.open_envelope(credential)
    except Exception:  # noqa: BLE001
        return VerifyResult(verified=False, status="invalid",
                            error_code="INVALID_CREDENTIAL", error_message="malformed credential envelope")

    if not signing.verify_payload(payload, sig, public_key):
        return VerifyResult(verified=False, status="invalid", kid=kid,
                            error_code="TAMPERED_SIGNATURE", error_message="signature verification failed")

    # SECURITY (Codex-confirmed HIGH 2026-08-19): the envelope `kid` is OUTSIDE the signed
    # payload, so flipping it kept the signature valid but pointed the revocation lookup at
    # the wrong namespace, bypassing revocation entirely. Bind to the kid of the key that
    # actually verified and require the envelope and payload kid to agree with it; use ONLY
    # this trusted kid for the downstream revocation lookup.
    trusted_kid = signing.kid_for(public_key)
    if kid != trusted_kid or str(payload.get("kid", "")) != trusted_kid:
        return VerifyResult(verified=False, status="invalid", kid=trusted_kid,
                            error_code="KID_MISMATCH",
                            error_message="envelope/payload kid does not match the verifying key")
    kid = trusted_kid

    # Hybrid: if the credential carries an ML-DSA-65 co-signature and a key is supplied, it must verify too.
    if not _hybrid_ok(credential, payload, mldsa_public_key):
        return VerifyResult(verified=False, status="invalid", kid=kid,
                            error_code="TAMPERED_SIGNATURE", error_message="ML-DSA co-signature failed")

    agent_did = payload.get("agent_did")
    scopes = payload.get("scopes") or []
    expires_at = payload.get("expires_at")

    if _is_expired(expires_at):
        return VerifyResult(verified=False, status="expired", agent_did=agent_did, scopes=scopes,
                            kid=kid, expires_at=expires_at, error_code="EXPIRED", error_message="credential has expired")

    if store is not None:
        try:
            rec = await store.get(kid=kid, passport_id=str(payload.get("passport_id")))
        except Exception:  # noqa: BLE001 — revocation store unreachable
            if strict:
                return VerifyResult(verified=False, status="indeterminate", agent_did=agent_did, scopes=scopes,
                                    kid=kid, expires_at=expires_at, error_code="REVOCATION_UNAVAILABLE",
                                    error_message="revocation store unavailable; failing closed")
            rec = None  # fail-open: signature + expiry already hold
        if rec is not None and rec.get("revoked_at") is not None:
            return VerifyResult(verified=False, status="revoked", agent_did=agent_did, scopes=scopes,
                                kid=kid, expires_at=expires_at, error_code="REVOKED",
                                error_message="credential has been revoked")

    if expected_agent_did and expected_agent_did != agent_did:
        return VerifyResult(verified=False, status="active", agent_did=agent_did, scopes=scopes, kid=kid,
                            expires_at=expires_at, error_code="AGENT_MISMATCH", error_message="agent_did does not match expected")
    if required_scope and required_scope not in scopes:
        return VerifyResult(verified=False, status="active", agent_did=agent_did, scopes=scopes, kid=kid,
                            expires_at=expires_at, error_code="SCOPE_NOT_GRANTED", error_message=f"scope {required_scope!r} not granted")

    return VerifyResult(verified=True, status="active", agent_did=agent_did, scopes=scopes,
                        spend_limit_microusd=payload.get("spend_limit_microusd"), kid=kid, expires_at=expires_at)


def verify_passport_chain(envelopes: list[str], public_key: bytes, *,
                          mldsa_public_key: bytes | None = None) -> ChainVerifyResult:
    """Verify an exported passport event chain offline: every signature, plus the hash links and seq order.

    Returns ``verified=False`` with ``first_bad_seq`` at the earliest entry whose signature, sequence, or
    ``prev_entry_hash`` link is wrong, so a single altered or dropped event is located, not just detected.
    With ``mldsa_public_key`` set, every entry's ML-DSA-65 co-signature is required.
    """
    prev = None
    for i, e in enumerate(envelopes):
        try:
            env = json.loads(signing.b64u_decode(e))
            payload = env["payload"]
            sig = signing.b64u_decode(env["sig"])
        except Exception:  # noqa: BLE001
            return ChainVerifyResult(False, i, i, "malformed entry")
        if payload.get("type") != ENTRY_TYPE or payload.get("canon_version") != CANON_VERSION:
            return ChainVerifyResult(False, i, i, "wrong entry type")
        if payload.get("seq") != i:
            return ChainVerifyResult(False, i, i, "seq out of order")
        if payload.get("prev_entry_hash") != prev:
            return ChainVerifyResult(False, i, i, "broken hash link")
        if not signing.verify_payload(payload, sig, public_key):
            return ChainVerifyResult(False, i, i, "bad signature")
        # SECURITY (Codex-caught 2026-08-19): a verifier that supplies an ML-DSA key is REQUIRING the
        # hybrid co-signature on every entry. sig2 is outside the signed payload, so "only check it
        # when present" let an attacker strip sig2 and downgrade the whole chain to Falcon-only. Require
        # sig2 to be present AND valid on each entry once a key is given (fail closed on a missing one).
        if mldsa_public_key is not None:
            if "sig2" not in env:
                return ChainVerifyResult(False, i, i, "missing ML-DSA co-signature")
            if not hybrid.verify_bytes(mldsa_public_key, rfc8785.dumps(payload), signing.b64u_decode(env["sig2"])):
                return ChainVerifyResult(False, i, i, "bad ML-DSA co-signature")
        prev = _prefixed(payload)
    return ChainVerifyResult(True, len(envelopes))
