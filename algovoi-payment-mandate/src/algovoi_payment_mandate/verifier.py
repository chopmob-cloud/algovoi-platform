"""Public mandate verification: signature, type, expiry, revocation, and optional assertions."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import rfc8785

from algovoi_payment_mandate import hybrid, signing
from algovoi_payment_mandate.charge_ledger import CANON_VERSION, ENTRY_TYPE
from algovoi_payment_mandate.models import VerifyResult
from algovoi_payment_mandate.store import MandateStore


def _prefixed(value) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _hybrid_ok(mandate: str, payload: dict, mldsa_public_key: bytes | None) -> bool:
    if mldsa_public_key is None:
        return True
    # SECURITY (Codex-confirmed 2026-08-19): when a verifier supplies an ML-DSA key it is
    # REQUIRING the hybrid co-signature. sig2 lives outside the signed payload, so a missing
    # or undecodable sig2 must FAIL (was: return True), else an attacker strips sig2 and
    # downgrades hybrid protection to Falcon-only.
    try:
        env = json.loads(signing.b64u_decode(mandate))
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


async def verify_mandate(
    mandate: str,
    public_key: bytes,
    *,
    store: MandateStore | None = None,
    required_scope: str | None = None,
    expected_payee: str | None = None,
    strict: bool = False,
    mldsa_public_key: bytes | None = None,
) -> VerifyResult:
    """Verify a payment mandate. Returns a :class:`VerifyResult` (never raises).

    Order: envelope decode -> type check -> Falcon signature -> expiry -> revocation (if a store is
    given) -> optional expected_payee / required_scope assertions.

    ``strict`` fails *closed* when a configured revocation store is unreachable (``REVOCATION_UNAVAILABLE``)
    instead of the default fail-*open* behaviour — the symmetric control to ``verify_passport(strict=...)``.
    """
    try:
        payload, sig, kid = signing.open_envelope(mandate)
    except Exception:  # noqa: BLE001
        return VerifyResult(verified=False, status="invalid",
                            error_code="INVALID_MANDATE", error_message="malformed mandate envelope")

    if payload.get("type") != "payment_mandate":
        return VerifyResult(verified=False, status="invalid", kid=kid,
                            error_code="WRONG_TYPE", error_message="not a payment_mandate envelope")

    if not signing.verify_payload(payload, sig, public_key):
        return VerifyResult(verified=False, status="invalid", kid=kid,
                            error_code="TAMPERED_SIGNATURE", error_message="signature verification failed")

    # SECURITY (Codex-confirmed CRITICAL 2026-08-19): the envelope `kid` is OUTSIDE the
    # signed payload, so flipping it kept the signature valid but pointed the revocation
    # (and, in the charge path, the spend-cap ledger) at the wrong namespace, bypassing
    # both. Bind to the kid of the key that actually verified, and require the envelope
    # and payload kid to agree with it. Use ONLY this trusted kid downstream.
    trusted_kid = signing.kid_for(public_key)
    if kid != trusted_kid or str(payload.get("kid", "")) != trusted_kid:
        return VerifyResult(verified=False, status="invalid", kid=trusted_kid,
                            error_code="KID_MISMATCH",
                            error_message="envelope/payload kid does not match the verifying key")
    kid = trusted_kid

    # Hybrid: if the mandate carries an ML-DSA-65 co-signature and a key is supplied, it must verify too.
    if not _hybrid_ok(mandate, payload, mldsa_public_key):
        return VerifyResult(verified=False, status="invalid", kid=kid,
                            error_code="TAMPERED_SIGNATURE", error_message="ML-DSA co-signature failed")

    fields = dict(
        mandate_id=payload.get("mandate_id"), payer=payload.get("payer"), payee=payload.get("payee"),
        asset=payload.get("asset"), chain=payload.get("chain"), max_amount=payload.get("max_amount"),
        period=payload.get("period"), max_per_charge=payload.get("max_per_charge"),
        scope=payload.get("scope") or [], kid=kid, expires_at=payload.get("expires_at"),
    )

    if _is_expired(payload.get("expires_at")):
        return VerifyResult(verified=False, status="expired",
                            error_code="EXPIRED", error_message="mandate has expired", **fields)

    if store is not None:
        try:
            rec = await store.get(kid=kid, mandate_id=str(payload.get("mandate_id")))
        except Exception:  # noqa: BLE001 — revocation store unreachable
            if strict:
                return VerifyResult(verified=False, status="indeterminate",
                                    error_code="REVOCATION_UNAVAILABLE",
                                    error_message="revocation store unavailable; failing closed", **fields)
            rec = None  # fail-open: signature + expiry already hold
        if rec is not None and rec.get("revoked_at") is not None:
            return VerifyResult(verified=False, status="revoked",
                                error_code="REVOKED", error_message="mandate has been revoked", **fields)

    if expected_payee and expected_payee != fields["payee"]:
        return VerifyResult(verified=False, status="active",
                            error_code="PAYEE_MISMATCH", error_message="payee does not match expected", **fields)
    if required_scope and required_scope not in fields["scope"]:
        return VerifyResult(verified=False, status="active",
                            error_code="SCOPE_NOT_GRANTED", error_message=f"scope {required_scope!r} not granted", **fields)

    return VerifyResult(verified=True, status="active", **fields)


def verify_mandate_chain(envelopes: list[str], public_key: bytes, *,
                         mldsa_public_key: bytes | None = None) -> ChainVerifyResult:
    """Verify an exported mandate charge chain offline: every signature, plus hash links and seq order.

    ``first_bad_seq`` points at the earliest entry whose signature, sequence, or ``prev_entry_hash`` link
    is wrong. With ``mldsa_public_key`` set, every entry's ML-DSA-65 co-signature is required.
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
        # SECURITY (Codex-caught 2026-08-19): a verifier supplying an ML-DSA key is REQUIRING the hybrid
        # co-signature on every entry. sig2 is outside the signed payload, so "only check it when present"
        # let an attacker strip sig2 and downgrade the chain to Falcon-only. Require sig2 present AND valid
        # on each entry once a key is given (fail closed on a missing one).
        if mldsa_public_key is not None:
            if "sig2" not in env:
                return ChainVerifyResult(False, i, i, "missing ML-DSA co-signature")
            if not hybrid.verify_bytes(mldsa_public_key, rfc8785.dumps(payload), signing.b64u_decode(env["sig2"])):
                return ChainVerifyResult(False, i, i, "bad ML-DSA co-signature")
        prev = _prefixed(payload)
    return ChainVerifyResult(True, len(envelopes))
