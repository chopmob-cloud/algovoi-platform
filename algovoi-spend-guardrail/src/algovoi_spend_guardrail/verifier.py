"""Offline verification of signed spend-decision receipts and the decision chain."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import rfc8785
from algovoi_agent_passport import signing

from algovoi_spend_guardrail import hybrid
from algovoi_spend_guardrail.ledger import CANON_VERSION, ENTRY_TYPE
from algovoi_spend_guardrail.models import ChainVerifyResult, VerifyDecisionResult
from algovoi_spend_guardrail.refs import _prefixed


def _is_expired(iso: str | None) -> bool:
    if not iso:
        return False  # no freshness window stamped -> not subject to expiry
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return False
    return datetime.now(timezone.utc) >= exp


def _open(receipt: str) -> tuple[dict, dict]:
    """Return (payload, full_envelope_dict). Raises on malformed input."""
    env = json.loads(signing.b64u_decode(receipt))
    payload = env["payload"]
    if not isinstance(payload, dict):
        raise ValueError("payload is not a JSON object")
    return payload, env


def _verify_sigs(payload: dict, env: dict, public_key: bytes,
                 mldsa_public_key: bytes | None) -> tuple[bool, bool]:
    """Return (signatures_ok, hybrid_verified).

    The Falcon signature must always verify. If the envelope carries an ML-DSA-65 co-signature and an
    ``mldsa_public_key`` is supplied, that must verify too (fail-closed: a hybrid receipt presented to a
    hybrid-aware verifier requires both). A hybrid receipt verified without the ML-DSA key passes on
    Falcon alone with ``hybrid_verified=False``.
    """
    msg = rfc8785.dumps(payload)
    try:
        if not signing.verify_bytes(public_key, msg, signing.b64u_decode(env["sig"])):
            return False, False
    except Exception:  # noqa: BLE001
        return False, False
    if "sig2" in env:
        if mldsa_public_key is None:
            return True, False
        if not hybrid.verify_bytes(mldsa_public_key, msg, signing.b64u_decode(env["sig2"])):
            return False, False
        return True, True
    # SECURITY (2026-08-19): no sig2 present. If the verifier supplied an ML-DSA key it is REQUIRING the
    # hybrid co-signature, so a missing sig2 is a strip-downgrade and must fail closed (was: return
    # True, False -> silently accepted Falcon-only). With no key supplied, Falcon-only is fine.
    if mldsa_public_key is not None:
        return False, False
    return True, False


def verify_decision(decision_receipt: str, public_key: bytes, *,
                    mldsa_public_key: bytes | None = None) -> VerifyDecisionResult:
    """Verify a guardrail decision receipt against the guardrail's public key (never raises).

    A signature-valid receipt whose freshness window has passed verifies with ``expired=True`` — the
    signature is genuine but the decision is stale and must not be replayed. When ``mldsa_public_key`` is
    given and the receipt is hybrid, both signatures must verify and ``hybrid=True`` is reported.
    """
    try:
        payload, env = _open(decision_receipt)
    except Exception:  # noqa: BLE001
        return VerifyDecisionResult(verified=False, error="malformed decision receipt")
    kid = env.get("kid")
    if payload.get("type") != ENTRY_TYPE:
        return VerifyDecisionResult(verified=False, kid=kid, error="not a spend_decision receipt")
    ok, hyb = _verify_sigs(payload, env, public_key, mldsa_public_key)
    if not ok:
        return VerifyDecisionResult(verified=False, kid=kid, error="signature verification failed")
    return VerifyDecisionResult(
        verified=True, decision=payload.get("decision"), decision_id=payload.get("decision_id"),
        agent_did=payload.get("agent_did"), charge_id=payload.get("charge_id"),
        amount=payload.get("amount"), payee=payload.get("payee"), reasons=payload.get("reasons"),
        kid=kid, evaluated_at=payload.get("evaluated_at"), expires_at=payload.get("expires_at"),
        decision_ref=payload.get("decision_ref"), expired=_is_expired(payload.get("expires_at")),
        hybrid=hyb)


def verify_decision_chain(envelopes: list[str], public_key: bytes, *,
                          mldsa_public_key: bytes | None = None) -> ChainVerifyResult:
    """Verify a whole exported decision chain: every signature, plus the hash links and seq order.

    Returns ``verified=False`` with ``first_bad_seq`` pointing at the earliest entry whose signature,
    sequence, or ``prev_entry_hash`` link is wrong — so a single altered or dropped decision is located,
    not just detected. With ``mldsa_public_key`` set, every entry's ML-DSA-65 co-signature is required.
    """
    prev_hash = None
    all_hybrid = True
    for i, e in enumerate(envelopes):
        try:
            payload, env = _open(e)
        except Exception:  # noqa: BLE001
            return ChainVerifyResult(verified=False, count=i, first_bad_seq=i, error="malformed entry")
        if payload.get("type") != ENTRY_TYPE or payload.get("canon_version") != CANON_VERSION:
            return ChainVerifyResult(verified=False, count=i, first_bad_seq=i, error="wrong entry type")
        if payload.get("seq") != i:
            return ChainVerifyResult(verified=False, count=i, first_bad_seq=i, error="seq out of order")
        if payload.get("prev_entry_hash") != prev_hash:
            return ChainVerifyResult(verified=False, count=i, first_bad_seq=i, error="broken hash link")
        ok, hyb = _verify_sigs(payload, env, public_key, mldsa_public_key)
        if not ok:
            return ChainVerifyResult(verified=False, count=i, first_bad_seq=i, error="bad signature")
        all_hybrid = all_hybrid and hyb
        prev_hash = _prefixed(payload)
    return ChainVerifyResult(verified=True, count=len(envelopes),
                             hybrid=(all_hybrid if envelopes else False))
