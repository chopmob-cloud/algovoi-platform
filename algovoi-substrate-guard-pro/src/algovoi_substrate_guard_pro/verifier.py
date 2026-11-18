"""Offline verification of signed admission receipts and the admission chain."""
from __future__ import annotations

import json

import rfc8785
from algovoi_agent_passport import signing

from algovoi_substrate_guard_pro import hybrid
from algovoi_substrate_guard_pro.ledger import CANON_VERSION, ENTRY_TYPE
from algovoi_substrate_guard_pro.models import ChainVerifyResult, VerifyDecisionResult
from algovoi_substrate_guard_pro.refs import _prefixed


def _open(receipt: str) -> tuple[dict, dict]:
    env = json.loads(signing.b64u_decode(receipt))
    payload = env["payload"]
    if not isinstance(payload, dict):
        raise ValueError("payload is not a JSON object")
    return payload, env


def _verify_sigs(payload: dict, env: dict, public_key: bytes,
                 mldsa_public_key: bytes | None) -> tuple[bool, bool]:
    """Return (signatures_ok, hybrid_verified). Falcon must always verify; if the envelope carries an
    ML-DSA-65 co-signature and an ``mldsa_public_key`` is supplied, that must verify too (fail-closed)."""
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
    return True, False


def verify_guard_decision(receipt: str, public_key: bytes, *,
                          mldsa_public_key: bytes | None = None) -> VerifyDecisionResult:
    """Verify one admission-decision receipt against the gate's public key (never raises)."""
    try:
        payload, env = _open(receipt)
    except Exception:  # noqa: BLE001
        return VerifyDecisionResult(verified=False, error="malformed admission receipt")
    kid = env.get("kid")
    if payload.get("type") != ENTRY_TYPE:
        return VerifyDecisionResult(verified=False, kid=kid, error="not a guard_decision receipt")
    ok, hyb = _verify_sigs(payload, env, public_key, mldsa_public_key)
    if not ok:
        return VerifyDecisionResult(verified=False, kid=kid, error="signature verification failed")
    return VerifyDecisionResult(
        verified=True, decision=payload.get("decision"), reject_code=payload.get("reject_code"),
        profile_ref=payload.get("profile_ref"), subject_ref=payload.get("subject_ref"),
        guard_decision_ref=payload.get("guard_decision_ref"), kid=kid,
        evaluated_at=payload.get("evaluated_at"), hybrid=hyb)


def verify_guard_chain(envelopes: list[str], public_key: bytes, *,
                       mldsa_public_key: bytes | None = None) -> ChainVerifyResult:
    """Verify a whole exported admission chain: every signature, plus the hash links and seq order.
    ``first_bad_seq`` points at the earliest entry whose signature, sequence, or ``prev_entry_hash`` link
    is wrong, so a single altered or dropped decision is located, not just detected."""
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


__all__ = ["verify_guard_decision", "verify_guard_chain"]
