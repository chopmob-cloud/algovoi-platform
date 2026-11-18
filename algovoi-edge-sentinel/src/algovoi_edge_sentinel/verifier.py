"""Offline verification of signed edge-decision receipts and the edge chain."""
from __future__ import annotations

import json

import rfc8785
from algovoi_agent_passport import signing

from algovoi_edge_sentinel import hybrid
from algovoi_edge_sentinel.ledger import CANON_VERSION, ENTRY_TYPE
from algovoi_edge_sentinel.models import ChainVerifyResult, VerifyDecisionResult
from algovoi_edge_sentinel.refs import _prefixed


def _open(receipt: str) -> tuple[dict, dict]:
    env = json.loads(signing.b64u_decode(receipt))
    payload = env["payload"]
    if not isinstance(payload, dict):
        raise ValueError("payload is not a JSON object")
    return payload, env


def _verify_sigs(payload: dict, env: dict, public_key: bytes,
                 mldsa_public_key: bytes | None) -> tuple[bool, bool]:
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


def verify_edge_decision(receipt: str, public_key: bytes, *,
                         mldsa_public_key: bytes | None = None) -> VerifyDecisionResult:
    """Verify one edge-decision receipt against the sentinel's public key (never raises)."""
    try:
        payload, env = _open(receipt)
    except Exception:  # noqa: BLE001
        return VerifyDecisionResult(verified=False, error="malformed edge receipt")
    kid = env.get("kid")
    if payload.get("type") != ENTRY_TYPE:
        return VerifyDecisionResult(verified=False, kid=kid, error="not an edge_decision receipt")
    ok, hyb = _verify_sigs(payload, env, public_key, mldsa_public_key)
    if not ok:
        return VerifyDecisionResult(verified=False, kid=kid, error="signature verification failed")
    return VerifyDecisionResult(
        verified=True, decision=payload.get("decision"), check=payload.get("check"),
        reason_code=payload.get("reason_code"), policy_ref=payload.get("policy_ref"),
        subject_ref=payload.get("subject_ref"), edge_decision_ref=payload.get("edge_decision_ref"),
        kid=kid, evaluated_at=payload.get("evaluated_at"), hybrid=hyb)


def verify_edge_chain(envelopes: list[str], public_key: bytes, *,
                      mldsa_public_key: bytes | None = None) -> ChainVerifyResult:
    """Verify a whole exported edge chain: every signature, plus the hash links and seq order."""
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


__all__ = ["verify_edge_decision", "verify_edge_chain"]
