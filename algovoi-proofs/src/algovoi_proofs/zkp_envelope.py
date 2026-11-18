"""
Self-contained ZKP receipt envelope: build the (unsigned) payload and verify the signed envelope.

Matches the algovoi-zkp-receipt wire format so proofs interoperate with the AlgoVoi platform.
A proof is a Falcon-1024-signed envelope binding a payment to a Bulletproofs range proof
(score >= threshold) without revealing the score.
"""
from __future__ import annotations

import base64
import json

from algovoi_proofs import signing

COMMITMENT_BYTES = 32
PROOF_MIN_BYTES = 200
PROOF_MAX_BYTES = 900


def build_payload(
    *,
    payment: dict,
    commitment_b64: str,
    proof_b64: str,
    threshold_milliunits: int,
    issuer_did: str,
    expires_at: str,
    issued_at: str,
    compliance_receipt_hash: str | None = None,
    screen_result: str | None = None,
) -> dict:
    payload = {
        "type": "zkp_receipt", "version": "1",
        "payment_id": payment["payment_id"], "chain": payment["chain"],
        "amount_microusd": payment["amount_microusd"], "recipient": payment.get("recipient", ""),
        "tx_id": payment["tx_id"], "settled_at": payment.get("settled_at", ""),
        "atb_cert_version": "2", "bench_issuer": issuer_did,
        "commitment_b64": commitment_b64, "proof_b64": proof_b64,
        "threshold_milliunits": threshold_milliunits,
        "expires_at": expires_at, "issued_at": issued_at,
    }
    if compliance_receipt_hash:
        payload["compliance_receipt_hash"] = compliance_receipt_hash
    if screen_result:
        payload["screen_result"] = screen_result
    return payload


def _b64len(s: str) -> int | None:
    try:
        return len(base64.b64decode(s + "=" * ((-len(s)) % 4)))
    except Exception:  # noqa: BLE001
        return None


def verify(envelope_b64: str, public_key: bytes) -> dict:
    """Verify a proof envelope. Returns ``{'valid': bool, 'payload'?: dict, 'failure_reason'?: str}``."""
    try:
        env = json.loads(signing.b64u_decode(envelope_b64))
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "failure_reason": f"envelope_decode:{e}"}
    payload = env.get("payload")
    sig_b64 = env.get("sig")
    alg = env.get("alg")
    kid = env.get("kid")
    if not isinstance(payload, dict) or not isinstance(sig_b64, str) or alg != "Falcon-1024" or not isinstance(kid, str):
        return {"valid": False, "failure_reason": "envelope_shape"}
    if payload.get("type") != "zkp_receipt" or str(payload.get("version", "")) != "1":
        return {"valid": False, "failure_reason": "wrong_type_or_version"}
    if not payload.get("payment_id") or not payload.get("chain") or payload.get("amount_microusd") is None or not payload.get("tx_id"):
        return {"valid": False, "failure_reason": "missing_receipt_fields"}
    commitment = payload.get("commitment_b64", "")
    proof = payload.get("proof_b64", "")
    if not commitment or not proof:
        return {"valid": False, "failure_reason": "missing_zkp_fields"}
    cl, pl = _b64len(commitment), _b64len(proof)
    if cl != COMMITMENT_BYTES or pl is None or not (PROOF_MIN_BYTES <= pl <= PROOF_MAX_BYTES):
        return {"valid": False, "failure_reason": "zkp_structural"}
    if kid != signing.kid_for(public_key):
        return {"valid": False, "failure_reason": "kid_mismatch"}
    if not signing.verify_payload(payload, signing.b64u_decode(sig_b64), public_key):
        return {"valid": False, "failure_reason": "bad_signature"}
    return {"valid": True, "payload": payload}
