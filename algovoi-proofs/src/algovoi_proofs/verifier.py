"""Public proof verification: issuer signature + optional range-proof re-check + compliance binding."""
from __future__ import annotations

from algovoi_proofs import compliance, signing, zkp_envelope
from algovoi_proofs.models import VerifyResult
from algovoi_proofs.prover import ProverClient, ProverUnavailable


async def verify_proof(
    proof_envelope: str,
    public_key: bytes,
    *,
    prover: ProverClient | None = None,
    verify_range_proof: bool = True,
    compliance_receipt: dict | None = None,
) -> VerifyResult:
    """Verify a proof envelope (never raises).

    1. Falcon signature + structural checks on the envelope.
    2. Optional: re-check the Bulletproofs range proof against ``prover``.
    3. Optional: confirm a supplied compliance receipt hashes to the bound value.
    """
    res = zkp_envelope.verify(proof_envelope, public_key)
    if not res["valid"]:
        return VerifyResult(verified=False, failure_reason=res.get("failure_reason"))
    payload = res["payload"]

    range_proof_valid: bool | None = None
    if verify_range_proof and prover is not None:
        try:
            rr = await prover.verify_range(
                payload.get("commitment_b64", ""), payload.get("proof_b64", ""),
                int(payload.get("threshold_milliunits", 0)))
            range_proof_valid = bool(rr.get("valid"))
        except ProverUnavailable:
            range_proof_valid = None  # could not check; surfaced as null, not a pass

    compliance_verified: bool | None = None
    bound = payload.get("compliance_receipt_hash")
    if compliance_receipt is not None and bound:
        try:
            compliance_verified = compliance.receipt_hash(compliance_receipt) == bound
        except Exception:  # noqa: BLE001
            compliance_verified = False

    return VerifyResult(
        verified=True,
        payment_id=payload.get("payment_id"),
        chain=payload.get("chain"),
        amount_microusd=payload.get("amount_microusd"),
        tx_id=payload.get("tx_id"),
        threshold_milliunits=int(payload.get("threshold_milliunits", 0)),
        compliance_verified=compliance_verified,
        range_proof_valid=range_proof_valid,
        issuer_did=payload.get("bench_issuer"),
        kid=signing.kid_for(public_key),
        expires_at=payload.get("expires_at"),
    )
