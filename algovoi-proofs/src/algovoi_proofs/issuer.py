"""Proof issuance — builds a compliance receipt, gets a range proof, and signs the envelope."""
from __future__ import annotations

from algovoi_proofs import licensing

from datetime import datetime, timedelta, timezone

from algovoi_proofs import compliance, signing, zkp_envelope
from algovoi_proofs.prover import ProverClient


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class ProofIssuer:
    """Mints privacy-preserving compliance proofs.

    Injects the Falcon issuer key and a :class:`ProverClient` (the Bulletproofs service). No
    infrastructure dependency. The proof binds a content-addressed compliance receipt by hash and
    a range proof that the payer's score >= threshold — without revealing PII or the score.
    """

    def __init__(
        self,
        *,
        secret_key: bytes,
        public_key: bytes,
        prover: ProverClient,
        issuer_did: str = "did:web:issuer.example.com",
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        self.sk = secret_key
        self.pk = public_key
        self.prover = prover
        self.issuer_did = issuer_did
        self.kid = signing.kid_for(public_key)

    async def issue(
        self,
        *,
        payment: dict,
        screen_result: str = "ALLOW",
        score_milliunits: int,
        threshold_milliunits: int,
        ttl_secs: int = 604_800,
        jurisdiction_flags: list[str] | None = None,
    ) -> dict:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        exp = now + timedelta(seconds=ttl_secs)

        receipt = compliance.build_receipt(
            network=payment["chain"], recipient=payment.get("recipient", ""),
            screen_result=screen_result, screen_timestamp_ms=int(now.timestamp() * 1000),
            screen_provider_did=self.issuer_did, jurisdiction_flags=jurisdiction_flags,
        )
        chash = compliance.receipt_hash(receipt)

        proof = await self.prover.prove(score_milliunits, threshold_milliunits)  # raises ProverUnavailable
        commitment_b64 = proof.get("commitment_b64")
        proof_b64 = proof.get("proof_b64")
        if not commitment_b64 or not proof_b64:
            raise ValueError("range-proof service returned no proof")

        payload = zkp_envelope.build_payload(
            payment=payment, commitment_b64=commitment_b64, proof_b64=proof_b64,
            threshold_milliunits=threshold_milliunits, issuer_did=self.issuer_did,
            expires_at=_iso(exp), issued_at=_iso(now), compliance_receipt_hash=chash, screen_result=screen_result,
        )
        envelope = signing.make_envelope(payload, self.sk, self.pk)
        return {"proof_envelope": envelope, "compliance_receipt": receipt, "kid": self.kid, "expires_at": _iso(exp)}
