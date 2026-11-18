"""Unit tests for algovoi-proofs (no live prover required — the prover is stubbed)."""
from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from algovoi_proofs import signing
from algovoi_proofs.app import create_app
from algovoi_proofs.issuer import ProofIssuer
from algovoi_proofs.models import IssueRequest
from algovoi_proofs.verifier import verify_proof

# Bulletproofs over Ristretto255: 32-byte commitment, ~672-byte aggregated range proof.
COMMITMENT = base64.b64encode(b"\x01" * 32).decode()
PROOF = base64.b64encode(b"\x02" * 672).decode()

PAYMENT = {
    "payment_id": "pay_1", "chain": "algorand", "amount_microusd": 1_500_000,
    "recipient": "WHGJFM33EXAMPLERECIPIENT", "tx_id": "TX123", "settled_at": "2026-06-01T00:00:00Z",
}


class FakeProver:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok

    async def prove(self, score: int, threshold: int) -> dict:
        return {"commitment_b64": COMMITMENT, "proof_b64": PROOF}

    async def verify_range(self, c: str, p: str, t: int) -> dict:
        return {"valid": self.ok}


@pytest.fixture
def keys():
    pk, sk = signing.generate_keypair()
    return pk, sk


def _issuer(pk, sk, prover=None):
    return ProofIssuer(secret_key=sk, public_key=pk, prover=prover or FakeProver(), issuer_did="did:web:test")


async def test_issue_verify_roundtrip(keys):
    pk, sk = keys
    out = await _issuer(pk, sk).issue(
        payment=PAYMENT, screen_result="ALLOW", score_milliunits=800, threshold_milliunits=600)
    res = await verify_proof(out["proof_envelope"], pk)
    assert res.verified
    assert res.payment_id == "pay_1"
    assert res.chain == "algorand"
    assert res.amount_microusd == 1_500_000
    assert res.threshold_milliunits == 600
    assert res.kid == signing.kid_for(pk)
    assert res.issuer_did == "did:web:test"


async def test_compliance_binding(keys):
    pk, sk = keys
    out = await _issuer(pk, sk).issue(
        payment=PAYMENT, screen_result="REFER", score_milliunits=700, threshold_milliunits=500)
    res = await verify_proof(out["proof_envelope"], pk, compliance_receipt=out["compliance_receipt"])
    assert res.compliance_verified is True

    tampered = dict(out["compliance_receipt"])
    tampered["screen_result"] = "ALLOW"
    res2 = await verify_proof(out["proof_envelope"], pk, compliance_receipt=tampered)
    assert res2.compliance_verified is False


async def test_range_proof_recheck(keys):
    pk, sk = keys
    out = await _issuer(pk, sk).issue(
        payment=PAYMENT, screen_result="ALLOW", score_milliunits=800, threshold_milliunits=600)
    res = await verify_proof(out["proof_envelope"], pk, prover=FakeProver(ok=True))
    assert res.range_proof_valid is True
    res2 = await verify_proof(out["proof_envelope"], pk, prover=FakeProver(ok=False))
    assert res2.range_proof_valid is False
    res3 = await verify_proof(out["proof_envelope"], pk, verify_range_proof=False)
    assert res3.range_proof_valid is None


async def test_tampered_envelope_rejected(keys):
    pk, sk = keys
    out = await _issuer(pk, sk).issue(
        payment=PAYMENT, screen_result="ALLOW", score_milliunits=800, threshold_milliunits=600)
    decoded = json.loads(signing.b64u_decode(out["proof_envelope"]))
    decoded["payload"]["amount_microusd"] = 999_999_999  # tamper after signing
    tampered = signing.b64u_encode(json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode())
    res = await verify_proof(tampered, pk)
    assert res.verified is False
    assert res.failure_reason == "bad_signature"


async def test_wrong_public_key_rejected(keys):
    pk, sk = keys
    pk2, _ = signing.generate_keypair()
    out = await _issuer(pk, sk).issue(
        payment=PAYMENT, screen_result="ALLOW", score_milliunits=800, threshold_milliunits=600)
    res = await verify_proof(out["proof_envelope"], pk2)
    assert res.verified is False
    assert res.failure_reason in ("kid_mismatch", "bad_signature")


async def test_malformed_envelope(keys):
    pk, _ = keys
    res = await verify_proof("not-a-valid-envelope!!!", pk)
    assert res.verified is False


def test_screen_result_validation():
    with pytest.raises(Exception):
        IssueRequest(payment=PAYMENT, screen_result="MAYBE", score_milliunits=1, threshold_milliunits=1)


def test_app_health_and_pqc_keys(keys):
    pk, sk = keys
    app = create_app(secret_key=sk, public_key=pk, prover_url="http://127.0.0.1:1", issuer_did="did:web:test")
    client = TestClient(app)
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["kid"] == signing.kid_for(pk)
    doc = client.get("/.well-known/pqc-keys.json").json()
    assert doc["keys"][0]["kid"] == signing.kid_for(pk)
    assert doc["keys"][0]["alg"] == "Falcon-1024"


def test_app_issue_503_when_prover_down(keys):
    pk, sk = keys
    app = create_app(secret_key=sk, public_key=pk, prover_url="http://127.0.0.1:1", issuer_did="did:web:test")
    client = TestClient(app)
    r = client.post("/v1/proofs/issue", json={
        "payment": PAYMENT, "screen_result": "ALLOW", "score_milliunits": 800, "threshold_milliunits": 600})
    assert r.status_code == 503


def test_app_issue_auth_required(keys):
    pk, sk = keys
    app = create_app(secret_key=sk, public_key=pk, prover_url="http://127.0.0.1:1", api_token="secret-token")
    client = TestClient(app)
    body = {"payment": PAYMENT, "screen_result": "ALLOW", "score_milliunits": 800, "threshold_milliunits": 600}
    assert client.post("/v1/proofs/issue", json=body).status_code == 401
    assert client.post("/v1/proofs/issue", headers={"Authorization": "Bearer wrong"}, json=body).status_code == 403


def test_app_verify_portal(keys):
    pk, sk = keys
    app = create_app(secret_key=sk, public_key=pk, prover_url="http://127.0.0.1:1")
    r = TestClient(app).get("/proofs/verify")
    assert r.status_code == 200 and "Proofs" in r.text
