"""Unit tests for algovoi-compliance-gate."""
from __future__ import annotations

import hashlib
import json

import pytest
import rfc8785
from fastapi.testclient import TestClient

from algovoi_compliance_gate import (
    AllowAllScreener,
    ComplianceGate,
    DenylistScreener,
    bearer_token_auth,
    create_app,
    signing,
    verify_compliance_receipt,
)

PROOFS_RECEIPT_KEYS = {
    "canon_version", "jurisdiction_flags", "payer_ref",
    "screen_provider_did", "screen_result", "screen_timestamp_ms",
}


@pytest.fixture
def keys():
    pk, sk = signing.generate_keypair()
    return pk, sk


def _gate(pk, sk, screener=None):
    return ComplianceGate(secret_key=sk, public_key=pk,
                          screener=screener or AllowAllScreener("did:web:screener"), gate_did="did:web:gate")


async def test_certify_allow_and_proofs_compatible(keys):
    pk, sk = keys
    out = await _gate(pk, sk).screen_and_certify(network="base", address="0xAbC123")
    r = out["receipt"]
    assert out["result"] == "ALLOW"
    assert set(r.keys()) == PROOFS_RECEIPT_KEYS                     # exact algovoi-proofs receipt shape
    assert r["canon_version"] == "jcs-rfc8785-v1" and r["screen_result"] == "ALLOW"
    vr = verify_compliance_receipt(out["receipt_envelope"], pk)
    assert vr.verified and vr.screen_result == "ALLOW" and vr.payer_ref == out["payer_ref"]
    # receipt_hash is the JCS content hash that algovoi-proofs binds to:
    assert out["receipt_hash"] == "sha256:" + hashlib.sha256(rfc8785.dumps(r)).hexdigest()


async def test_no_pii_in_certified_output(keys):
    pk, sk = keys
    addr = "0xDEADBEEFcafeSECRETADDRESS"
    out = await _gate(pk, sk).screen_and_certify(network="base", address=addr)
    payload, _, _ = signing.open_envelope(out["receipt_envelope"])
    blob = json.dumps(out["receipt"]) + out["receipt_envelope"] + out["payer_ref"] + json.dumps(payload)
    assert addr not in blob                                         # cleartext address never leaves
    assert out["payer_ref"] == "sha256:" + hashlib.sha256(f"base:{addr}".encode()).hexdigest()


async def test_denylist_screener_three_states(keys):
    pk, sk = keys
    g = _gate(pk, sk, DenylistScreener(deny={"0xbad"}, refer={"0xmaybe"}, provider_did="did:web:scr"))
    assert (await g.screen_and_certify(network="base", address="0xBAD"))["result"] == "DENY"     # case-insensitive
    assert (await g.screen_and_certify(network="base", address="0xMaybe"))["result"] == "REFER"
    assert (await g.screen_and_certify(network="base", address="0xgood"))["result"] == "ALLOW"


async def test_payer_ref_deterministic(keys):
    pk, sk = keys
    g = _gate(pk, sk)
    a = (await g.screen_and_certify(network="base", address="0xabc"))["payer_ref"]
    b = (await g.screen_and_certify(network="base", address="0xabc"))["payer_ref"]
    assert a == b


async def test_verify_tampered_rejected(keys):
    pk, sk = keys
    out = await _gate(pk, sk).screen_and_certify(network="base", address="0xabc")
    env = json.loads(signing.b64u_decode(out["receipt_envelope"]))
    env["payload"]["screen_result"] = "DENY"                       # tamper (still a valid enum) → sig breaks
    forged = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    assert verify_compliance_receipt(forged, pk).verified is False


async def test_verify_wrong_key_rejected(keys):
    pk, sk = keys
    pk2, _ = signing.generate_keypair()
    out = await _gate(pk, sk).screen_and_certify(network="base", address="0xabc")
    assert verify_compliance_receipt(out["receipt_envelope"], pk2).verified is False


# ---- app -----------------------------------------------------------------------------------

def test_app_health_and_pqc_keys(keys):
    pk, sk = keys
    client = TestClient(create_app(_gate(pk, sk), public_key=pk))
    assert client.get("/health").json()["kid"] == signing.kid_for(pk)
    assert client.get("/.well-known/pqc-keys.json").json()["keys"][0]["alg"] == "Falcon-1024"


def test_app_screen_then_verify(keys):
    pk, sk = keys
    client = TestClient(create_app(_gate(pk, sk, DenylistScreener(deny={"0xbad"})), public_key=pk))
    r = client.post("/v1/compliance/screen", json={"network": "base", "address": "0xBAD"}).json()
    assert r["result"] == "DENY"
    v = client.post("/v1/compliance/verify", json={"receipt_envelope": r["receipt_envelope"]}).json()
    assert v["verified"] is True and v["screen_result"] == "DENY"


def test_app_screen_auth_required(keys):
    pk, sk = keys
    client = TestClient(create_app(_gate(pk, sk), public_key=pk, auth_dependency=bearer_token_auth("secret")))
    assert client.post("/v1/compliance/screen", json={"network": "base", "address": "0xabc"}).status_code == 401


async def test_risk_check_fails_safe_on_missing_score():
    """Security fix 2026-08-19: the risk check REFERs (not ALLOWs) when no risk_score is supplied, so a
    caller can't skip the risk gate by omitting the signal."""
    from algovoi_compliance_gate.checks import RiskThresholdCheck
    chk = RiskThresholdCheck()
    # no context / no score -> REFER (was ALLOW)
    r = await chk.run(network="base", address="0x", amount_microusd=None, context=None,
                      policy={"deny_risk": 900, "refer_risk": 600})
    assert r.result == "REFER" and r.reason_code == "RISK_UNAVAILABLE"
    # a real low score still clears
    r2 = await chk.run(network="base", address="0x", amount_microusd=None, context={"risk_score": 10},
                       policy={"deny_risk": 900, "refer_risk": 600})
    assert r2.result == "ALLOW"
