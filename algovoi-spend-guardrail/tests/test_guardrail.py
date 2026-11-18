"""Unit tests for algovoi-spend-guardrail (composes Agent Passport + Payment Mandate)."""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from algovoi_agent_passport import InMemoryStore as PStore, PassportIssuer, signing
from algovoi_payment_mandate import InMemoryStore as MStore, MandateIssuer

from algovoi_spend_guardrail import (
    Policy,
    SpendGuardrail,
    bearer_token_auth,
    create_app,
    verify_decision,
)

USDC = 1_000_000


@pytest.fixture
def env():
    ppk, psk = signing.generate_keypair()
    mpk, msk = signing.generate_keypair()
    gpk, gsk = signing.generate_keypair()
    pstore = PStore()
    mi = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore(), issuer_did="did:web:mi")
    pi = PassportIssuer(secret_key=psk, public_key=ppk, store=pstore, issuer_did="did:web:pi")
    return {"ppk": ppk, "gpk": gpk, "gsk": gsk, "pi": pi, "mi": mi, "pstore": pstore}


def _guard(env, policy=None):
    return SpendGuardrail(passport_public_key=env["ppk"], mandate_issuer=env["mi"],
                          decision_secret_key=env["gsk"], decision_public_key=env["gpk"],
                          policy=policy, passport_store=env["pstore"], guardrail_did="did:web:guard")


async def _issue(env, *, scopes=("payments.send",), spend_limit=None, max_amount=50 * USDC, payee="merchant:acme"):
    cred = (await env["pi"].issue(agent_did="did:web:agent.example.com", scopes=list(scopes),
                                  spend_limit_microusd=spend_limit))["credential"]
    mandate = (await env["mi"].issue(payer="acct:alice", payee=payee, max_amount=max_amount, period="month"))["mandate"]
    return cred, mandate


# ---- decision logic ------------------------------------------------------------------------

async def test_allow_happy_path(env):
    g = _guard(env, Policy(required_scope="payments.send"))
    cred, mandate = await _issue(env)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=20 * USDC, payee="merchant:acme")
    assert d.allowed and d.decision == "ALLOW" and d.remaining_this_period == 30 * USDC
    vr = verify_decision(d.decision_receipt, env["gpk"])
    assert vr.verified and vr.decision == "ALLOW" and vr.charge_id == "c1"


async def test_deny_per_tx_policy_does_not_consume_mandate(env):
    g = _guard(env, Policy(max_amount_per_tx=10 * USDC))
    cred, mandate = await _issue(env, max_amount=50 * USDC)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=20 * USDC, payee="merchant:acme")
    assert not d.allowed and "policy:per_tx_cap_exceeded" in d.reasons
    # the mandate ledger must NOT have been consumed by the policy-denied charge:
    d2 = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c2", amount=10 * USDC, payee="merchant:acme")
    assert d2.allowed and d2.remaining_this_period == 40 * USDC


async def test_deny_payee_not_allowed(env):
    g = _guard(env, Policy(allowed_payees={"merchant:acme"}))
    cred, mandate = await _issue(env)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=5 * USDC, payee="merchant:evil")
    assert not d.allowed and "policy:payee_not_allowed" in d.reasons


async def test_asset_allowlist_fails_closed_on_unspecified_asset(env):
    """An asset allow-list must deny a charge with no declared asset — omitting `asset` must not
    bypass the allow-list (security fix 2026-08-19)."""
    g = _guard(env, Policy(allowed_assets={"USDC"}))
    cred, mandate = await _issue(env)
    # asset omitted -> cannot be confirmed in-list -> DENY (was: allow-list skipped entirely)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=5 * USDC, payee="merchant:acme")
    assert not d.allowed and "policy:asset_not_allowed" in d.reasons
    # a declared, in-list asset still passes the policy gate
    d2 = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c2",
                           amount=5 * USDC, payee="merchant:acme", asset="USDC")
    assert d2.allowed


async def test_deny_scope_missing(env):
    g = _guard(env, Policy(required_scope="payments.refund"))
    cred, mandate = await _issue(env, scopes=("payments.send",))
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=5 * USDC, payee="merchant:acme")
    assert not d.allowed and "policy:scope_missing" in d.reasons


async def test_deny_passport_spend_limit(env):
    g = _guard(env)
    cred, mandate = await _issue(env, spend_limit=10 * USDC)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=20 * USDC, payee="merchant:acme")
    assert not d.allowed and "passport:spend_limit_exceeded" in d.reasons


async def test_deny_mandate_period_cap(env):
    g = _guard(env)
    cred, mandate = await _issue(env, max_amount=15 * USDC)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=20 * USDC, payee="merchant:acme")
    assert not d.allowed and any(r.startswith("mandate:") for r in d.reasons)


async def test_deny_revoked_passport(env):
    g = _guard(env)
    out = await env["pi"].issue(agent_did="did:web:agent.example.com", scopes=["payments.send"])
    mandate = (await env["mi"].issue(payer="acct:alice", payee="merchant:acme", max_amount=50 * USDC, period="month"))["mandate"]
    await env["pi"].revoke(passport_id=out["passport_id"])
    d = await g.authorize(passport_credential=out["credential"], mandate=mandate, charge_id="c1", amount=5 * USDC, payee="merchant:acme")
    assert not d.allowed and "passport:REVOKED" in d.reasons


async def test_decision_receipt_wrong_key_rejected(env):
    g = _guard(env)
    cred, mandate = await _issue(env)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=5 * USDC, payee="merchant:acme")
    wpk, _ = signing.generate_keypair()
    assert verify_decision(d.decision_receipt, wpk).verified is False


# ---- app -----------------------------------------------------------------------------------

def test_app_health_and_pqc_keys(env):
    client = TestClient(create_app(_guard(env), decision_public_key=env["gpk"]))
    assert client.get("/health").json()["kid"] == signing.kid_for(env["gpk"])
    assert client.get("/.well-known/pqc-keys.json").json()["keys"][0]["kid"] == signing.kid_for(env["gpk"])


def test_app_authorize_then_verify(env):
    cred, mandate = asyncio.run(_issue(env))
    client = TestClient(create_app(_guard(env, Policy(required_scope="payments.send")), decision_public_key=env["gpk"]))
    r = client.post("/v1/guardrail/authorize", json={
        "passport_credential": cred, "mandate": mandate, "charge_id": "c1",
        "amount": 20_000_000, "payee": "merchant:acme"}).json()
    assert r["allowed"] is True and r["decision"] == "ALLOW"
    v = client.post("/v1/guardrail/verify-decision", json={"decision_receipt": r["decision_receipt"]}).json()
    assert v["verified"] is True and v["decision"] == "ALLOW"


def test_app_authorize_auth_required(env):
    client = TestClient(create_app(_guard(env), decision_public_key=env["gpk"],
                                   auth_dependency=bearer_token_auth("secret")))
    body = {"passport_credential": "x", "mandate": "y", "charge_id": "c1", "amount": 1, "payee": "p"}
    assert client.post("/v1/guardrail/authorize", json=body).status_code == 401
