"""Cap C: the REFER (review/step-up) verdict and rolling-window velocity caps."""
from __future__ import annotations

import pytest

from algovoi_agent_passport import InMemoryStore as PStore, PassportIssuer, signing
from algovoi_payment_mandate import InMemoryStore as MStore, MandateIssuer

from algovoi_spend_guardrail import Policy, SpendGuardrail, refs, verify_decision_chain

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


def _guard(env, policy):
    return SpendGuardrail(passport_public_key=env["ppk"], mandate_issuer=env["mi"],
                          decision_secret_key=env["gsk"], decision_public_key=env["gpk"],
                          policy=policy, passport_store=env["pstore"], guardrail_did="did:web:guard")


async def _issue(env, *, max_amount=50 * USDC, payee="merchant:acme"):
    cred = (await env["pi"].issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    mandate = (await env["mi"].issue(payer="acct:alice", payee=payee, max_amount=max_amount, period="month"))["mandate"]
    return cred, mandate


# ---- REFER ------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_amount_above_soft_threshold_refers_without_consuming_mandate(env):
    g = _guard(env, Policy(refer_above_amount=10 * USDC))
    cred, mandate = await _issue(env, max_amount=20 * USDC)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="r1",
                          amount=15 * USDC, payee="merchant:acme")
    assert d.decision == "REFER" and d.allowed is False
    assert d.reasons == ["policy:amount_needs_review"]
    assert refs.is_ref(d.decision_ref)            # REFER is content-addressed too (commercial-only verdict)
    # the mandate was NOT consumed: a later ALLOW (under the soft threshold) sees the full cap intact,
    # so its remaining_this_period reflects only its own draw, not the 15 USDC that was referred.
    ok = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="r2",
                           amount=5 * USDC, payee="merchant:acme")
    assert ok.allowed and ok.decision == "ALLOW"
    assert ok.remaining_this_period == 15 * USDC   # 20 cap - 5 spent (the REFER drew nothing)


@pytest.mark.asyncio
async def test_flagged_payee_refers(env):
    g = _guard(env, Policy(refer_payees={"merchant:watchme"}))
    cred, mandate = await _issue(env, payee="merchant:watchme")
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="r1",
                          amount=1 * USDC, payee="merchant:watchme")
    assert d.decision == "REFER" and d.reasons == ["policy:payee_needs_review"]


# ---- velocity ---------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rolling_velocity_caps_a_burst(env):
    g = _guard(env, Policy(velocity_window_secs=3600, velocity_max_amount=2 * USDC))
    cred, mandate = await _issue(env)
    a = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="v1", amount=1 * USDC, payee="merchant:acme")
    b = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="v2", amount=1 * USDC, payee="merchant:acme")
    c = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="v3", amount=1 * USDC, payee="merchant:acme")
    assert a.allowed and b.allowed
    assert c.decision == "DENY" and c.reasons == ["policy:velocity_exceeded"]


@pytest.mark.asyncio
async def test_velocity_is_per_agent(env):
    # Two agents under one gate: agent A maxes its window; agent B is unaffected.
    g = _guard(env, Policy(velocity_window_secs=3600, velocity_max_amount=1 * USDC))
    credA = (await env["pi"].issue(agent_did="did:web:A", scopes=["payments.send"]))["credential"]
    credB = (await env["pi"].issue(agent_did="did:web:B", scopes=["payments.send"]))["credential"]
    mandate = (await env["mi"].issue(payer="acct:alice", payee="merchant:acme", max_amount=50 * USDC, period="month"))["mandate"]
    await g.authorize(passport_credential=credA, mandate=mandate, charge_id="a1", amount=1 * USDC, payee="merchant:acme")
    da = await g.authorize(passport_credential=credA, mandate=mandate, charge_id="a2", amount=1 * USDC, payee="merchant:acme")
    db = await g.authorize(passport_credential=credB, mandate=mandate, charge_id="b1", amount=1 * USDC, payee="merchant:acme")
    assert da.reasons == ["policy:velocity_exceeded"]   # A is capped
    assert db.allowed                                    # B is independent


@pytest.mark.asyncio
async def test_refer_and_deny_decisions_stay_in_the_verifiable_chain(env):
    g = _guard(env, Policy(refer_above_amount=10 * USDC, velocity_window_secs=3600, velocity_max_amount=5 * USDC))
    cred, mandate = await _issue(env)
    await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=1 * USDC, payee="merchant:acme")
    await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c2", amount=15 * USDC, payee="merchant:acme")  # REFER
    res = verify_decision_chain(g.ledger.envelopes, env["gpk"])
    assert res.verified and res.count == 2
