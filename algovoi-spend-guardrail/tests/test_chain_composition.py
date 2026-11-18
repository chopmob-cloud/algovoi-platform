"""Step 3: the decision chain composes byte-for-byte from every link.

Each upstream package now emits its own content address. This proves the three independently-computed
refs (passport_ref from agent-passport, mandate_ref from payment-mandate, the guardrail's derivation)
agree, and that the guardrail's decision_ref is exactly the published guardrail_ref over them.
"""
from __future__ import annotations

import pytest

from algovoi_agent_passport import InMemoryStore as PStore, PassportIssuer, passport_ref, signing
from algovoi_payment_mandate import InMemoryStore as MStore, MandateIssuer, mandate_ref

from algovoi_spend_guardrail import Policy, SpendGuardrail, refs

USDC = 1_000_000


@pytest.fixture
def env():
    ppk, psk = signing.generate_keypair()
    mpk, msk = signing.generate_keypair()
    gpk, gsk = signing.generate_keypair()
    pstore = PStore()
    pi = PassportIssuer(secret_key=psk, public_key=ppk, store=pstore, issuer_did="did:web:pi")
    mi = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore(), issuer_did="did:web:mi")
    g = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mi, decision_secret_key=gsk,
                       decision_public_key=gpk, policy=Policy(), passport_store=pstore,
                       guardrail_did="did:web:guard")
    return {"pi": pi, "mi": mi, "g": g, "gpk": gpk}


@pytest.mark.asyncio
async def test_passport_ref_matches_guardrail_derivation(env):
    out = await env["pi"].issue(agent_did="did:web:agent", scopes=["payments.send"])
    cred = out["credential"]
    payload, _, _ = signing.open_envelope(cred)
    # the agent-passport package and the guardrail derive the SAME agent address
    assert passport_ref(cred) == refs.passport_ref(payload)


@pytest.mark.asyncio
async def test_mandate_ref_matches_guardrail_derivation(env):
    out = await env["mi"].issue(payer="acct:alice", payee="merchant:acme", max_amount=50 * USDC, period="month")
    mandate = out["mandate"]
    payload, _, _ = signing.open_envelope(mandate)
    assert mandate_ref(mandate, revocation_state="active") == refs.mandate_ref(payload, revocation_state="active")


@pytest.mark.asyncio
async def test_decision_ref_recomposes_from_independent_refs(env):
    cred = (await env["pi"].issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    mandate = (await env["mi"].issue(payer="acct:alice", payee="merchant:acme",
                                     max_amount=50 * USDC, period="month"))["mandate"]
    d = await env["g"].authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                                 amount=10 * USDC, payee="merchant:acme")
    assert d.allowed
    # refs the gate put on the receipt == the refs the upstream packages compute independently
    assert d.agent_ref == passport_ref(cred)
    assert d.mandate_ref == mandate_ref(mandate, revocation_state="active")
    # and decision_ref is the published guardrail_ref construction over exactly those
    assert d.decision_ref == refs.decision_ref(
        verdict="ALLOW", agent_ref=passport_ref(cred),
        mandate_ref_=mandate_ref(mandate, revocation_state="active"),
        policy_bound_ref_=d.policy_bound_ref)


@pytest.mark.asyncio
async def test_revoked_mandate_addresses_differently(env):
    mandate = (await env["mi"].issue(payer="acct:alice", payee="merchant:acme",
                                     max_amount=50 * USDC, period="month"))["mandate"]
    assert mandate_ref(mandate, revocation_state="active") != mandate_ref(mandate, revocation_state="revoked")
