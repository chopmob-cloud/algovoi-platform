"""Step 2: durable decision chain — the chain + velocity survive a restart (SQLite DecisionStore)."""
from __future__ import annotations

import pytest

from algovoi_agent_passport import InMemoryStore as PStore, PassportIssuer, signing
from algovoi_payment_mandate import InMemoryStore as MStore, MandateIssuer

from algovoi_spend_guardrail import (
    DecisionStore,
    Policy,
    SpendGuardrail,
    verify_decision_chain,
)

USDC = 1_000_000


def _keys():
    return signing.generate_keypair(), signing.generate_keypair(), signing.generate_keypair()


async def _gate(db_path, *, policy=None, gkeys=None):
    (ppk, psk), (mpk, msk), (gpk, gsk) = gkeys or _keys()
    pstore = PStore()
    pi = PassportIssuer(secret_key=psk, public_key=ppk, store=pstore, issuer_did="did:web:pi")
    mi = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore(), issuer_did="did:web:mi")
    g = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mi, decision_secret_key=gsk,
                       decision_public_key=gpk, policy=policy, passport_store=pstore,
                       guardrail_did="did:web:guard",
                       decision_store=DecisionStore(dsn=f"sqlite:///{db_path}"))
    return g, gpk, pi, mi


async def _issue(pi, mi, *, payee="merchant:acme", max_amount=100 * USDC):
    cred = (await pi.issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    mandate = (await mi.issue(payer="acct:alice", payee=payee, max_amount=max_amount, period="month"))["mandate"]
    return cred, mandate


@pytest.mark.asyncio
async def test_chain_resumes_across_restart(tmp_path):
    db = tmp_path / "g.db"
    gk = _keys()
    # session 1: two decisions
    g1, gpk, pi, mi = await _gate(str(db), gkeys=gk)
    cred, mandate = await _issue(pi, mi)
    await g1.authorize(passport_credential=cred, mandate=mandate, charge_id="c0", amount=1 * USDC, payee="merchant:acme")
    await g1.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=1 * USDC, payee="merchant:acme")
    assert g1.ledger.seq == 2

    # session 2: a FRESH gate on the same DB + same key -> seq continues, chain stays linked
    g2, _, pi2, mi2 = await _gate(str(db), gkeys=gk)
    assert g2.ledger.seq == 2                      # resumed, not reset
    cred2, mandate2 = await _issue(pi2, mi2)
    await g2.authorize(passport_credential=cred2, mandate=mandate2, charge_id="c2", amount=1 * USDC, payee="merchant:acme")
    assert g2.ledger.seq == 3

    res = verify_decision_chain(g2.ledger.envelopes, gpk)
    assert res.verified and res.count == 3         # one unbroken chain across both sessions


@pytest.mark.asyncio
async def test_velocity_persists_across_restart(tmp_path):
    db = tmp_path / "v.db"
    gk = _keys()
    pol = Policy(velocity_window_secs=3600, velocity_max_amount=2 * USDC)
    g1, gpk, pi, mi = await _gate(str(db), policy=pol, gkeys=gk)
    cred, mandate = await _issue(pi, mi)
    await g1.authorize(passport_credential=cred, mandate=mandate, charge_id="c0", amount=1 * USDC, payee="merchant:acme")
    await g1.authorize(passport_credential=cred, mandate=mandate, charge_id="c1", amount=1 * USDC, payee="merchant:acme")
    # window now holds 2 USDC == cap

    # restart: a fresh gate must still see the prior spend and cap the next charge
    g2, _, pi2, mi2 = await _gate(str(db), policy=pol, gkeys=gk)
    # reuse the SAME agent did/credential so velocity (keyed on agent_did) carries over
    d = await g2.authorize(passport_credential=cred, mandate=mandate, charge_id="c2", amount=1 * USDC, payee="merchant:acme")
    assert d.decision == "DENY" and d.reasons == ["policy:velocity_exceeded"]


@pytest.mark.asyncio
async def test_no_store_still_in_memory(tmp_path):
    # default (no decision_store) keeps the prior in-memory behaviour
    (ppk, psk), (mpk, msk), (gpk, gsk) = _keys()
    pstore = PStore()
    pi = PassportIssuer(secret_key=psk, public_key=ppk, store=pstore, issuer_did="did:web:pi")
    mi = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore(), issuer_did="did:web:mi")
    g = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mi, decision_secret_key=gsk,
                       decision_public_key=gpk, passport_store=pstore)
    assert g.ledger.store is None
    cred, mandate = await _issue(pi, mi)
    await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c0", amount=1 * USDC, payee="merchant:acme")
    assert g.ledger.seq == 1 and len(g.ledger.envelopes) == 1
