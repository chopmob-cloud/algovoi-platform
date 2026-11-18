"""Cap E: hybrid Falcon+ML-DSA-65 decision signing and the substrate-guard input-bounds gate."""
from __future__ import annotations

import json

import pytest

from algovoi_agent_passport import InMemoryStore as PStore, PassportIssuer, signing
from algovoi_payment_mandate import InMemoryStore as MStore, MandateIssuer

from algovoi_spend_guardrail import (
    Bounds,
    Policy,
    SpendGuardrail,
    bounds,
    hybrid,
    verify_decision,
    verify_decision_chain,
)

USDC = 1_000_000


async def _setup(*, mldsa=False, bnds=None):
    ppk, psk = signing.generate_keypair()
    mpk, msk = signing.generate_keypair()
    gpk, gsk = signing.generate_keypair()
    pstore = PStore()
    pi = PassportIssuer(secret_key=psk, public_key=ppk, store=pstore, issuer_did="did:web:pi")
    mi = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore(), issuer_did="did:web:mi")
    kw = {}
    mldsa_pk = None
    if mldsa:
        mldsa_pk, mldsa_sk = hybrid.generate_keypair()
        kw.update(mldsa_secret_key=mldsa_sk, mldsa_public_key=mldsa_pk)
    if bnds is not None:
        kw["bounds"] = bnds
    g = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mi, decision_secret_key=gsk,
                       decision_public_key=gpk, policy=Policy(), passport_store=pstore,
                       guardrail_did="did:web:guard", **kw)
    cred = (await pi.issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    mandate = (await mi.issue(payer="acct:alice", payee="merchant:acme", max_amount=100 * USDC, period="month"))["mandate"]
    return g, gpk, mldsa_pk, cred, mandate


# ---- hybrid signing ----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hybrid_decision_requires_both_signatures():
    g, gpk, mldsa_pk, cred, mandate = await _setup(mldsa=True)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    # both sigs present and verified
    v = verify_decision(d.decision_receipt, gpk, mldsa_public_key=mldsa_pk)
    assert v.verified and v.hybrid is True
    # Falcon-only verifier still accepts it (hybrid reported False — it didn't check the 2nd sig)
    v2 = verify_decision(d.decision_receipt, gpk)
    assert v2.verified and v2.hybrid is False
    # wrong ML-DSA key -> fail closed
    other_pk, _ = hybrid.generate_keypair()
    assert verify_decision(d.decision_receipt, gpk, mldsa_public_key=other_pk).verified is False


@pytest.mark.asyncio
async def test_hybrid_tamper_breaks_both():
    g, gpk, mldsa_pk, cred, mandate = await _setup(mldsa=True)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    env = json.loads(signing.b64u_decode(d.decision_receipt))
    env["payload"]["amount"] = 999 * USDC
    forged = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    assert verify_decision(forged, gpk, mldsa_public_key=mldsa_pk).verified is False


@pytest.mark.asyncio
async def test_hybrid_chain_reports_hybrid():
    g, gpk, mldsa_pk, cred, mandate = await _setup(mldsa=True)
    for i in range(3):
        await g.authorize(passport_credential=cred, mandate=mandate, charge_id=f"c{i}",
                          amount=1 * USDC, payee="merchant:acme")
    res = verify_decision_chain(g.ledger.envelopes, gpk, mldsa_public_key=mldsa_pk)
    assert res.verified and res.count == 3 and res.hybrid is True


@pytest.mark.asyncio
async def test_falcon_only_decision_is_not_hybrid():
    g, gpk, _, cred, mandate = await _setup(mldsa=False)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    v = verify_decision(d.decision_receipt, gpk, mldsa_public_key=None)
    assert v.verified and v.hybrid is False


# ---- input bounds ------------------------------------------------------------------------------

def test_bounds_check_flags_oversize_and_profile_is_pinnable():
    big = "x" * 20_000
    v = bounds.check(passport_credential=big, mandate="m", charge_id="c", amount=1, payee="p")
    assert "bounds:credential_too_large" in v
    assert bounds.profile_ref().startswith("sha256:")
    # a different profile addresses differently (pinnable / rotation-detectable)
    assert bounds.profile_ref(Bounds(max_credential_bytes=999)) != bounds.profile_ref()


@pytest.mark.asyncio
async def test_oversize_credential_denied_without_touching_crypto():
    tight = Bounds(max_credential_bytes=128)
    g, gpk, _, cred, mandate = await _setup(bnds=tight)   # real cred is far larger than 128 bytes
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    assert not d.allowed and d.reasons == ["bounds:credential_too_large"]
    assert d.agent_ref is None        # the credential was never parsed/verified
    # the bounds DENY is still a signed, chained decision
    assert verify_decision(d.decision_receipt, gpk).verified


@pytest.mark.asyncio
async def test_bad_amount_denied_by_bounds():
    g, gpk, _, cred, mandate = await _setup()
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=10 ** 19, payee="merchant:acme")    # over max_amount
    assert not d.allowed and "bounds:amount_out_of_range" in d.reasons
