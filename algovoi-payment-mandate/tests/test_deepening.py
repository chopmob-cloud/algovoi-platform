"""Mandate deepening: signed charge chain, hybrid Falcon+ML-DSA, no-PII, CCC-shape."""
from __future__ import annotations

import json

import pytest

from algovoi_payment_mandate import (
    InMemoryStore,
    MandateIssuer,
    hybrid,
    signing,
    verify_mandate,
    verify_mandate_chain,
)
from algovoi_payment_mandate.charge_ledger import CHAIN_FILE, ENTRY_TYPE

USDC = 1_000_000


async def _issuer(*, mldsa=False):
    pk, sk = signing.generate_keypair()
    kw, mpk = {}, None
    if mldsa:
        mpk, msk = hybrid.generate_keypair()
        kw = {"mldsa_secret_key": msk, "mldsa_public_key": mpk}
    mi = MandateIssuer(secret_key=sk, public_key=pk, store=InMemoryStore(), issuer_did="did:web:mi", **kw)
    return mi, pk, mpk


async def _mandate(mi, *, payee="merchant:acme", max_amount=50 * USDC):
    return (await mi.issue(payer="acct:alice", payee=payee, max_amount=max_amount, period="month"))["mandate"]


# ---- charge chain -------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_authorized_charges_form_a_verifiable_chain():
    mi, pk, _ = await _issuer()
    m = await _mandate(mi)
    for i in range(3):
        r = await mi.authorize_charge(mandate=m, charge_id=f"c{i}", amount=1 * USDC, payee="merchant:acme")
        assert r.authorized
    res = verify_mandate_chain(mi.charges.envelopes, pk)
    assert res.verified and res.count == 3


@pytest.mark.asyncio
async def test_declined_charge_is_not_in_the_chain():
    mi, pk, _ = await _issuer()
    m = await _mandate(mi, max_amount=5 * USDC)
    await mi.authorize_charge(mandate=m, charge_id="ok", amount=5 * USDC, payee="merchant:acme")
    d = await mi.authorize_charge(mandate=m, charge_id="over", amount=5 * USDC, payee="merchant:acme")  # cap exceeded
    assert not d.authorized
    assert mi.charges.seq == 1  # only the authorized charge is chained


@pytest.mark.asyncio
async def test_charge_event_is_no_pii_amount_is_string():
    mi, pk, _ = await _issuer()
    m = await _mandate(mi)
    await mi.authorize_charge(mandate=m, charge_id="c0", amount=2 * USDC, payee="merchant:acme")
    payload = json.loads(signing.b64u_decode(mi.charges.envelopes[0]))["payload"]
    assert payload["type"] == ENTRY_TYPE
    assert payload["mandate_ref"].startswith("sha256:")
    assert payload["amount_minor"] == str(2 * USDC)      # decimal string, JCS-safe
    assert "payer" not in payload                          # no raw payer identity


@pytest.mark.asyncio
async def test_tampered_charge_breaks_chain():
    mi, pk, _ = await _issuer()
    m = await _mandate(mi)
    for i in range(3):
        await mi.authorize_charge(mandate=m, charge_id=f"c{i}", amount=1 * USDC, payee="merchant:acme")
    env = list(mi.charges.envelopes)
    e = json.loads(signing.b64u_decode(env[1]))
    e["payload"]["amount_minor"] = "999000000"
    env[1] = signing.b64u_encode(json.dumps(e, separators=(",", ":"), sort_keys=True).encode())
    res = verify_mandate_chain(env, pk)
    assert not res.verified and res.first_bad_seq == 1


# ---- hybrid -------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hybrid_mandate_requires_both_signatures():
    mi, pk, mpk = await _issuer(mldsa=True)
    m = await _mandate(mi)
    assert (await verify_mandate(m, pk, mldsa_public_key=mpk)).verified
    assert (await verify_mandate(m, pk)).verified                       # Falcon-only still accepts
    other_pk, _ = hybrid.generate_keypair()
    assert (await verify_mandate(m, pk, mldsa_public_key=other_pk)).verified is False


@pytest.mark.asyncio
async def test_hybrid_charge_chain_verifies_with_mldsa_key():
    mi, pk, mpk = await _issuer(mldsa=True)
    m = await _mandate(mi)
    await mi.authorize_charge(mandate=m, charge_id="c0", amount=1 * USDC, payee="merchant:acme")
    assert verify_mandate_chain(mi.charges.envelopes, pk, mldsa_public_key=mpk).verified
    bad_pk, _ = hybrid.generate_keypair()
    assert verify_mandate_chain(mi.charges.envelopes, pk, mldsa_public_key=bad_pk).verified is False


# ---- CCC-ingestable pack ------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_export_pack_is_ccc_shaped(tmp_path):
    mi, pk, _ = await _issuer()
    m = await _mandate(mi)
    await mi.authorize_charge(mandate=m, charge_id="c0", amount=1 * USDC, payee="merchant:acme")
    mi.export_pack(str(tmp_path))
    chain = json.loads((tmp_path / CHAIN_FILE).read_text())
    assert (tmp_path / "public_key.b64").exists()
    payload = json.loads(signing.b64u_decode(chain[0]))["payload"]
    assert payload["type"] == ENTRY_TYPE and payload["prev_entry_hash"] is None and payload["seq"] == 0
