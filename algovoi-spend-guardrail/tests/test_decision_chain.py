"""Cap A: signed decision chain, replay/freshness, CCC-shape, and lite-funnel byte-composition."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import rfc8785

from algovoi_agent_passport import InMemoryStore as PStore, PassportIssuer, signing
from algovoi_payment_mandate import InMemoryStore as MStore, MandateIssuer

from algovoi_spend_guardrail import (
    Policy,
    SpendGuardrail,
    refs,
    verify_decision,
    verify_decision_chain,
)
from algovoi_spend_guardrail.ledger import CANON_VERSION, CHAIN_FILE, ENTRY_TYPE

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


def _guard(env, policy=None, ttl=300):
    return SpendGuardrail(passport_public_key=env["ppk"], mandate_issuer=env["mi"],
                          decision_secret_key=env["gsk"], decision_public_key=env["gpk"],
                          policy=policy, passport_store=env["pstore"], guardrail_did="did:web:guard",
                          decision_ttl_secs=ttl)


async def _issue(env, *, scopes=("payments.send",), max_amount=50 * USDC, payee="merchant:acme"):
    cred = (await env["pi"].issue(agent_did="did:web:agent.example.com", scopes=list(scopes)))["credential"]
    mandate = (await env["mi"].issue(payer="acct:alice", payee=payee, max_amount=max_amount, period="month"))["mandate"]
    return cred, mandate


# ---- refs + decision_ref carried on the receipt ------------------------------------------------

@pytest.mark.asyncio
async def test_allow_carries_all_refs_and_decision_ref(env):
    g = _guard(env)
    cred, mandate = await _issue(env)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=20 * USDC, payee="merchant:acme")
    assert d.allowed
    for r in (d.agent_ref, d.mandate_ref, d.policy_bound_ref, d.decision_ref):
        assert refs.is_ref(r)
    # decision_ref is exactly the published guardrail_ref construction over the carried refs.
    assert d.decision_ref == refs.decision_ref(
        verdict="ALLOW", agent_ref=d.agent_ref, mandate_ref_=d.mandate_ref,
        policy_bound_ref_=d.policy_bound_ref)


@pytest.mark.asyncio
async def test_passport_invalid_deny_has_no_agent_ref(env):
    g = _guard(env)
    _, mandate = await _issue(env)
    d = await g.authorize(passport_credential="not-a-credential", mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    assert not d.allowed
    assert d.agent_ref is None and d.decision_ref is None        # identity not trusted -> no agent ref
    assert refs.is_ref(d.mandate_ref)                            # the mandate still parses


# ---- the chain ---------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_decisions_form_a_verifiable_chain(env):
    g = _guard(env)
    cred, mandate = await _issue(env)
    for i in range(4):
        await g.authorize(passport_credential=cred, mandate=mandate, charge_id=f"c{i}",
                          amount=1 * USDC, payee="merchant:acme")
    res = verify_decision_chain(g.ledger.envelopes, env["gpk"])
    assert res.verified and res.count == 4
    # sequence + linkage
    assert [json.loads(signing.b64u_decode(e))["payload"]["seq"] for e in g.ledger.envelopes] == [0, 1, 2, 3]


@pytest.mark.asyncio
async def test_tampered_decision_breaks_chain_at_that_seq(env):
    g = _guard(env)
    cred, mandate = await _issue(env)
    for i in range(3):
        await g.authorize(passport_credential=cred, mandate=mandate, charge_id=f"c{i}",
                          amount=1 * USDC, payee="merchant:acme")
    env_list = list(g.ledger.envelopes)
    # forge entry 1: flip the amount inside the signed payload, re-wrap (signature now invalid)
    e = json.loads(signing.b64u_decode(env_list[1]))
    e["payload"]["amount"] = 999 * USDC
    env_list[1] = signing.b64u_encode(json.dumps(e, separators=(",", ":"), sort_keys=True).encode())
    res = verify_decision_chain(env_list, env["gpk"])
    assert not res.verified and res.first_bad_seq == 1


@pytest.mark.asyncio
async def test_dropped_decision_breaks_chain(env):
    g = _guard(env)
    cred, mandate = await _issue(env)
    for i in range(3):
        await g.authorize(passport_credential=cred, mandate=mandate, charge_id=f"c{i}",
                          amount=1 * USDC, payee="merchant:acme")
    env_list = [g.ledger.envelopes[0], g.ledger.envelopes[2]]   # drop the middle decision
    res = verify_decision_chain(env_list, env["gpk"])
    assert not res.verified and res.first_bad_seq == 1


# ---- replay / freshness ------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fresh_decision_not_expired(env):
    g = _guard(env, ttl=300)
    cred, mandate = await _issue(env)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    v = verify_decision(d.decision_receipt, env["gpk"])
    assert v.verified and v.expired is False and v.decision_ref == d.decision_ref


@pytest.mark.asyncio
async def test_stale_decision_verifies_but_flags_expired(env):
    g = _guard(env, ttl=0)               # window closes immediately
    cred, mandate = await _issue(env)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    v = verify_decision(d.decision_receipt, env["gpk"])
    assert v.verified is True and v.expired is True      # signature genuine, but stale -> must not replay


# ---- CCC-ingestable pack -----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_export_pack_is_ccc_shaped(env, tmp_path: Path):
    g = _guard(env)
    cred, mandate = await _issue(env)
    await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                      amount=1 * USDC, payee="merchant:acme")
    g.export_pack(str(tmp_path))
    chain = json.loads((tmp_path / CHAIN_FILE).read_text())
    assert (tmp_path / "public_key.b64").exists()
    payload = json.loads(signing.b64u_decode(chain[0]))["payload"]
    assert payload["type"] == ENTRY_TYPE and payload["canon_version"] == CANON_VERSION
    assert payload["prev_entry_hash"] is None and payload["seq"] == 0
    # no-PII: the receipt carries refs + amounts, never raw counterparty data beyond the policy payee
    assert payload["agent_ref"].startswith("sha256:")


# ---- the lite funnel composes byte-for-byte ----------------------------------------------------

def test_decision_ref_matches_published_corpus_vectors():
    """A commercial decision_ref recomputes the published lite guardrail_ref byte-for-byte."""
    vf = Path("C:/algo/algovoi-jcs-conformance-vectors/vectors/spend_guardrail_lite_v1/"
              "spend_guardrail_lite_v1.json")
    if not vf.exists():
        pytest.skip("conformance corpus not present")
    data = json.loads(vf.read_text(encoding="utf-8"))
    for v in data["vectors"]:
        got = refs.decision_ref(verdict=v["verdict"], agent_ref=v["agent_ref"],
                                mandate_ref_=v["mandate_ref"], policy_bound_ref_=v["policy_bound_ref"])
        assert got == v["expected_guardrail_ref"], v["id"]


def test_prefixed_equals_substrate_canonicalizer():
    x = {"b": 2, "a": 1}
    assert refs._prefixed(x) == "sha256:" + hashlib.sha256(rfc8785.dumps(x)).hexdigest()
