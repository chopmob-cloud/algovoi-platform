"""Passport deepening: signed event chain (issue/revoke), hybrid Falcon+ML-DSA, no-PII, CCC-shape."""
from __future__ import annotations

import json

import pytest

from algovoi_agent_passport import (
    InMemoryStore,
    PassportIssuer,
    hybrid,
    passport_ref,
    signing,
    verify_passport,
    verify_passport_chain,
)
from algovoi_agent_passport.event_ledger import CHAIN_FILE, ENTRY_TYPE


async def _issuer(store=None, *, mldsa=False):
    pk, sk = signing.generate_keypair()
    kw = {}
    mpk = None
    if mldsa:
        mpk, msk = hybrid.generate_keypair()
        kw = {"mldsa_secret_key": msk, "mldsa_public_key": mpk}
    pi = PassportIssuer(secret_key=sk, public_key=pk, store=store or InMemoryStore(), issuer_did="did:web:pi", **kw)
    return pi, pk, mpk


# ---- event chain --------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_issue_and_revoke_form_a_verifiable_event_chain():
    pi, pk, _ = await _issuer()
    a = await pi.issue(agent_did="did:web:agent1", scopes=["payments.send"])
    await pi.issue(agent_did="did:web:agent2", scopes=["payments.send"])
    await pi.revoke(passport_id=a["passport_id"], reason="key rotation")
    res = verify_passport_chain(pi.events.envelopes, pk)
    assert res.verified and res.count == 3
    events = [json.loads(signing.b64u_decode(e))["payload"]["event"] for e in pi.events.envelopes]
    assert events == ["issue", "issue", "revoke"]


@pytest.mark.asyncio
async def test_event_chain_is_no_pii_and_carries_passport_ref():
    pi, pk, _ = await _issuer()
    out = await pi.issue(agent_did="did:web:agent", scopes=["payments.send"])
    payload = json.loads(signing.b64u_decode(pi.events.envelopes[0]))["payload"]
    assert payload["type"] == ENTRY_TYPE
    assert payload["passport_ref"].startswith("sha256:")
    # the event records the content address, not the raw agent identity
    assert "agent_did" not in payload and "scopes" not in payload


@pytest.mark.asyncio
async def test_tampered_event_breaks_chain():
    pi, pk, _ = await _issuer()
    for i in range(3):
        await pi.issue(agent_did=f"did:web:a{i}", scopes=["x"])
    env = list(pi.events.envelopes)
    e = json.loads(signing.b64u_decode(env[1]))
    e["payload"]["event"] = "forged"
    env[1] = signing.b64u_encode(json.dumps(e, separators=(",", ":"), sort_keys=True).encode())
    res = verify_passport_chain(env, pk)
    assert not res.verified and res.first_bad_seq == 1


# ---- hybrid signing -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hybrid_credential_requires_both_signatures():
    pi, pk, mpk = await _issuer(mldsa=True)
    cred = (await pi.issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    # both signatures verify
    v = await verify_passport(cred, pk, mldsa_public_key=mpk)
    assert v.verified
    # Falcon-only verifier still accepts it (does not check the second signature)
    assert (await verify_passport(cred, pk)).verified
    # wrong ML-DSA key -> fail closed
    other_pk, _ = hybrid.generate_keypair()
    assert (await verify_passport(cred, pk, mldsa_public_key=other_pk)).verified is False


@pytest.mark.asyncio
async def test_hybrid_event_chain_verifies_with_mldsa_key():
    pi, pk, mpk = await _issuer(mldsa=True)
    await pi.issue(agent_did="did:web:agent", scopes=["payments.send"])
    res = verify_passport_chain(pi.events.envelopes, pk, mldsa_public_key=mpk)
    assert res.verified
    bad_pk, _ = hybrid.generate_keypair()
    assert verify_passport_chain(pi.events.envelopes, pk, mldsa_public_key=bad_pk).verified is False


@pytest.mark.asyncio
async def test_falcon_only_credential_still_verifies():
    pi, pk, _ = await _issuer(mldsa=False)
    cred = (await pi.issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    assert (await verify_passport(cred, pk)).verified
    # passport_ref is unchanged by the deepening
    assert passport_ref(cred).startswith("sha256:")


# ---- envelope-kid binding + hybrid downgrade (2026-08-19 security fixes) -------------------------

@pytest.mark.asyncio
async def test_flipped_envelope_kid_is_rejected():
    """The unsigned envelope ``kid`` must not be trusted: flipping it (to point the revocation
    lookup at an empty namespace) keeps the Falcon signature valid but must now fail KID_MISMATCH."""
    store = InMemoryStore()
    pi, pk, _ = await _issuer(store=store)
    out = await pi.issue(agent_did="did:web:agent", scopes=["payments.send"])
    cred = out["credential"]
    # Revoke it, so a successful bypass would show as still-active.
    await pi.revoke(passport_id=out["passport_id"], reason="compromised")
    assert (await verify_passport(cred, pk, store=store)).status == "revoked"
    # Flip the outer envelope kid to a different (attacker-chosen) namespace.
    env = json.loads(signing.b64u_decode(cred))
    env["kid"] = "deadbeefdeadbeef"
    forged = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    res = await verify_passport(forged, pk, store=store)
    assert res.verified is False and res.error_code == "KID_MISMATCH"


@pytest.mark.asyncio
async def test_hybrid_event_chain_sig2_strip_is_rejected():
    """Codex-caught (2026-08-19): stripping ``sig2`` from a chain entry must fail when the verifier
    supplies an ML-DSA key — it must not silently downgrade the chain to Falcon-only."""
    pi, pk, mpk = await _issuer(mldsa=True)
    await pi.issue(agent_did="did:web:agent", scopes=["payments.send"])
    env = list(pi.events.envelopes)
    e = json.loads(signing.b64u_decode(env[0]))
    e.pop("sig2", None)
    env[0] = signing.b64u_encode(json.dumps(e, separators=(",", ":"), sort_keys=True).encode())
    # Falcon-only chain verification still passes; hybrid-required verification must reject it.
    assert verify_passport_chain(env, pk).verified
    assert verify_passport_chain(env, pk, mldsa_public_key=mpk).verified is False


@pytest.mark.asyncio
async def test_hybrid_sig2_strip_is_rejected():
    """When a verifier supplies an ML-DSA key it requires the co-signature; stripping the unsigned
    ``sig2`` must fail closed (was: silently downgraded to Falcon-only)."""
    pi, pk, mpk = await _issuer(mldsa=True)
    cred = (await pi.issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    env = json.loads(signing.b64u_decode(cred))
    env.pop("sig2", None)
    stripped = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    # Falcon-only verifier (no ML-DSA key) still accepts it.
    assert (await verify_passport(stripped, pk)).verified
    # But a verifier that requires the hybrid co-signature must reject the stripped credential.
    assert (await verify_passport(stripped, pk, mldsa_public_key=mpk)).verified is False


# ---- CCC-ingestable pack ------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_export_pack_is_ccc_shaped(tmp_path):
    pi, pk, _ = await _issuer()
    await pi.issue(agent_did="did:web:agent", scopes=["payments.send"])
    pi.export_pack(str(tmp_path))
    chain = json.loads((tmp_path / CHAIN_FILE).read_text())
    assert (tmp_path / "public_key.b64").exists()
    payload = json.loads(signing.b64u_decode(chain[0]))["payload"]
    assert payload["type"] == ENTRY_TYPE and payload["prev_entry_hash"] is None and payload["seq"] == 0
