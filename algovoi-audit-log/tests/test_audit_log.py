"""Unit tests for algovoi-audit-log."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from algovoi_audit_log import (
    AuditLog,
    InMemoryStore,
    bearer_token_auth,
    create_app,
    signing,
    verify_chain,
    verify_entry,
)


@pytest.fixture
def keys():
    pk, sk = signing.generate_keypair()
    return pk, sk


def _log(pk, sk, store=None):
    return AuditLog(secret_key=sk, public_key=pk, store=store or InMemoryStore(), issuer_did="did:web:test")


async def test_append_and_verify_chain(keys):
    pk, sk = keys
    log = _log(pk, sk)
    for i in range(3):
        await log.append(event_type="payment.authorized",
                         event={"payment_id": f"p{i}", "amount": 1000 + i, "decision": "ALLOW"},
                         actor="did:web:gateway")
    res = await log.verify_chain()
    assert res.valid and res.length == 3 and res.head_entry_hash
    v = verify_entry(await log.get_entry(0), pk)
    assert v.verified and v.seq == 0 and v.event_type == "payment.authorized"


async def test_event_recorded_inline_with_hash(keys):
    pk, sk = keys
    out = await _log(pk, sk).append(event_type="x", event={"k": "v", "n": 5})
    payload, _, _ = signing.open_envelope(out["receipt"])
    assert payload["event"] == {"k": "v", "n": 5}
    assert payload["event_hash"] == signing.payload_hash({"k": "v", "n": 5}) == out["event_hash"]


async def test_chain_tamper_detected(keys):
    pk, sk = keys
    log = _log(pk, sk)
    for i in range(3):
        await log.append(event_type="e", event={"i": i})
    entries = await log.list_entries()
    env = json.loads(signing.b64u_decode(entries[1]))
    env["payload"]["event"] = {"i": 999}                 # tamper the recorded event
    entries[1] = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    res = verify_chain(entries, pk)
    assert res.valid is False and res.broken_at == 1


async def test_truncation_and_hole_detected(keys):
    """A clean prefix is not a clean whole: interior deletion is caught unconditionally; a dropped
    tail is caught against a pinned head (security fix 2026-08-19)."""
    pk, sk = keys
    store = InMemoryStore()
    log = _log(pk, sk, store)
    for i in range(4):
        await log.append(event_type="e", event={"i": i})
    pinned = await store.head()                       # out-of-band anchor: seq_count=4 + head hash
    assert (await log.verify_chain()).valid
    assert (await log.verify_chain(expected_head=pinned)).valid

    # Trailing deletion: the store head moves with the drop, so an un-anchored check cannot tell,
    # but against the pinned head it MUST fail.
    del store._rows[3]
    res_anchored = await log.verify_chain(expected_head=pinned)
    assert res_anchored.valid is False and res_anchored.reason in ("length_mismatch", "head_mismatch")

    # Interior deletion is caught even without an anchor: the contiguous scan hits a hole while the
    # persisted seq_count still counts the orphaned tail.
    store2 = InMemoryStore()
    log2 = _log(pk, sk, store2)
    for i in range(4):
        await log2.append(event_type="e", event={"i": i})
    del store2._rows[1]
    res_hole = await log2.verify_chain()
    assert res_hole.valid is False and res_hole.reason == "missing_entry"


async def test_read_only_log_cannot_append(keys):
    pk, sk = keys
    store = InMemoryStore()
    await _log(pk, sk, store).append(event_type="e", event={"a": 1})
    reader = AuditLog(public_key=pk, store=store)         # no secret_key
    assert (await reader.verify_chain()).valid
    with pytest.raises(RuntimeError):
        await reader.append(event_type="e", event={"b": 2})


async def test_verify_entry_wrong_key_rejected(keys):
    pk, sk = keys
    pk2, _ = signing.generate_keypair()
    out = await _log(pk, sk).append(event_type="e", event={"a": 1})
    assert verify_entry(out["receipt"], pk2).verified is False


def test_app_full_flow(keys):
    pk, sk = keys
    client = TestClient(create_app(_log(pk, sk), public_key=pk))
    a = client.post("/v1/audit-log/append", json={
        "event_type": "login", "event": {"user": "alice", "ip": "203.0.113.4"}, "actor": "did:web:app"}).json()
    assert a["seq"] == 0
    assert client.post("/v1/audit-log/verify", json={"receipt": a["receipt"]}).json()["verified"] is True
    assert client.get("/v1/audit-log/verify-chain").json()["valid"] is True
    assert client.get("/v1/audit-log/entry/0").json()["payload"]["event_type"] == "login"
    assert client.get("/v1/audit-log/entry/99").status_code == 404


def test_app_append_auth_required(keys):
    pk, sk = keys
    client = TestClient(create_app(_log(pk, sk), public_key=pk, auth_dependency=bearer_token_auth("secret")))
    assert client.post("/v1/audit-log/append", json={"event_type": "e", "event": {"a": 1}}).status_code == 401
