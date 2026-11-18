"""Tests for the standalone Agent Passport app (real Falcon-1024, in-memory + SQLite stores)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("pqcrypto", reason="pqcrypto not installed")

from algovoi_agent_passport import (  # noqa: E402
    InMemoryStore,
    PassportIssuer,
    SqliteStore,
    bearer_token_auth,
    create_app,
    signing,
    verify_passport,
)

TOKEN = "test-issuer-token"


@pytest.fixture()
def setup():
    pk, sk = signing.generate_keypair()
    store = InMemoryStore()
    issuer = PassportIssuer(secret_key=sk, public_key=pk, store=store, issuer_did="did:web:test")
    app = create_app(issuer, public_key=pk, auth_dependency=bearer_token_auth(TOKEN))
    return pk, sk, store, issuer, TestClient(app)


def _h():
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def test_health(setup):
    *_, client = setup
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["app"] == "agent-passport"


def test_issue_requires_auth(setup):
    *_, client = setup
    assert client.post("/v1/passport/issue", json={"agent_did": "did:web:a"}).status_code == 401


def test_issue_verify_active(setup):
    *_, client = setup
    cred = client.post("/v1/passport/issue", headers=_h(),
                       json={"agent_did": "did:web:agent.test", "scopes": ["payments.send"], "ttl_secs": 3600}).json()["credential"]
    v = client.post("/v1/passport/verify", json={"credential": cred}).json()
    assert v["verified"] is True and v["status"] == "active" and v["agent_did"] == "did:web:agent.test"


def test_malformed_rejected(setup):
    *_, client = setup
    v = client.post("/v1/passport/verify", json={"credential": "not-a-cred"}).json()
    assert v["verified"] is False and v["error_code"] == "INVALID_CREDENTIAL"


def test_tampered_rejected(setup):
    *_, client = setup
    cred = client.post("/v1/passport/issue", headers=_h(), json={"agent_did": "did:web:agent.test", "ttl_secs": 3600}).json()["credential"]
    env = json.loads(signing.b64u_decode(cred))
    env["payload"]["agent_did"] = "did:web:attacker"
    tampered = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    assert client.post("/v1/passport/verify", json={"credential": tampered}).json()["error_code"] == "TAMPERED_SIGNATURE"


def test_revoke_lifecycle(setup):
    *_, client = setup
    iss = client.post("/v1/passport/issue", headers=_h(), json={"agent_did": "did:web:agent.test", "ttl_secs": 3600}).json()
    cred, pid, kid = iss["credential"], iss["passport_id"], iss["kid"]
    assert client.get(f"/v1/passport/status/{kid}/{pid}").json()["status"] == "active"
    assert client.post("/v1/passport/revoke", headers=_h(), json={"passport_id": pid}).json()["status"] == "revoked"
    v = client.post("/v1/passport/verify", json={"credential": cred}).json()
    assert v["status"] == "revoked" and v["error_code"] == "REVOKED"
    assert client.get(f"/v1/passport/status/{kid}/{pid}").json()["status"] == "revoked"
    assert pid in client.get(f"/passport/crl/{kid}.json").json()["revoked"]


def test_scope_and_agent_mismatch(setup):
    *_, client = setup
    cred = client.post("/v1/passport/issue", headers=_h(), json={"agent_did": "did:web:agent.test", "scopes": ["payments.send"], "ttl_secs": 3600}).json()["credential"]
    assert client.post("/v1/passport/verify", json={"credential": cred, "required_scope": "admin"}).json()["error_code"] == "SCOPE_NOT_GRANTED"
    assert client.post("/v1/passport/verify", json={"credential": cred, "expected_agent_did": "did:web:other"}).json()["error_code"] == "AGENT_MISMATCH"


def test_expired(setup):
    pk, sk, *_ , client = setup
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {"type": "agent_passport", "version": "1", "passport_id": "x", "agent_did": "did:web:a",
               "scopes": [], "spend_limit_microusd": None, "spend_window": None, "issuer_did": "did:web:test",
               "kid": signing.kid_for(pk), "issued_at": (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "expires_at": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    cred = signing.make_envelope(payload, sk, pk)
    v = client.post("/v1/passport/verify", json={"credential": cred}).json()
    assert v["status"] == "expired" and v["error_code"] == "EXPIRED"


def test_revoke_unknown_404(setup):
    *_, client = setup
    assert client.post("/v1/passport/revoke", headers=_h(), json={"passport_id": str(uuid4())}).status_code == 404


def test_portal_html(setup):
    *_, client = setup
    r = client.get("/passport/verify")
    assert r.status_code == 200 and "<!doctype html" in r.text.lower()


@pytest.mark.asyncio
async def test_sqlite_store_roundtrip(tmp_path):
    pk, sk = signing.generate_keypair()
    store = SqliteStore(str(tmp_path / "p.db"))
    issuer = PassportIssuer(secret_key=sk, public_key=pk, store=store)
    r = await issuer.issue(agent_did="did:web:a", scopes=["x"])
    assert (await verify_passport(r["credential"], pk, store=store)).status == "active"
    assert await issuer.revoke(passport_id=r["passport_id"]) is True
    assert (await verify_passport(r["credential"], pk, store=store)).status == "revoked"
    assert r["passport_id"] in await issuer.list_revoked(kid=issuer.kid)
