"""Unit tests for algovoi-payment-mandate (no external services required)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from algovoi_payment_mandate import signing
from algovoi_payment_mandate.app import create_app
from algovoi_payment_mandate.auth import bearer_token_auth
from algovoi_payment_mandate.issuer import MandateIssuer
from algovoi_payment_mandate.models import IssueRequest
from algovoi_payment_mandate.store import InMemoryStore
from algovoi_payment_mandate.verifier import verify_mandate

USDC = 1_000_000  # micro-USD per USDC


@pytest.fixture
def keys():
    pk, sk = signing.generate_keypair()
    return pk, sk


def _issuer(pk, sk):
    return MandateIssuer(secret_key=sk, public_key=pk, store=InMemoryStore(), issuer_did="did:web:test")


async def _issue(iss, **kw):
    base = dict(payer="acct:alice", payee="merchant:acme", max_amount=50 * USDC, period="month")
    base.update(kw)
    return await iss.issue(**base)


# ---- issuance + verification ---------------------------------------------------------------

async def test_issue_verify_roundtrip(keys):
    pk, sk = keys
    out = await _issue(_issuer(pk, sk), scope=["subscription"])
    res = await verify_mandate(out["mandate"], pk)
    assert res.verified and res.status == "active"
    assert res.payer == "acct:alice" and res.payee == "merchant:acme"
    assert res.max_amount == 50 * USDC and res.period == "month"
    assert res.scope == ["subscription"] and res.kid == signing.kid_for(pk)


async def test_tampered_mandate_rejected(keys):
    pk, sk = keys
    out = await _issue(_issuer(pk, sk))
    env = json.loads(signing.b64u_decode(out["mandate"]))
    env["payload"]["max_amount"] = 999_999 * USDC  # tamper after signing; original sig left in place
    forged = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    res = await verify_mandate(forged, pk)
    assert res.verified is False and res.error_code == "TAMPERED_SIGNATURE"


async def test_wrong_public_key_rejected(keys):
    pk, sk = keys
    pk2, _ = signing.generate_keypair()
    out = await _issue(_issuer(pk, sk))
    res = await verify_mandate(out["mandate"], pk2)
    assert res.verified is False and res.error_code == "TAMPERED_SIGNATURE"


async def test_expired_mandate(keys):
    pk, sk = keys
    payload = {
        "type": "payment_mandate", "version": "1", "mandate_id": "m1", "payer": "a", "payee": "b",
        "asset": "USDC", "chain": "*", "max_amount": 100, "period": "month", "max_per_charge": None,
        "scope": [], "issuer_did": "did:web:test", "kid": signing.kid_for(pk),
        "issued_at": "2020-01-01T00:00:00Z", "expires_at": "2020-01-02T00:00:00Z",
    }
    env = signing.make_envelope(payload, sk, pk)
    res = await verify_mandate(env, pk)
    assert res.verified is False and res.status == "expired"


async def test_revocation(keys):
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss)
    assert (await verify_mandate(out["mandate"], pk, store=iss.store)).verified is True
    assert await iss.revoke(mandate_id=out["mandate_id"]) is True
    res = await verify_mandate(out["mandate"], pk, store=iss.store)
    assert res.verified is False and res.status == "revoked"
    assert await iss.status(kid=out["kid"], mandate_id=out["mandate_id"]) == "revoked"
    assert out["mandate_id"] in await iss.list_revoked(kid=out["kid"])


async def test_scope_assertion(keys):
    pk, sk = keys
    out = await _issue(_issuer(pk, sk), scope=["subscription"])
    ok = await verify_mandate(out["mandate"], pk, required_scope="subscription")
    bad = await verify_mandate(out["mandate"], pk, required_scope="payroll")
    assert ok.verified is True and bad.verified is False and bad.error_code == "SCOPE_NOT_GRANTED"


# ---- charge authorization engine -----------------------------------------------------------

async def test_charge_within_cap(keys):
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss, max_amount=50 * USDC)
    r1 = await iss.authorize_charge(mandate=out["mandate"], charge_id="c1", amount=20 * USDC, at="2026-06-01T00:00:00Z")
    assert r1.authorized and r1.period_total_after == 20 * USDC and r1.remaining_this_period == 30 * USDC
    r2 = await iss.authorize_charge(mandate=out["mandate"], charge_id="c2", amount=20 * USDC, at="2026-06-10T00:00:00Z")
    assert r2.authorized and r2.period_total_after == 40 * USDC and r2.remaining_this_period == 10 * USDC


async def test_period_cap_exceeded(keys):
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss, max_amount=50 * USDC)
    await iss.authorize_charge(mandate=out["mandate"], charge_id="c1", amount=40 * USDC, at="2026-06-01T00:00:00Z")
    r = await iss.authorize_charge(mandate=out["mandate"], charge_id="c2", amount=20 * USDC, at="2026-06-02T00:00:00Z")
    assert r.authorized is False and r.decline_reason == "PERIOD_CAP_EXCEEDED"
    assert r.period_total_after == 40 * USDC and r.remaining_this_period == 10 * USDC


async def test_idempotent_charge(keys):
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss, max_amount=50 * USDC)
    a = await iss.authorize_charge(mandate=out["mandate"], charge_id="dup", amount=20 * USDC, at="2026-06-01T00:00:00Z")
    b = await iss.authorize_charge(mandate=out["mandate"], charge_id="dup", amount=20 * USDC, at="2026-06-01T00:00:00Z")
    assert a.authorized and b.authorized and b.idempotent is True
    # not double-counted: total still one charge worth
    assert b.period_total_after == 20 * USDC


async def test_per_charge_cap(keys):
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss, max_amount=50 * USDC, max_per_charge=10 * USDC)
    r = await iss.authorize_charge(mandate=out["mandate"], charge_id="c1", amount=20 * USDC, at="2026-06-01T00:00:00Z")
    assert r.authorized is False and r.decline_reason == "PER_CHARGE_CAP_EXCEEDED"


async def test_payee_mismatch(keys):
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss)
    r = await iss.authorize_charge(mandate=out["mandate"], charge_id="c1", amount=1 * USDC,
                                   payee="merchant:evil", at="2026-06-01T00:00:00Z")
    assert r.authorized is False and r.decline_reason == "PAYEE_MISMATCH"


async def test_period_rollover(keys, monkeypatch):
    # Security note (2026-08-19): the per-period bucket is keyed by SERVER time, never by the
    # caller-supplied `at` (which would let the charged party pick an empty bucket per charge and
    # evade the cap). Rollover is therefore exercised by advancing the server clock, not `at`.
    import algovoi_payment_mandate.issuer as issuer_mod
    from datetime import datetime as _dt, timezone as _tz

    class _FakeDT(_dt):
        _now = _dt(2026, 6, 15, tzinfo=_tz.utc)

        @classmethod
        def now(cls, tz=None):
            return cls._now if tz is None else cls._now.astimezone(tz)

    monkeypatch.setattr(issuer_mod, "datetime", _FakeDT)
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss, max_amount=50 * USDC)
    a = await iss.authorize_charge(mandate=out["mandate"], charge_id="jun", amount=50 * USDC)
    assert a.authorized and a.period_key == "2026-06" and a.remaining_this_period == 0
    # advance the SERVER clock to the next month → fresh cap
    _FakeDT._now = _dt(2026, 7, 1, tzinfo=_tz.utc)
    b = await iss.authorize_charge(mandate=out["mandate"], charge_id="jul", amount=50 * USDC)
    assert b.authorized and b.period_key == "2026-07" and b.remaining_this_period == 0
    # a second charge in the SAME server month is still capped (proves `at` can't reopen the bucket)
    c = await iss.authorize_charge(mandate=out["mandate"], charge_id="jul2", amount=1 * USDC,
                                   at="2026-08-01T00:00:00Z")
    assert c.authorized is False and c.decline_reason == "PERIOD_CAP_EXCEEDED"


async def test_revoked_mandate_declines_charge(keys):
    pk, sk = keys
    iss = _issuer(pk, sk)
    out = await _issue(iss)
    await iss.revoke(mandate_id=out["mandate_id"])
    r = await iss.authorize_charge(mandate=out["mandate"], charge_id="c1", amount=1 * USDC, at="2026-06-01T00:00:00Z")
    assert r.authorized is False and r.decline_reason == "REVOKED"


def test_model_rejects_bad_period():
    with pytest.raises(Exception):
        IssueRequest(payer="a", payee="b", max_amount=1, period="fortnight")


# ---- app surface ---------------------------------------------------------------------------

def test_app_health_and_pqc_keys(keys):
    pk, sk = keys
    app = create_app(_issuer(pk, sk), public_key=pk)
    client = TestClient(app)
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["kid"] == signing.kid_for(pk)
    doc = client.get("/.well-known/pqc-keys.json").json()
    assert doc["keys"][0]["kid"] == signing.kid_for(pk) and doc["keys"][0]["alg"] == "Falcon-1024"


def test_app_full_lifecycle(keys):
    pk, sk = keys
    app = create_app(_issuer(pk, sk), public_key=pk)
    client = TestClient(app)
    issued = client.post("/v1/mandates/issue", json={
        "payer": "acct:alice", "payee": "merchant:acme", "max_amount": 50_000_000, "period": "month"}).json()
    assert client.post("/v1/mandates/verify", json={"mandate": issued["mandate"]}).json()["verified"] is True
    charge = client.post("/v1/mandates/authorize-charge", json={
        "mandate": issued["mandate"], "charge_id": "c1", "amount": 20_000_000, "at": "2026-06-01T00:00:00Z"}).json()
    assert charge["authorized"] is True and charge["remaining_this_period"] == 30_000_000
    assert client.post("/v1/mandates/revoke", json={"mandate_id": issued["mandate_id"]}).json()["status"] == "revoked"
    assert client.post("/v1/mandates/verify", json={"mandate": issued["mandate"]}).json()["status"] == "revoked"


def test_app_authorize_charge_auth_required(keys):
    pk, sk = keys
    app = create_app(_issuer(pk, sk), public_key=pk, auth_dependency=bearer_token_auth("secret"))
    client = TestClient(app)
    body = {"mandate": "x", "charge_id": "c1", "amount": 1}
    assert client.post("/v1/mandates/authorize-charge", json=body).status_code == 401
    assert client.post("/v1/mandates/authorize-charge", headers={"Authorization": "Bearer wrong"}, json=body).status_code == 403
