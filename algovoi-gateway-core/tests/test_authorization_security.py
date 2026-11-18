"""Security tests for the gateway-core authorization gate (CRITICAL + HIGH fixes, 2026-08-19).

Covers: single-use replay protection on a signed guardrail ALLOW, destination (payee) fail-closed
binding, amount binding, and the ALLOW/expiry gates. Runnable with pytest (asyncio auto mode).
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
import substrate2
from substrate2.pqc import generate_falcon_1024_keypair, sign_falcon_1024

from algovoi_gateway_core.authorization import verify_authorization
from algovoi_gateway_core.engine import AuthorizationRequired, GatewayEngine
from algovoi_gateway_core.provider import ChainInfo, PaymentRequest, SettlementObservation, register


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _decision(sk, *, decision="ALLOW", amount=1000, payee="addr:merchant",
              decision_id="dec-1", ttl_secs=300) -> str:
    """Build a Falcon-signed spend_decision receipt as the guardrail would emit it."""
    exp = _iso(datetime.now(timezone.utc) + timedelta(seconds=ttl_secs)) if ttl_secs else None
    payload = {
        "type": "spend_decision", "version": "1", "decision": decision,
        "decision_id": decision_id, "decision_ref": f"sha256:{decision_id}",
        "amount": amount, "payee": payee, "expires_at": exp,
    }
    sig = sign_falcon_1024(sk, substrate2.canonicalize_bytes(payload))
    env = {"payload": payload, "alg": "Falcon-1024", "sig": _b64u(sig)}
    return _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())


class _StubProvider:
    """Minimal payout-capable provider so pay_out can complete without a real chain."""

    def info(self) -> ChainInfo:
        return ChainInfo(network="stub", display_name="Stub", assets=("USDC",),
                         finality_seconds=1, supports_payout=True)

    async def new_receive_address(self, req: PaymentRequest) -> str:
        return "addr:merchant"

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        return SettlementObservation(settled=False, network="stub", reason="pending")

    _paid = 0

    async def sign_and_pay(self, *, network, asset, amount_minor, pay_to, reference) -> str:
        type(self)._paid += 1
        return f"0xtx{type(self)._paid}"


@pytest.fixture
def keys():
    pk, sk = generate_falcon_1024_keypair()
    return pk, sk


def test_allow_authorizes_exact_amount_and_payee(keys):
    pk, sk = keys
    r = verify_authorization(_decision(sk), pk, amount_minor=1000, pay_to="addr:merchant")
    assert r.ok and r.reason == "ok"


def test_amount_mismatch_rejected(keys):
    pk, sk = keys
    r = verify_authorization(_decision(sk, amount=1000), pk, amount_minor=999, pay_to="addr:merchant")
    assert not r.ok and r.reason == "amount_mismatch"


def test_deny_rejected(keys):
    pk, sk = keys
    r = verify_authorization(_decision(sk, decision="DENY"), pk, amount_minor=1000, pay_to="addr:merchant")
    assert not r.ok and r.reason.startswith("not_allow")


def test_expired_rejected(keys):
    pk, sk = keys
    exp_past = (datetime.now(timezone.utc) - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {"type": "spend_decision", "version": "1", "decision": "ALLOW", "decision_id": "x",
               "decision_ref": "sha256:x", "amount": 1000, "payee": "addr:merchant", "expires_at": exp_past}
    sig = sign_falcon_1024(sk, substrate2.canonicalize_bytes(payload))
    env = {"payload": payload, "alg": "Falcon-1024", "sig": _b64u(sig)}
    cred = _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    r = verify_authorization(cred, pk, amount_minor=1000, pay_to="addr:merchant")
    assert not r.ok and r.reason == "decision_expired"


def test_payee_binding_fails_closed_when_decision_has_no_payee(keys):
    pk, sk = keys
    # a decision that omits the payee must NOT authorize an arbitrary destination
    r = verify_authorization(_decision(sk, payee=None), pk, amount_minor=1000, pay_to="addr:attacker")
    assert not r.ok and r.reason == "payee_mismatch"


def test_wrong_payee_rejected(keys):
    pk, sk = keys
    r = verify_authorization(_decision(sk, payee="addr:merchant"), pk, amount_minor=1000, pay_to="addr:attacker")
    assert not r.ok and r.reason == "payee_mismatch"


async def test_single_use_blocks_replay(keys):
    pk, sk = keys
    register("stub", _StubProvider())
    eng = GatewayEngine()
    dec = _decision(sk, decision_id="dec-replay")
    # first payout against a fresh ALLOW succeeds
    out = await eng.pay_out(network="stub", asset="USDC", amount_minor=1000, pay_to="addr:merchant",
                            reference="o1", decision_receipt=dec, guardrail_public_key=pk,
                            require_authorization=True)
    assert out["status"] == "paid"
    # replaying the SAME signed ALLOW must be refused (single-use), not settled again
    with pytest.raises(AuthorizationRequired):
        await eng.pay_out(network="stub", asset="USDC", amount_minor=1000, pay_to="addr:merchant",
                          reference="o2", decision_receipt=dec, guardrail_public_key=pk,
                          require_authorization=True)
