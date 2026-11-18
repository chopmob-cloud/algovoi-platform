"""VerifyResult.confirmed_round plumbing for the Algorand/Voi verifier.

The verifier already fetches the indexer's ``confirmed-round`` to decide the
tx is settled; these tests confirm it now also surfaces it on VerifyResult
(so downstream evidence capture can anchor a state proof), without disturbing
the failure paths or the extra="forbid" contract.
"""
from __future__ import annotations

import json

import pytest

from algovoi_settlement_verify.schemas import NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.algorand import AlgorandVerifier

_RECEIVER = "A" * 58
_TX_ID = "B" * 52


class _FakeResp:
    def __init__(self, payload: dict):
        self._payload = payload
        self.status_code = 200

    def json(self) -> dict:
        return self._payload


def _payload(**over) -> PaymentPayload:
    kw = dict(
        network=NetworkEnum.algorand_mainnet,
        tx_id=_TX_ID,
        expected_amount_microalgos=1_000_000,
        expected_receiver=_RECEIVER,
    )
    kw.update(over)
    return PaymentPayload(**kw)


def _verifier() -> AlgorandVerifier:
    return AlgorandVerifier(
        node_url="https://node.example",
        indexer_url="https://idx.example",
    )


# ── schema-level ──────────────────────────────────────────────────────────────

def test_field_defaults_none():
    r = VerifyResult(verified=False, tx_id=_TX_ID, network=NetworkEnum.algorand_mainnet, error="x")
    assert r.confirmed_round is None


def test_field_accepts_int():
    r = VerifyResult(
        verified=True, tx_id=_TX_ID, network=NetworkEnum.algorand_mainnet,
        confirmed_amount=5, confirmed_round=42,
    )
    assert r.confirmed_round == 42


def test_extra_still_forbidden():
    with pytest.raises(Exception):
        VerifyResult(verified=True, tx_id=_TX_ID, network=NetworkEnum.algorand_mainnet, bogus=1)


# ── verifier populates the round on success ───────────────────────────────────

async def test_native_payment_populates_confirmed_round(monkeypatch):
    v = _verifier()
    tx = {"transaction": {"confirmed-round": 34_567_890,
                          "payment-transaction": {"receiver": _RECEIVER, "amount": 1_000_000}}}

    async def _fake_fetch(_tx_id):
        return _FakeResp(tx)

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_fetch)
    result = await v.verify(_payload())
    assert result.verified is True
    assert result.confirmed_amount == 1_000_000
    assert result.confirmed_round == 34_567_890


async def test_unconfirmed_tx_has_no_round(monkeypatch):
    v = _verifier()

    async def _fake_fetch(_tx_id):
        return _FakeResp({"transaction": {"payment-transaction": {"receiver": _RECEIVER, "amount": 1}}})

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_fetch)
    result = await v.verify(_payload())
    assert result.verified is False
    assert result.confirmed_round is None


async def test_receiver_mismatch_has_no_round(monkeypatch):
    v = _verifier()
    tx = {"transaction": {"confirmed-round": 999,
                          "payment-transaction": {"receiver": "C" * 58, "amount": 1_000_000}}}

    async def _fake_fetch(_tx_id):
        return _FakeResp(tx)

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_fetch)
    result = await v.verify(_payload())
    assert result.verified is False
    assert result.confirmed_round is None


async def test_authority_tx_populates_round(monkeypatch):
    v = _verifier()

    async def _fake_fetch(_tx_id):
        return _FakeResp({"transaction": {"confirmed-round": 7_777}})

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_fetch)
    result = await v.verify_authority_tx(_TX_ID, NetworkEnum.voi_mainnet)
    assert result.verified is True
    assert result.confirmed_round == 7_777


async def test_asa_transfer_populates_confirmed_round(monkeypatch):
    """ASA transfer success path populates confirmed_round on VerifyResult."""
    v = _verifier()
    asset_id = 123456
    tx = {"transaction": {
        "confirmed-round": 55_000_000,
        "asset-transfer-transaction": {
            "asset-id": asset_id,
            "receiver": _RECEIVER,
            "amount": 1_000_000,
        },
    }}

    async def _fake_fetch(_tx_id):
        return _FakeResp(tx)

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_fetch)
    result = await v.verify(_payload(expected_asset_id=asset_id))
    assert result.verified is True
    assert result.confirmed_round == 55_000_000


async def test_confirmed_round_integer_zero_treated_as_unconfirmed(monkeypatch):
    """confirmed-round: 0 is not a valid settled round — treated as unconfirmed."""
    v = _verifier()

    async def _fake_fetch(_tx_id):
        return _FakeResp({"transaction": {
            "confirmed-round": 0,
            "payment-transaction": {"receiver": _RECEIVER, "amount": 1_000_000},
        }})

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_fetch)
    result = await v.verify(_payload())
    assert result.verified is False
    assert result.confirmed_round is None


# ── ARC200 recipient must come from the signed ARC-4 arg, not accounts[] (security fix 2026-08-19) ──

import base64 as _b64  # noqa: E402
from algovoi_settlement_verify.verifiers import algorand as _alg  # noqa: E402


def _arc4_args(recipient_pubkey: bytes, amount: int) -> list[str]:
    """Build [selector, ARC-4 address, ARC-4 uint256] as base64, as the indexer returns them."""
    selector = _b64.b64encode(b"\xd4\x0f\xb3\xf9").decode()          # arbitrary 4-byte method selector
    addr_arg = _b64.b64encode(recipient_pubkey).decode()            # 32-byte ARC-4 address
    amt_arg = _b64.b64encode(amount.to_bytes(32, "big")).decode()   # ARC-4 uint256
    return [selector, addr_arg, amt_arg]


async def test_arc200_recipient_from_signed_arg_not_accounts(monkeypatch):
    """An attacker who sets accounts[0]=merchant but args[1]=attacker must NOT get a verified pass:
    the true ARC200 recipient is the signed ARC-4 argument, so the spoof fails Receiver mismatch."""
    v = _verifier()
    cid = sorted(_alg._ARC200_CONTRACT_IDS)[0]
    merchant_pk, attacker_pk = bytes([1]) * 32, bytes([2]) * 32
    merchant = _alg._pubkey_to_address(merchant_pk)

    spoof = {"transaction": {"confirmed-round": 100, "application-transaction": {
        "application-id": cid, "accounts": [merchant],            # spoofed foreign-accounts hint
        "application-args": _arc4_args(attacker_pk, 1_000_000)}}}  # real recipient = attacker

    async def _fake_spoof(_):
        return _FakeResp(spoof)

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_spoof)
    res = await v.verify(_payload(expected_asset_id=cid, expected_receiver=merchant))
    assert res.verified is False and res.error == "Receiver mismatch"

    # A legitimate transfer whose signed arg actually addresses the merchant still verifies.
    ok = {"transaction": {"confirmed-round": 100, "application-transaction": {
        "application-id": cid, "accounts": [],
        "application-args": _arc4_args(merchant_pk, 1_000_000)}}}

    async def _fake_ok(_):
        return _FakeResp(ok)

    monkeypatch.setattr(v, "_fetch_tx_with_retry", _fake_ok)
    res_ok = await v.verify(_payload(expected_asset_id=cid, expected_receiver=merchant))
    assert res_ok.verified is True and res_ok.confirmed_amount == 1_000_000
