"""EVM finality gate (security fix 2026-08-19): min_confirmations rejects a shallow (reorg-able) receipt."""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from algovoi_settlement_verify.schemas import NetworkEnum, PaymentPayload
from algovoi_settlement_verify.verifiers.base_chain import (
    BaseChainVerifier,
    _TRANSFER_TOPIC,
    _USDC_MAINNET,
    _addr_topic,
)

RPC = "https://rpc.example/base"
RECEIVER = "0x" + "ab" * 20
TX = "0x" + "cd" * 32
AMOUNT = 1_000_000


def _receipt_json(block_hex: str) -> dict:
    return {
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "status": "0x1",
            "blockNumber": block_hex,
            "logs": [{
                "address": _USDC_MAINNET,
                "topics": [_TRANSFER_TOPIC, _addr_topic("0x" + "00" * 20), _addr_topic(RECEIVER)],
                "data": "0x" + format(AMOUNT, "064x"),
            }],
        },
    }


def _responder(head_hex: str):
    def _r(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "eth_getTransactionReceipt":
            return httpx.Response(200, json=_receipt_json("0x64"))     # tx in block 100
        if body["method"] == "eth_blockNumber":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": head_hex})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": None})
    return _r


def _payload() -> PaymentPayload:
    return PaymentPayload(network=NetworkEnum.base_mainnet, tx_id=TX,
                          expected_amount_microalgos=AMOUNT, expected_receiver=RECEIVER)


@respx.mock
async def test_shallow_confirmation_rejected():
    respx.post(RPC).mock(side_effect=_responder("0x66"))  # head 102 -> 3 confirmations
    v = BaseChainVerifier(RPC, NetworkEnum.base_mainnet, min_confirmations=6)
    r = await v.verify(_payload())
    assert r.verified is False and "confirmations" in (r.error or "").lower()


@respx.mock
async def test_deep_confirmation_accepted():
    respx.post(RPC).mock(side_effect=_responder("0x6e"))  # head 110 -> 11 confirmations
    v = BaseChainVerifier(RPC, NetworkEnum.base_mainnet, min_confirmations=6)
    r = await v.verify(_payload())
    assert r.verified is True and r.confirmed_amount == AMOUNT


@respx.mock
async def test_min_confirmations_zero_keeps_prior_behaviour():
    respx.post(RPC).mock(side_effect=_responder("0x64"))  # no eth_blockNumber call expected
    v = BaseChainVerifier(RPC, NetworkEnum.base_mainnet)  # default 0
    r = await v.verify(_payload())
    assert r.verified is True
