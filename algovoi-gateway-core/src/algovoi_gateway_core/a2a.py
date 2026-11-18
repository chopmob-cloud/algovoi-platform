"""A2A facilitator (optional capability) for the AlgoVoi payment gateway add-on.

A2A (Agent2Agent) carries work as tasks with typed message parts. This shim renders a gateway intent
as an A2A payment task (an ``input-required`` task whose DataPart states the amount, asset, recipient,
network, and the intent + verify endpoint), then verifies the settlement through the same engine and
returns the Falcon-1024 signed ``gateway_settlement`` receipt. The A2A ``taskId`` is bound into the
intent ``reference`` so the receipt commits to the task it settled. Agent identity/negotiation stays
with the A2A layer; the gateway is the settlement-proof beneath it.
"""
from __future__ import annotations

from algovoi_gateway_core.x402 import network_id, verify_result as _verify

PROTOCOL = "a2a"


def payment_task(intent: dict, *, task_id: str, mainnet: bool = True) -> dict:
    """An A2A payment task (kind=task, state=input-required) describing the required settlement."""
    return {
        "protocol": PROTOCOL,
        "kind": "task",
        "taskId": task_id,
        "status": {"state": "input-required"},
        "parts": [{
            "kind": "data",
            "data": {
                "type": "payment-required",
                "network": network_id(intent["network"], mainnet=mainnet),
                "asset": intent["asset"],
                "amount": str(intent["amount_minor"]),
                "payTo": intent["pay_to"],
                "intentId": intent["intent_id"],
                "verifyEndpoint": "/v1/a2a/verify",
            },
        }],
    }


def verify_result(intent_rec: dict, ledger, *, task_id: str) -> dict:
    out = _verify(intent_rec, ledger)
    out["protocol"] = PROTOCOL
    out["taskId"] = task_id
    return out


__all__ = ["PROTOCOL", "payment_task", "verify_result"]
