"""AP2 facilitator (optional capability) for the AlgoVoi payment gateway add-on.

AP2 (Agent Payments Protocol) authorizes a payment with a merchant-signed CartMandate. This shim
renders the cart's price as a W3C Payment Request the payer settles on-chain, then verifies the
settlement through the same engine and returns the Falcon-1024 signed ``gateway_settlement`` receipt.
The mandate's ``cart_id`` is bound into the intent ``reference`` so the receipt commits to the cart it
settled (``reference_ref`` = sha256 of the cart id), giving an offline-verifiable cart→settlement link.
The gateway does not evaluate mandate bounds or consent; that stays with the AP2 mandate layer.
"""
from __future__ import annotations

from algovoi_gateway_core.x402 import network_id, verify_result as _verify

PROTOCOL = "ap2"


def cart_payment_request(intent: dict, *, cart_id: str, mainnet: bool = True) -> dict:
    """Render an AP2 CartMandate's price as a W3C-Payment-Request-shaped requirement for a gateway intent."""
    return {
        "protocol": PROTOCOL,
        "cart_id": cart_id,
        "payment_request": {
            "methodData": [{
                "supportedMethods": "crypto:" + network_id(intent["network"], mainnet=mainnet),
                "data": {"asset": intent["asset"], "payTo": intent["pay_to"]},
            }],
            "details": {
                "id": cart_id,
                "total": {"label": "total", "amount": {"currency": intent["asset"],
                                                       "value": str(intent["amount_minor"])}},
            },
        },
        "extra": {"intentId": intent["intent_id"], "verifyEndpoint": "/v1/ap2/verify"},
    }


def verify_result(intent_rec: dict, ledger, *, cart_id: str) -> dict:
    out = _verify(intent_rec, ledger)
    out["protocol"] = PROTOCOL
    out["cart_id"] = cart_id
    return out


__all__ = ["PROTOCOL", "cart_payment_request", "verify_result"]
