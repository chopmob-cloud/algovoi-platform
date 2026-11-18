"""MPP facilitator (optional capability) for the AlgoVoi payment gateway add-on.

MPP is the x402 ``intent`` extension (a ``charge`` or recurring ``subscription`` intent on top of the
x402 ``exact`` scheme). This shim shapes a gateway intent as an MPP payment-required body and verifies
settlement through the same engine, returning the Falcon-1024 signed ``gateway_settlement`` receipt as
proof. Bind the MPP request id into the intent ``reference`` so the receipt commits to it.
"""
from __future__ import annotations

from algovoi_gateway_core.x402 import X402_VERSION, network_id, verify_result as _verify

PROTOCOL = "mpp"


def payment_required(intent: dict, *, mpp_intent: str = "charge",
                     period_count: int | None = None, period_unit: str | None = None,
                     mainnet: bool = True) -> dict:
    """An MPP (x402 + ``intent``) payment-required body for a gateway intent."""
    accept = {
        "scheme": "exact",
        "network": network_id(intent["network"], mainnet=mainnet),
        "intent": mpp_intent,
        "amount": str(intent["amount_minor"]),
        "maxAmountRequired": str(intent["amount_minor"]),
        "asset": intent["asset"],
        "payTo": intent["pay_to"],
        "recipient": intent["pay_to"],
        "resource": intent.get("reference", ""),
        "extra": {"intentId": intent["intent_id"], "verifyEndpoint": "/v1/mpp/verify"},
    }
    if mpp_intent == "subscription" and period_count:
        accept["period_count"] = period_count
        accept["period_unit"] = period_unit or "month"
    return {"x402Version": X402_VERSION, "protocol": PROTOCOL, "accepts": [accept],
            "error": "Payment required"}


def verify_result(intent_rec: dict, ledger) -> dict:
    out = _verify(intent_rec, ledger)
    out["protocol"] = PROTOCOL
    return out


__all__ = ["PROTOCOL", "payment_required", "verify_result"]
