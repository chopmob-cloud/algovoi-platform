"""x402 facilitator (optional capability) for the AlgoVoi payment gateway add-on.

Turns the receive-and-verify engine into an x402 (HTTP 402 Payment Required) facilitator speaking
the x402 v1 wire format (the same shape AlgoVoi uses elsewhere): build a 402 *requirements* body
from a payment intent, then *verify* a claimed settlement on-chain. The proof of payment returned on
success is the gateway's own Falcon-1024 signed, offline-verifiable settlement receipt, so any party
can check it against the gateway public key with no shared secret, no JWT, and no live service.

This module is pure formatting + lookup over the existing engine/ledger; it adds no new crypto and
no protocol dependency. The MPP / AP2 / A2A authorization layers can wrap the same engine the same
way (the gateway stays the settlement-proof layer beneath whichever protocol initiates the payment).
"""
from __future__ import annotations

import base64
import json

import substrate2

X402_VERSION = 1


def network_id(network: str, *, mainnet: bool = True) -> str:
    """x402 network identifier, e.g. ``base:mainnet`` (matches the AlgoVoi x402 convention)."""
    return f"{network}:{'mainnet' if mainnet else 'testnet'}"


def payment_required(intent: dict, *, resource: str = "",
                     verify_endpoint: str = "/v1/x402/verify", mainnet: bool = True) -> dict:
    """An x402 spec-v1 ``402`` body built from a :meth:`GatewayEngine.create_intent` result.

    The single ``accepts`` entry pins the exact amount, asset, recipient, and network the payer must
    settle to, and carries the ``intentId`` the client posts back to ``verifyEndpoint`` after paying.
    """
    return {
        "x402Version": X402_VERSION,
        "accepts": [{
            "scheme": "exact",
            "network": network_id(intent["network"], mainnet=mainnet),
            "maxAmountRequired": str(intent["amount_minor"]),
            "asset": intent["asset"],
            "payTo": intent["pay_to"],
            "resource": resource or intent.get("reference", ""),
            "extra": {
                "intentId": intent["intent_id"],
                "verifyEndpoint": verify_endpoint,
                "note": ("Pay the exact amount in the named asset to payTo on this network, then "
                         "POST {\"intent_id\": ...} to verifyEndpoint to obtain a signed receipt."),
            },
        }],
        "error": "Payment required",
    }


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def receipt_for(ledger, receipt_hash: str | None) -> str | None:
    """Return the signed receipt envelope (b64u) whose payload hashes to ``receipt_hash``, else None."""
    if not receipt_hash:
        return None
    for env_b64 in ledger.envelopes:
        try:
            env = json.loads(_b64u_decode(env_b64))
            if substrate2.sha256_jcs_prefixed(env["payload"]) == receipt_hash:
                return env_b64
        except Exception:  # noqa: BLE001
            continue
    return None


def verify_result(intent_rec: dict, ledger) -> dict:
    """Build the x402 verify response from a checked intent record + the settlement ledger.

    On a settled intent it returns ``verified: true`` plus the Falcon-1024 signed
    ``gateway_settlement`` receipt envelope as offline-verifiable proof; otherwise ``verified: false``
    with the current status/reason so the caller can keep polling.
    """
    settled = intent_rec.get("status") == "settled"
    out = {
        "x402Version": X402_VERSION,
        "verified": settled,
        "status": intent_rec.get("status"),
        "intentId": intent_rec.get("intent_id"),
    }
    if settled:
        out["payment"] = {
            "network": intent_rec.get("network"),
            "asset": intent_rec.get("asset"),
            "amount_minor": str(intent_rec.get("amount_minor")),
            "tx_id": intent_rec.get("tx_id"),
        }
        out["receipt"] = receipt_for(ledger, intent_rec.get("receipt_hash"))
        out["receipt_kind"] = "gateway_settlement"  # Falcon-1024 signed, offline-verifiable
    else:
        out["reason"] = intent_rec.get("last_reason") or intent_rec.get("status")
    return out


__all__ = ["X402_VERSION", "network_id", "payment_required", "receipt_for", "verify_result"]
