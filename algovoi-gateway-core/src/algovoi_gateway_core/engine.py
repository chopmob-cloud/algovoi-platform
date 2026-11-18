"""The chain-agnostic gateway engine: create a payment intent, watch the chain through the
installed :class:`ChainProvider`, and on settlement emit a signed, CCC-ingestable receipt.

Custody/payout is delegated to the provider's ``sign_and_pay`` (Phase 3) and is optional.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import asdict
from datetime import datetime, timezone

from algovoi_gateway_core import provider as registry
from algovoi_gateway_core.provider import PaymentRequest
from algovoi_gateway_core.receipt import SettlementLedger


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


class GatewayEngine:
    """Drives payment intents across whatever chain providers are installed."""

    def __init__(self, ledger: SettlementLedger | None = None) -> None:
        self.ledger = ledger or SettlementLedger.generate()
        self._intents: dict[str, dict] = {}

    def chains(self) -> list[dict]:
        """The installed chains and their capabilities (receive-only vs payout)."""
        return [asdict(ci) for ci in registry.installed()]

    async def create_intent(self, req: PaymentRequest) -> dict:
        """Create a payment intent: resolve the receive address via the chain provider."""
        prov = registry.get(req.network)
        pay_to = req.pay_to or await prov.new_receive_address(req)
        intent_id = "int_" + secrets.token_hex(12)
        rec = {
            "intent_id": intent_id, "network": req.network, "asset": req.asset,
            "amount_minor": req.amount_minor, "pay_to": pay_to, "reference": req.reference,
            "status": "pending", "created_at_ms": _now_ms(), "expires_at_ms": req.expires_at_ms,
            "receipt_hash": None, "tx_id": None,
        }
        self._intents[intent_id] = rec
        return rec

    async def check(self, intent_id: str) -> dict:
        """Poll the chain for settlement. On a confirmed, finalized match, record a signed
        receipt and flip the intent to ``settled`` (idempotent)."""
        rec = self._intents.get(intent_id)
        if rec is None:
            raise KeyError(intent_id)
        if rec["status"] == "settled":
            return rec
        prov = registry.get(rec["network"])
        req = PaymentRequest(network=rec["network"], asset=rec["asset"],
                             amount_minor=rec["amount_minor"], pay_to=rec["pay_to"],
                             reference=rec["reference"], expires_at_ms=rec["expires_at_ms"])
        obs = await prov.observe_settlement(req)
        rec["last_reason"] = obs.reason
        if obs.settled and obs.finalized:
            payload = self.ledger.record(req, obs)
            import substrate2
            rec.update(status="settled", tx_id=obs.tx_id,
                       receipt_hash=substrate2.sha256_jcs_prefixed(payload))
        elif obs.settled:
            rec["status"] = "confirming"
            rec["tx_id"] = obs.tx_id
        return rec

    async def pay_out(self, *, network: str, asset: str, amount_minor: int,
                      pay_to: str, reference: str, decision_receipt: str | None = None,
                      guardrail_public_key: bytes | None = None,
                      require_authorization: bool = False) -> dict:
        """Phase 3 (custody): sign + broadcast an outbound payment through the provider's operator
        key, then record a signed, no-PII ``gateway_payout`` receipt. Returns the payout result.

        Cap D: if ``require_authorization`` (and a ``guardrail_public_key`` is configured), the payout is
        signed only against a fresh, signature-valid ``ALLOW`` Spend Guardrail decision for this exact
        amount and destination; the decision's ``decision_ref`` is bound into the payout receipt as
        ``authorized_by_ref``. Raises :class:`AuthorizationRequired` if the decision is missing or invalid.
        """
        authorized_by_ref = None
        if require_authorization:
            if guardrail_public_key is None or not decision_receipt:
                raise AuthorizationRequired("payout requires an authorizing guardrail decision")
            from algovoi_gateway_core.authorization import verify_authorization
            res = verify_authorization(decision_receipt, guardrail_public_key,
                                       amount_minor=amount_minor, pay_to=pay_to)
            if not res.ok:
                raise AuthorizationRequired(f"payout not authorized: {res.reason}")
            authorized_by_ref = res.decision_ref
        elif decision_receipt and guardrail_public_key is not None:
            # not required, but if a decision is supplied and valid, bind it (best-effort provenance)
            from algovoi_gateway_core.authorization import verify_authorization
            res = verify_authorization(decision_receipt, guardrail_public_key,
                                       amount_minor=amount_minor, pay_to=pay_to)
            authorized_by_ref = res.decision_ref if res.ok else None
        prov = registry.get(network)
        tx_id = await prov.sign_and_pay(network=network, asset=asset, amount_minor=amount_minor,
                                        pay_to=pay_to, reference=reference)
        payload = self.ledger.record_payout(network=network, asset=asset, amount_minor=amount_minor,
                                            pay_to=pay_to, tx_id=tx_id, reference=reference,
                                            authorized_by_ref=authorized_by_ref)
        import substrate2
        return {"status": "paid", "network": network, "asset": asset,
                "amount_minor": str(amount_minor), "pay_to": pay_to, "tx_id": tx_id,
                "reference": reference, "authorized_by_ref": authorized_by_ref,
                "receipt_hash": substrate2.sha256_jcs_prefixed(payload)}


class AuthorizationRequired(PermissionError):
    """Raised when a payout requires an authorizing guardrail decision that is missing or invalid."""


__all__ = ["GatewayEngine", "AuthorizationRequired"]
