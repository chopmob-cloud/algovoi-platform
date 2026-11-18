"""FastAPI service for the gateway core: create intents, poll settlement, export the receipt
chain. One process; chains light up as their add-ons are installed. Port 8090 by default."""
from __future__ import annotations

import os
import tempfile

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from algovoi_gateway_core import a2a as _a2a
from algovoi_gateway_core import ap2 as _ap2
from algovoi_gateway_core import mpp as _mpp
from algovoi_gateway_core import x402 as _x402
from algovoi_gateway_core.engine import GatewayEngine
from algovoi_gateway_core.provider import PaymentRequest


class IntentIn(BaseModel):
    network: str
    asset: str = "USDC"
    amount_minor: int = Field(..., ge=1)
    pay_to: str
    reference: str
    expires_at_ms: int | None = None


class X402RequireIn(BaseModel):
    network: str
    asset: str = "USDC"
    amount_minor: int = Field(..., ge=1)
    pay_to: str
    reference: str = ""
    resource: str = ""
    mainnet: bool = True


class X402VerifyIn(BaseModel):
    intent_id: str


class MppRequireIn(BaseModel):
    network: str
    asset: str = "USDC"
    amount_minor: int = Field(..., ge=1)
    pay_to: str
    reference: str = ""
    mpp_intent: str = "charge"
    period_count: int | None = None
    period_unit: str | None = None
    mainnet: bool = True


class Ap2CartIn(BaseModel):
    network: str
    asset: str = "USDC"
    amount_minor: int = Field(..., ge=1)
    pay_to: str
    cart_id: str
    mainnet: bool = True


class A2aTaskIn(BaseModel):
    network: str
    asset: str = "USDC"
    amount_minor: int = Field(..., ge=1)
    pay_to: str
    task_id: str
    mainnet: bool = True


class Ap2VerifyIn(BaseModel):
    intent_id: str
    cart_id: str


class A2aVerifyIn(BaseModel):
    intent_id: str
    task_id: str


class PayoutIn(BaseModel):
    network: str
    asset: str = "USDC"
    amount_minor: int = Field(..., ge=1)
    pay_to: str
    reference: str = ""
    decision_receipt: str | None = None   # Spend Guardrail ALLOW that authorizes this payout (Cap D)


def create_app(engine: GatewayEngine | None = None, *,
               guardrail_public_key: bytes | None = None,
               require_payout_authorization: bool = True) -> FastAPI:
    # SECURITY (Codex-tracked CRITICAL 2026-08-19): payout authorization defaults ON.
    # /v1/payouts signs and broadcasts with the operator custody key; with authorization
    # off (and the old 0.0.0.0 bind) any reachable caller could drain the hot wallet.
    # Setting require_payout_authorization=False is now an explicit, dangerous opt-in.
    eng = engine or GatewayEngine()
    app = FastAPI(title="AlgoVoi Payment Gateway", version="0.1.0")

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "algovoi-gateway", "chains": [c["network"] for c in eng.chains()]}

    @app.get("/v1/chains")
    async def chains():
        return {"chains": eng.chains()}

    @app.post("/v1/intents")
    async def create_intent(body: IntentIn):
        try:
            return await eng.create_intent(PaymentRequest(**body.model_dump()))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/v1/intents/{intent_id}")
    async def get_intent(intent_id: str):
        rec = eng._intents.get(intent_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="unknown intent")
        return rec

    @app.post("/v1/intents/{intent_id}/check")
    async def check_intent(intent_id: str):
        try:
            return await eng.check(intent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown intent")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=str(exc))

    @app.get("/v1/settlements/export")
    async def export_settlements():
        pack = eng.ledger.export_pack(os.path.join(tempfile.mkdtemp(), "gateway_pack"))
        return {"pack_dir": pack, "entries": len(eng.ledger.envelopes)}

    # ── x402 facilitator (optional): make the verification engine speak HTTP 402. ──
    @app.post("/v1/x402/requirements")
    async def x402_requirements(body: X402RequireIn):
        """Create a payment intent and return an x402 v1 `402 Payment Required` body for it."""
        try:
            intent = await eng.create_intent(PaymentRequest(
                network=body.network, asset=body.asset, amount_minor=body.amount_minor,
                pay_to=body.pay_to, reference=body.reference))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc))
        return JSONResponse(
            status_code=402,
            content=_x402.payment_required(intent, resource=body.resource, mainnet=body.mainnet),
            headers={"X-Payment-Required": "true"})

    @app.post("/v1/x402/verify")
    async def x402_verify(body: X402VerifyIn):
        """Verify the intent settled on-chain; on success return the signed gateway_settlement receipt."""
        try:
            rec = await eng.check(body.intent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown intent")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=str(exc))
        return _x402.verify_result(rec, eng.ledger)

    # ── MPP (x402 intent extension) ──
    @app.post("/v1/mpp/requirements")
    async def mpp_requirements(body: MppRequireIn):
        try:
            intent = await eng.create_intent(PaymentRequest(
                network=body.network, asset=body.asset, amount_minor=body.amount_minor,
                pay_to=body.pay_to, reference=body.reference))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc))
        return JSONResponse(status_code=402, headers={"X-Payment-Required": "true"},
                            content=_mpp.payment_required(
                                intent, mpp_intent=body.mpp_intent, period_count=body.period_count,
                                period_unit=body.period_unit, mainnet=body.mainnet))

    @app.post("/v1/mpp/verify")
    async def mpp_verify(body: X402VerifyIn):
        try:
            rec = await eng.check(body.intent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown intent")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=str(exc))
        return _mpp.verify_result(rec, eng.ledger)

    # ── AP2 (cart mandate -> settlement) ──
    @app.post("/v1/ap2/cart")
    async def ap2_cart(body: Ap2CartIn):
        try:
            intent = await eng.create_intent(PaymentRequest(
                network=body.network, asset=body.asset, amount_minor=body.amount_minor,
                pay_to=body.pay_to, reference=body.cart_id))  # bind cart id into the receipt
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc))
        return _ap2.cart_payment_request(intent, cart_id=body.cart_id, mainnet=body.mainnet)

    @app.post("/v1/ap2/verify")
    async def ap2_verify(body: Ap2VerifyIn):
        try:
            rec = await eng.check(body.intent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown intent")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=str(exc))
        return _ap2.verify_result(rec, eng.ledger, cart_id=body.cart_id)

    # ── A2A (payment task) ──
    @app.post("/v1/a2a/task")
    async def a2a_task(body: A2aTaskIn):
        try:
            intent = await eng.create_intent(PaymentRequest(
                network=body.network, asset=body.asset, amount_minor=body.amount_minor,
                pay_to=body.pay_to, reference=body.task_id))   # bind task id into the receipt
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc))
        return _a2a.payment_task(intent, task_id=body.task_id, mainnet=body.mainnet)

    @app.post("/v1/a2a/verify")
    async def a2a_verify(body: A2aVerifyIn):
        try:
            rec = await eng.check(body.intent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown intent")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=str(exc))
        return _a2a.verify_result(rec, eng.ledger, task_id=body.task_id)

    # ── Custody (Phase 3): sign + broadcast an outbound payout via the operator's key. ──
    @app.post("/v1/payouts")
    async def create_payout(body: PayoutIn):
        """Sign and broadcast an outbound payment through the chain's operator-held key, and record a
        signed gateway_payout receipt. Fail-closed: no operator key -> 403; chain without payout -> 501."""
        from algovoi_gateway_core.custody import CustodyNotConfigured
        from algovoi_gateway_core.engine import AuthorizationRequired
        try:
            return await eng.pay_out(network=body.network, asset=body.asset,
                                     amount_minor=body.amount_minor, pay_to=body.pay_to,
                                     reference=body.reference, decision_receipt=body.decision_receipt,
                                     guardrail_public_key=guardrail_public_key,
                                     require_authorization=require_payout_authorization)
        except AuthorizationRequired as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except CustodyNotConfigured as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except NotImplementedError as exc:
            raise HTTPException(status_code=501, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=str(exc))

    return app


def main() -> None:
    import uvicorn
    # Bind loopback by default; exposing the payout gateway on all interfaces must be a
    # deliberate operator choice (set GATEWAY_BIND=0.0.0.0:8090). Codex-tracked CRITICAL.
    bind = os.environ.get("GATEWAY_BIND", "127.0.0.1:8090")
    host, _, port = bind.partition(":")
    uvicorn.run(create_app(), host=host, port=int(port or "8090"))
