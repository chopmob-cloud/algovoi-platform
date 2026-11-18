"""ZKP Receipt HTTP service.

Wraps build_zkp_receipt_payload and verify_zkp_receipt as a stateless FastAPI service.

Endpoints:
  POST /build    — construct unsigned ZKP receipt payload (send to issuer for signing)
  POST /verify   — verify a signed ZKP receipt envelope
  GET  /health   — liveness probe

Configuration (environment variables):
  ZKP_RECEIPT_ISSUER_PKS  — JSON object {"<issuer-did>": "<falcon1024-pk-base64>"}.
                             Required for /verify with DID-based lookup.
                             Callers may also pass pk_b64 directly in the request.
  ZKP_RECEIPT_BIND         — bind address (default 0.0.0.0:8093)

IETF anchor: draft-hopley-x402-pqc-credential-binding-00
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from algovoi_zkp_receipt import (
    PaymentReceipt,
    ZkpReceiptVerifyResult,
    build_zkp_receipt_payload,
    verify_zkp_receipt,
)

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

def _load_issuer_pks() -> dict[str, str]:
    """Load optional issuer PK registry from env."""
    pks_json = os.environ.get("ZKP_RECEIPT_ISSUER_PKS", "").strip()
    if not pks_json:
        return {}
    try:
        return json.loads(pks_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ZKP_RECEIPT_ISSUER_PKS is not valid JSON: {exc}") from exc


_issuer_pks: dict[str, str] = _load_issuer_pks()

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AlgoVoi ZKP Receipt",
    description=(
        "Zero-knowledge proof-bound payment receipt attestation. "
        "Binds an ATB Phase 2 ZKP credential to a specific on-chain payment "
        "receipt — proving 'the agent that made this payment has ATB score >= threshold'. "
        "IETF: draft-hopley-x402-pqc-credential-binding-00"
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
)


# ── Request / response models ─────────────────────────────────────────────────

class BuildRequest(BaseModel):
    payment_id: str
    chain: str
    amount_microusd: int = Field(..., ge=0)
    recipient: str
    tx_id: str
    settled_at: str
    commitment_b64: str = Field(..., description="Pedersen commitment from ATB ZKP service.")
    proof_b64: str = Field(..., description="Bulletproofs range proof from ATB ZKP service.")
    threshold_milliunits: int = Field(..., ge=0, le=1000)
    issuer_did: str
    expires_at: str = Field(..., description="ISO 8601 UTC expiry.")
    issued_at: str | None = Field(
        None,
        description="ISO 8601 UTC issuance. Defaults to now.",
    )


class BuildResponse(BaseModel):
    payload: dict[str, Any]


class VerifyRequest(BaseModel):
    envelope_b64url: str = Field(..., description="Base64url ZKP receipt envelope.")
    pk_b64: str | None = Field(
        None,
        description=(
            "Issuer Falcon-1024 public key (base64 standard). "
            "If omitted, the service looks up the issuer DID from the envelope "
            "in its configured ZKP_RECEIPT_ISSUER_PKS registry."
        ),
    )


class VerifyResponse(BaseModel):
    valid: bool
    payment_id: str | None = None
    chain: str | None = None
    amount_microusd: int | None = None
    tx_id: str | None = None
    issuer_did: str | None = None
    kid: str | None = None
    expires_at: str | None = None
    failure_reason: str | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_pk(envelope_b64url: str, pk_b64_override: str | None) -> str | None:
    """Resolve the issuer PK: direct override > registry lookup."""
    if pk_b64_override:
        return pk_b64_override
    if not _issuer_pks:
        return None
    # Extract issuer DID from envelope without full verification.
    import base64

    try:
        pad = 4 - (len(envelope_b64url) % 4)
        if pad and pad < 4:
            envelope_b64url = envelope_b64url + "=" * pad
        envelope = json.loads(base64.urlsafe_b64decode(envelope_b64url))
        issuer_did: str = envelope.get("payload", {}).get("bench_issuer", "")
        return _issuer_pks.get(issuer_did)
    except Exception:
        return None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "zkp-receipt",
        "version": "0.1.0",
        "issuer_count": len(_issuer_pks),
    }


@app.post("/build", response_model=BuildResponse)
async def build(body: BuildRequest) -> BuildResponse:
    """Construct an unsigned ZKP receipt payload.

    Pass the returned payload to the issuer's signing endpoint to obtain a
    Falcon-1024 signed envelope. The signature covers payment receipt fields
    and ATB ZKP credential fields together.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    receipt = PaymentReceipt(
        payment_id=body.payment_id,
        chain=body.chain,  # type: ignore[arg-type]
        amount_microusd=body.amount_microusd,
        recipient=body.recipient,
        tx_id=body.tx_id,
        settled_at=body.settled_at,
    )
    payload = build_zkp_receipt_payload(
        receipt=receipt,
        commitment_b64=body.commitment_b64,
        proof_b64=body.proof_b64,
        threshold_milliunits=body.threshold_milliunits,
        issuer_did=body.issuer_did,
        expires_at=body.expires_at,
        issued_at=body.issued_at or now_str,
    )
    return BuildResponse(payload=payload)


@app.post("/verify", response_model=VerifyResponse)
async def verify(body: VerifyRequest) -> VerifyResponse:
    """Verify a signed ZKP receipt envelope.

    Checks Falcon-1024 signature, ZKP field shape, expiry, and receipt fields.
    Pass pk_b64 directly or configure ZKP_RECEIPT_ISSUER_PKS for registry lookup.
    """
    pk_b64 = _resolve_pk(body.envelope_b64url, body.pk_b64)
    if not pk_b64:
        return VerifyResponse(
            valid=False,
            failure_reason=(
                "no_public_key — pass pk_b64 in the request or configure "
                "ZKP_RECEIPT_ISSUER_PKS on the service"
            ),
        )

    result = verify_zkp_receipt(body.envelope_b64url, pk_b64)
    logger.info("verify valid=%s payment_id=%s", result.valid, result.payment_id)

    return VerifyResponse(
        valid=result.valid,
        payment_id=result.payment_id,
        chain=result.chain,
        amount_microusd=result.amount_microusd,
        tx_id=result.tx_id,
        issuer_did=result.issuer_did,
        kid=result.kid,
        expires_at=result.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ") if result.expires_at else None,
        failure_reason=result.failure_reason,
    )
