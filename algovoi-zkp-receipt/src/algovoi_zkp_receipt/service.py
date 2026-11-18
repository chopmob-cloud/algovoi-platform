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
    __version__,
    build_zkp_receipt_payload,
    verify_zkp_receipt,
)

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

def _load_issuer_pks() -> dict[str, str]:
    """Load the optional issuer PK registry from env or a file.

    ``ZKP_RECEIPT_ISSUER_PKS`` (JSON) → ``ZKP_RECEIPT_ISSUER_PKS_FILE`` (JSON file)
    → empty. An empty registry is fine: the service still starts healthy and
    /verify accepts a per-request ``pk_b64`` instead. No secret is required, so
    the service is already out-of-box clean with zero configuration.
    """
    issuer_pks: dict[str, str] = {}
    pks_json = os.environ.get("ZKP_RECEIPT_ISSUER_PKS", "").strip()
    if not pks_json:
        pfile = os.environ.get("ZKP_RECEIPT_ISSUER_PKS_FILE", "").strip()
        if pfile and os.path.exists(pfile):
            with open(pfile, encoding="utf-8") as fh:
                pks_json = fh.read().strip()
    if pks_json:
        try:
            issuer_pks = json.loads(pks_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"ZKP_RECEIPT_ISSUER_PKS is not valid JSON: {exc}") from exc
        if not isinstance(issuer_pks, dict):
            raise RuntimeError('ZKP_RECEIPT_ISSUER_PKS must be a JSON object {"<did>": "<pk_b64>"}')

    # Live trust-pull from the substrate-2 control plane hub, if configured.
    hub = os.environ.get("S2_HUB_URL", "").strip()
    if hub:
        from algovoi_zkp_receipt.hub_client import fetch_issuer_pks
        try:
            issuer_pks = {**issuer_pks, **fetch_issuer_pks(hub)}
        except Exception as exc:  # noqa: BLE001
            logger.warning("zkp_receipt.hub.pull_failed url=%s err=%s", hub, exc)

    # Self-register with the control plane so this service shows in its posture.
    s_hub = os.environ.get("S2_HUB_URL", "").strip()
    s_token = os.environ.get("S2_HUB_TOKEN", "").strip()
    if s_hub and s_token:
        from algovoi_zkp_receipt.hub_client import self_register
        ok = self_register(s_hub, s_token, name=os.environ.get("S2_HUB_NAME", "zkp-receipt"),
                           type_="zkp-receipt",
                           base_url=os.environ.get("S2_HUB_SELF_URL", "http://zkp-receipt:8093"))
        logger.info("zkp_receipt.hub.self_register url=%s ok=%s", s_hub, ok)

    return issuer_pks


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
    version=__version__,
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
        "version": __version__,
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


def main() -> None:
    """Console entry point — serve the ZKP receipt service."""
    import uvicorn
    bind = os.environ.get("ZKP_RECEIPT_BIND", "0.0.0.0:8093")
    host, _, port = bind.partition(":")
    uvicorn.run(app, host=host, port=int(port or "8093"))
