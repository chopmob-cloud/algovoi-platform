"""Federation Validator HTTP service.

Wraps FederationValidator as a stateless FastAPI microservice.

Endpoints:
  POST /compose   — verify N PQC credentials, return composite federation token
  POST /verify    — verify a federation token HMAC + expiry
  GET  /health    — liveness probe

Configuration (environment variables):
  FEDERATION_VALIDATOR_SECRET   — hex-encoded HMAC key (>= 64 hex chars = 32 bytes).
                                   Required.
  FEDERATION_ISSUER_PKS         — JSON object {"<issuer-did>": "<falcon1024-pk-base64>"}.
                                   Required.
  FEDERATION_MIN_CREDENTIALS    — minimum credentials to accept (default 2)
  FEDERATION_INTERNAL_TOKEN     — hex token for internal service bypass (optional).
                                   When set, POST /compose with
                                   Authorization: Bearer <token> skips cert
                                   verification and issues a token directly.
                                   For internal platform service-to-service calls only.
  FEDERATION_INTERNAL_TTL_SECS  — TTL for internally-issued tokens (default 3600)
  FEDERATION_BIND               — bind address (default 0.0.0.0:8092)

IETF anchor: draft-hopley-x402-federation-zkp-00
"""
from __future__ import annotations

import hmac
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Annotated, Any

from fastapi import FastAPI, Header
from pydantic import BaseModel, Field

from algovoi_federation_validator import (
    FederationValidator,
    IssuerEntry,
    verify_federation_token,
)
from algovoi_federation_validator._crypto import (
    compose_commitments,
    issue_federation_token,
)

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

def _load_config() -> tuple[bytes, dict[str, str], int, bytes | None, int]:
    secret_hex = os.environ.get("FEDERATION_VALIDATOR_SECRET", "").strip()
    if not secret_hex:
        raise RuntimeError(
            "FEDERATION_VALIDATOR_SECRET is required. "
            "Generate: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError as exc:
        raise RuntimeError(f"FEDERATION_VALIDATOR_SECRET must be hex: {exc}") from exc
    if len(secret) < 32:
        raise RuntimeError("FEDERATION_VALIDATOR_SECRET must be >= 64 hex chars (32 bytes)")

    pks_json = os.environ.get("FEDERATION_ISSUER_PKS", "").strip()
    if not pks_json:
        raise RuntimeError(
            "FEDERATION_ISSUER_PKS is required. "
            'Format: \'{"did:algovoi:bench:prod": "<falcon1024-pk-base64>"}\''
        )
    try:
        issuer_pks: dict[str, str] = json.loads(pks_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"FEDERATION_ISSUER_PKS is not valid JSON: {exc}") from exc
    if not issuer_pks:
        raise RuntimeError("FEDERATION_ISSUER_PKS must contain at least one entry")

    min_creds = int(os.environ.get("FEDERATION_MIN_CREDENTIALS", "2"))

    internal_token: bytes | None = None
    internal_hex = os.environ.get("FEDERATION_INTERNAL_TOKEN", "").strip()
    if internal_hex:
        try:
            internal_token = bytes.fromhex(internal_hex)
        except ValueError as exc:
            raise RuntimeError(f"FEDERATION_INTERNAL_TOKEN must be hex: {exc}") from exc
        if len(internal_token) < 32:
            raise RuntimeError("FEDERATION_INTERNAL_TOKEN must be >= 64 hex chars (32 bytes)")

    internal_ttl = int(os.environ.get("FEDERATION_INTERNAL_TTL_SECS", "3600"))

    return secret, issuer_pks, min_creds, internal_token, internal_ttl


_secret, _issuer_pks, _min_creds, _internal_token, _internal_ttl = _load_config()
_validator = FederationValidator(
    validator_secret=_secret,
    issuer_pks=_issuer_pks,
    min_credentials=_min_creds,
)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AlgoVoi Federation Validator",
    description=(
        "Cross-issuer ZKP credential composition — compose independent "
        "Falcon-1024 PQC credentials into a single federation token "
        "without a shared trust root. "
        "IETF: draft-hopley-x402-federation-zkp-00"
    ),
    version="0.1.1",
    docs_url="/docs",
    redoc_url=None,
)


# ── Request / response models ─────────────────────────────────────────────────

class ComposeRequest(BaseModel):
    credentials: list[str] = Field(
        default_factory=list,
        description=(
            "Base64url ATB ZKP Phase 2 credential envelopes. "
            "May be empty when presenting a valid internal service token."
        ),
    )


class IssuerInfo(BaseModel):
    did: str
    kid: str
    alg: str


class ComposeResponse(BaseModel):
    valid: bool
    token: str | None = Field(None, description="Base64url federation token envelope.")
    fed_commitment: str | None = None
    fed_nonce: str | None = None
    issuers: list[IssuerInfo] = Field(default_factory=list)
    expires_at: str | None = None
    issued_at: str | None = None
    source: str | None = Field(None, description="'internal' for bypass-issued tokens.")
    failure_reason: str | None = None


class VerifyRequest(BaseModel):
    token: str = Field(..., description="Base64url federation token to verify.")


class VerifyResponse(BaseModel):
    valid: bool
    payload: dict[str, Any] | None = None
    failure_reason: str | None = None


# ── Internal bypass helpers ───────────────────────────────────────────────────

def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip()
    return None


def _is_internal(authorization: str | None) -> bool:
    """Return True if the request carries a valid internal service token."""
    if not _internal_token:
        return False
    token = _bearer(authorization)
    if not token:
        return False
    try:
        token_bytes = bytes.fromhex(token)
    except ValueError:
        return False
    return hmac.compare_digest(_internal_token, token_bytes)


def _issue_internal_token() -> ComposeResponse:
    """Issue a federation token for an internal service without credential verification."""
    import os as _os
    nonce = _os.urandom(32)
    # Synthetic commitment — deterministic per nonce, marks internal source.
    synthetic_commitment = compose_commitments([nonce], b"algovoi-internal-bypass-v1")
    issuer = IssuerEntry(did="did:algovoi:internal", kid="internal", alg="internal")
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=_internal_ttl)

    token = issue_federation_token(
        issuers=[issuer],
        commitment_bytes_list=[synthetic_commitment],
        nonce=nonce,
        expires_at=expires_at,
        validator_secret=_secret,
    )

    logger.info("compose.internal token issued expires=%s", token.expires_at.isoformat())
    return ComposeResponse(
        valid=True,
        token=token.raw,
        fed_commitment=token.fed_commitment_hex,
        fed_nonce=token.fed_nonce_hex,
        issuers=[IssuerInfo(did=issuer.did, kid=issuer.kid, alg=issuer.alg)],
        expires_at=token.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        issued_at=token.issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        source="internal",
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "federation-validator",
        "version": "0.1.1",
        "issuer_count": len(_issuer_pks),
        "min_credentials": _min_creds,
        "internal_bypass": _internal_token is not None,
    }


@app.post("/compose", response_model=ComposeResponse)
async def compose(
    body: ComposeRequest,
    authorization: Annotated[str | None, Header()] = None,
) -> ComposeResponse:
    """Compose PQC credentials into a federation token.

    **Internal service path:** present `Authorization: Bearer <FEDERATION_INTERNAL_TOKEN>`
    with an empty `credentials` list. Returns a federation token immediately
    without credential verification. For platform service-to-service calls only.

    **External agent path:** present one or more ATB ZKP Phase 2 credential
    envelopes. Each is verified against its issuer's Falcon-1024 public key.
    """
    if _is_internal(authorization):
        return _issue_internal_token()

    result = _validator.compose(body.credentials)

    if not result.valid:
        logger.warning("compose.failed reason=%s", result.failure_reason)
        return ComposeResponse(valid=False, failure_reason=result.failure_reason)

    token = result.token
    assert token is not None

    logger.info(
        "compose.ok issuers=%s commitment=%s",
        [i.did for i in token.issuers],
        token.fed_commitment_hex[:16],
    )
    return ComposeResponse(
        valid=True,
        token=token.raw,
        fed_commitment=token.fed_commitment_hex,
        fed_nonce=token.fed_nonce_hex,
        issuers=[IssuerInfo(did=i.did, kid=i.kid, alg=i.alg) for i in token.issuers],
        expires_at=token.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        issued_at=token.issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        source="external",
    )


@app.post("/verify", response_model=VerifyResponse)
async def verify(body: VerifyRequest) -> VerifyResponse:
    """Verify a federation token's HMAC signature and expiry."""
    payload = verify_federation_token(body.token, _secret)
    if payload is None:
        return VerifyResponse(valid=False, failure_reason="invalid_or_expired")
    return VerifyResponse(valid=True, payload=payload)
