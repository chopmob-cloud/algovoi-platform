"""Federation Validator HTTP service.

Wraps FederationValidator as a stateless FastAPI microservice.

Endpoints:
  POST /compose   — verify N PQC credentials, return composite federation token
  POST /verify    — verify a federation token HMAC + expiry
  GET  /health    — liveness probe

Configuration (environment variables):
  FEDERATION_VALIDATOR_SECRET   — hex-encoded HMAC key (>= 64 hex chars = 32 bytes).
                                   Optional: if unset, the secret is read from
                                   FEDERATION_VALIDATOR_SECRET_FILE, else bootstrapped
                                   and persisted under FEDERATION_DATA_DIR on first run.
  FEDERATION_VALIDATOR_SECRET_FILE — path to a file holding the hex secret (optional).
  FEDERATION_DATA_DIR           — dir for the bootstrapped secret (default /app/data;
                                   mount a volume here to persist across restarts).
  FEDERATION_ISSUER_PKS         — JSON object {"<issuer-did>": "<falcon1024-pk-base64>"}.
                                   Optional: if unset, read from FEDERATION_ISSUER_PKS_FILE,
                                   else the service starts with an empty trust set and the
                                   external /compose path rejects until issuers register.
  FEDERATION_ISSUER_PKS_FILE    — path to a JSON file of issuer public keys (optional).
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
import secrets
from datetime import datetime, timezone, timedelta
from typing import Annotated, Any

from fastapi import FastAPI, Header
from pydantic import BaseModel, Field

from algovoi_federation_validator import (
    FederationValidator,
    IssuerEntry,
    __version__,
    verify_federation_token,
)
from algovoi_federation_validator._crypto import (
    compose_commitments,
    issue_federation_token,
)

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

def _data_dir() -> str:
    """Directory for bootstrapped state (the auto-generated validator secret).
    Mount a volume here to persist it across container restarts."""
    return os.environ.get("FEDERATION_DATA_DIR", "/app/data")


def _resolve_secret() -> bytes:
    """Resolve the validator HMAC secret without ever crashing on first run.

    Order of precedence:
      1. ``FEDERATION_VALIDATOR_SECRET`` (hex) — explicit, recommended for prod.
      2. ``FEDERATION_VALIDATOR_SECRET_FILE`` — hex secret read from a mounted file.
      3. Bootstrap — ``<FEDERATION_DATA_DIR>/validator_secret.hex``: load if present,
         else generate 32 random bytes, persist (0600) and use. If that directory
         is not writable, fall back to an ephemeral per-process secret (warned;
         federation tokens then do not survive a restart).
    """
    secret_hex = os.environ.get("FEDERATION_VALIDATOR_SECRET", "").strip()
    source = "env FEDERATION_VALIDATOR_SECRET"
    if not secret_hex:
        sfile = os.environ.get("FEDERATION_VALIDATOR_SECRET_FILE", "").strip()
        if sfile and os.path.exists(sfile):
            with open(sfile, encoding="utf-8") as fh:
                secret_hex = fh.read().strip()
            source = f"file {sfile}"
        else:
            path = os.path.join(_data_dir(), "validator_secret.hex")
            try:
                if os.path.exists(path):
                    with open(path, encoding="utf-8") as fh:
                        secret_hex = fh.read().strip()
                    source = f"bootstrap file {path}"
                else:
                    os.makedirs(_data_dir(), exist_ok=True)
                    secret_hex = secrets.token_hex(32)
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(secret_hex)
                    os.chmod(path, 0o600)
                    source = f"bootstrap generated {path}"
                    logger.warning(
                        "federation.bootstrap.secret_generated path=%s "
                        "(mount a volume at %s to persist it across restarts)",
                        path, _data_dir(),
                    )
            except OSError as exc:
                secret_hex = secrets.token_hex(32)
                source = "ephemeral (data dir not writable)"
                logger.warning(
                    "federation.bootstrap.secret_ephemeral err=%s "
                    "(tokens will not survive a restart; set FEDERATION_VALIDATOR_SECRET "
                    "or a writable FEDERATION_DATA_DIR)", exc,
                )
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError as exc:
        raise RuntimeError(f"validator secret must be hex: {exc}") from exc
    if len(secret) < 32:
        raise RuntimeError("validator secret must be >= 64 hex chars (32 bytes)")
    logger.info("federation.secret source=%s", source)
    return secret


def _resolve_issuers() -> dict[str, str]:
    """Resolve the issuer trust set without crashing when none is configured yet.

    Order: ``FEDERATION_ISSUER_PKS`` (JSON) → ``FEDERATION_ISSUER_PKS_FILE`` (JSON
    file) → empty. With an empty set the service still starts and is healthy; the
    external ``/compose`` path rejects credentials until issuers are registered,
    while the internal-service token path is unaffected. An empty trust set is a
    configure-me state, not a fatal error.
    """
    issuer_pks: dict[str, str] = {}
    pks_json = os.environ.get("FEDERATION_ISSUER_PKS", "").strip()
    if not pks_json:
        pfile = os.environ.get("FEDERATION_ISSUER_PKS_FILE", "").strip()
        if pfile and os.path.exists(pfile):
            with open(pfile, encoding="utf-8") as fh:
                pks_json = fh.read().strip()
    if pks_json:
        try:
            issuer_pks = json.loads(pks_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"FEDERATION_ISSUER_PKS is not valid JSON: {exc}") from exc
        if not isinstance(issuer_pks, dict):
            raise RuntimeError('FEDERATION_ISSUER_PKS must be a JSON object {"<did>": "<pk_b64>"}')

    # Live trust-pull from the substrate-2 control plane hub, if configured.
    hub = os.environ.get("S2_HUB_URL", "").strip()
    if hub:
        from algovoi_federation_validator.hub_client import fetch_issuer_pks
        # SECURITY (2026-08-19): a plain-http hub pull is MITM-able and can inject/replace trust anchors.
        # Require https unless the operator explicitly opts into insecure transport (e.g. a trusted VPC).
        if hub.startswith("http://") and os.environ.get("S2_HUB_ALLOW_INSECURE", "").strip().lower() not in ("1", "true", "yes"):
            logger.warning("federation.hub.insecure_skipped url=%s (set S2_HUB_ALLOW_INSECURE=1 to allow http)", hub)
        else:
            try:
                hub_pks = fetch_issuer_pks(hub)
                # Locally-configured pins are the trust anchor and WIN over the hub pull, so a compromised
                # or spoofed hub cannot REPLACE a pinned issuer key — it can only ADD dids not pinned locally.
                issuer_pks = {**hub_pks, **issuer_pks}
                logger.info("federation.hub.pulled count=%d url=%s (local pins take precedence)", len(hub_pks), hub)
            except Exception as exc:  # noqa: BLE001
                logger.warning("federation.hub.pull_failed url=%s err=%s (using local trust set)", hub, exc)

    if not issuer_pks:
        logger.warning(
            "federation.bootstrap.no_issuers — external /compose will reject until issuers are "
            "registered (FEDERATION_ISSUER_PKS / FEDERATION_ISSUER_PKS_FILE / S2_HUB_URL). "
            "The internal-service token path is unaffected."
        )
    return issuer_pks


def _load_config() -> tuple[bytes, dict[str, str], int, bytes | None, int]:
    secret = _resolve_secret()
    issuer_pks = _resolve_issuers()
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


def _hub_self_register() -> None:
    """Announce this service to the substrate-2 control plane, if configured —
    set S2_HUB_URL + S2_HUB_TOKEN and it shows up in the CP posture automatically."""
    hub = os.environ.get("S2_HUB_URL", "").strip()
    token = os.environ.get("S2_HUB_TOKEN", "").strip()
    if not (hub and token):
        return
    from algovoi_federation_validator.hub_client import self_register
    ok = self_register(
        hub, token,
        name=os.environ.get("S2_HUB_NAME", "federation-validator"),
        type_="federation",
        base_url=os.environ.get("S2_HUB_SELF_URL", "http://federation-validator:8092"),
    )
    logger.info("federation.hub.self_register url=%s ok=%s", hub, ok)


_hub_self_register()

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AlgoVoi Federation Validator",
    description=(
        "Cross-issuer ZKP credential composition — compose independent "
        "Falcon-1024 PQC credentials into a single federation token "
        "without a shared trust root. "
        "IETF: draft-hopley-x402-federation-zkp-00"
    ),
    version=__version__,
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
        "version": __version__,
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


def main() -> None:
    """Console entry point — serve the federation validator."""
    import uvicorn
    # The federation validator is a reverse-proxied CONTAINER service (fronted by nginx; the container
    # port is not published to the public). Binding all interfaces inside the container is the intended
    # deployment pattern — self-hosters override FEDERATION_BIND=127.0.0.1:8092 for a local-only run.
    bind = os.environ.get("FEDERATION_BIND", "0.0.0.0:8092")  # nosec B104 - reverse-proxied container bind
    host, _, port = bind.partition(":")
    uvicorn.run(app, host=host, port=int(port or "8092"))
