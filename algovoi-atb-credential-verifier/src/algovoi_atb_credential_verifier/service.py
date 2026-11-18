"""ATB Credential Verifier HTTP service.

Wraps the ATBCredentialVerifier library as a stateless FastAPI service so it bolts
into the substrate-2 control plane exactly like federation-validator and
zkp-receipt: it pulls its issuer trust set from the hub, self-registers, and
exposes /health + /verify. Boots clean with no configuration.

Endpoints:
  GET  /health   liveness + issuer count
  POST /verify   verify an X-ATB-Credential / X-ATB-ZK-Credential header value

Configuration (environment variables):
  ATB_VERIFIER_ISSUER_PKS       JSON {"<did>": "<falcon1024-pk-base64>"}. Optional.
  ATB_VERIFIER_ISSUER_PKS_FILE  path to the same JSON, read when the env var is unset.
  S2_HUB_URL                    substrate-2 control plane hub: live-pull the trust set.
  S2_HUB_TOKEN                  set with S2_HUB_URL to self-register with the control plane.
  ATB_VERIFIER_BIND             bind address (default 0.0.0.0:8095)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from algovoi_atb_credential_verifier import __version__
from algovoi_atb_credential_verifier.verifier import ATBCredentialVerifier

logger = logging.getLogger(__name__)


def _resolve_issuers() -> dict[str, str]:
    """Issuer trust set: ATB_VERIFIER_ISSUER_PKS env -> _FILE -> live pull from
    S2_HUB_URL. Empty is fine: the service starts healthy and /verify rejects until
    issuers are registered."""
    issuer_pks: dict[str, str] = {}
    pks_json = os.environ.get("ATB_VERIFIER_ISSUER_PKS", "").strip()
    if not pks_json:
        pfile = os.environ.get("ATB_VERIFIER_ISSUER_PKS_FILE", "").strip()
        if pfile and os.path.exists(pfile):
            with open(pfile, encoding="utf-8") as fh:
                pks_json = fh.read().strip()
    if pks_json:
        try:
            issuer_pks = json.loads(pks_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"ATB_VERIFIER_ISSUER_PKS is not valid JSON: {exc}") from exc
        if not isinstance(issuer_pks, dict):
            raise RuntimeError('ATB_VERIFIER_ISSUER_PKS must be a JSON object {"<did>": "<pk_b64>"}')

    hub = os.environ.get("S2_HUB_URL", "").strip()
    if hub:
        from algovoi_atb_credential_verifier.hub_client import fetch_issuer_pks
        try:
            issuer_pks = {**issuer_pks, **fetch_issuer_pks(hub)}
            logger.info("atb_verifier.hub.pulled url=%s", hub)
        except Exception as exc:  # noqa: BLE001
            logger.warning("atb_verifier.hub.pull_failed url=%s err=%s (using local trust set)", hub, exc)
    return issuer_pks


_issuer_pks = _resolve_issuers()
_verifier = ATBCredentialVerifier(trusted_hubs=[(did, pk) for did, pk in _issuer_pks.items()])


def _hub_self_register() -> None:
    hub = os.environ.get("S2_HUB_URL", "").strip()
    token = os.environ.get("S2_HUB_TOKEN", "").strip()
    if not (hub and token):
        return
    from algovoi_atb_credential_verifier.hub_client import self_register
    ok = self_register(
        hub, token,
        name=os.environ.get("S2_HUB_NAME", "atb-credential-verifier"),
        type_="atb-verifier",
        base_url=os.environ.get("S2_HUB_SELF_URL", "http://atb-credential-verifier:8095"),
    )
    logger.info("atb_verifier.hub.self_register url=%s ok=%s", hub, ok)


_hub_self_register()

app = FastAPI(
    title="AlgoVoi ATB Credential Verifier",
    description="Verify ATB Phase-2 (Falcon-1024 + Bulletproofs) agent-trust credentials offline.",
    version=__version__,
    docs_url="/docs",
    redoc_url=None,
)


class VerifyRequest(BaseModel):
    credential: str = Field(..., description="X-ATB-Credential / X-ATB-ZK-Credential header value (base64url).")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "atb-credential-verifier",
        "version": __version__,
        "issuer_count": len(_issuer_pks),
    }


@app.post("/verify")
async def verify(body: VerifyRequest) -> dict[str, Any]:
    # Phase-2 verify, fully offline: Falcon-1024 signature + Bulletproofs range proof
    # (via bpverify), no external ZKP service.
    r = _verifier.verify_zkp(body.credential)
    return {
        "valid": r.valid,
        "passed": r.passed,
        "kid": r.kid,
        "has_zkp": r.has_zkp,
        "threshold_milliunits": r.threshold_milliunits,
        "expires_at": r.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ") if r.expires_at else None,
        "failure_reason": r.failure_reason,
    }


def main() -> None:
    import uvicorn
    bind = os.environ.get("ATB_VERIFIER_BIND", "0.0.0.0:8095")
    host, _, port = bind.partition(":")
    uvicorn.run(app, host=host, port=int(port or "8095"))
