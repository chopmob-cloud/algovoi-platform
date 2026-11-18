"""Mandate Auditor HTTP service.

Mounts as a standalone FastAPI app or as a router onto an existing app.

Endpoints:
  GET  /v1/audit/{kid}/{mandate_id}          — live audit report (JSON)
  GET  /v1/audit/{kid}/{mandate_id}/export   — downloadable audit pack (attachment)
  GET  /health                               — liveness probe

Configuration (environment):
  MANDATE_AUDITOR_BIND   — bind address (default 127.0.0.1:8097; loopback)
  MANDATE_STORE_PATH     — path to the SQLite mandates.db (default mandates.db)
  MANDATE_KID            — key-id filter; if set, only serves this kid
  MANDATE_AUDITOR_TOKEN  — bearer token required on the audit endpoints; required for a non-loopback bind

IETF anchor: draft-hopley-x402-retention-chain (retention-chain primitive)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, Response

from algovoi_mandate_auditor import __version__
from algovoi_mandate_auditor import licensing as _licensing
from algovoi_mandate_auditor.audit import AuditReport, build_audit_report, verify_audit_report
from algovoi_payment_mandate.store import MandateStore, SqliteStore


def bearer_token_auth(token: str) -> Callable:
    """A bearer-token dependency for the audit endpoints (timing-safe compare)."""
    import hmac

    async def _dep(authorization: str | None = Header(default=None)) -> None:
        expected = f"Bearer {token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")
    return _dep


def create_auditor_app(store: MandateStore, *, kid: str | None = None,
                       auth_dependency: Callable | None = None) -> FastAPI:
    """Build an auditor FastAPI app backed by an existing MandateStore.

    Args:
        store: The same MandateStore used by the mandate issuer.
        kid: If provided, the app only serves audit reports for this key-id.
        auth_dependency: If provided, guards the audit endpoints (the charge history is a regulated
            ledger; leaving it open discloses every amount/charge_id/timestamp to any caller). ``health``
            stays open for liveness probes.
    """
    _licensing.require_license()
    # SECURITY (2026-08-19): the audit endpoints expose the full authorized-charge history, so they must
    # be authenticated. When an auth dependency is configured it is applied to both audit routes below.
    audit_deps = [Depends(auth_dependency)] if auth_dependency else []

    app = FastAPI(
        title="AlgoVoi Mandate Auditor",
        description=(
            "Mandate Auditor Suite — build and verify self-contained retention-chain audit "
            "reports for payment mandate charge histories. Any party can verify a downloaded "
            "audit pack offline with no AlgoVoi infrastructure. "
            "Regulatory: MiCA Art. 68(9), DORA Art. 17, AMLR Art. 77."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url=None,
    )

    async def _report(req_kid: str, mandate_id: str) -> AuditReport:
        if kid is not None and req_kid != kid:
            raise HTTPException(status_code=403, detail="kid not served by this auditor")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        report = await build_audit_report(store, kid=req_kid, mandate_id=mandate_id, generated_at=now)
        if report.record_count == 0:
            # Still return an empty report — zero charges is a valid state.
            pass
        return report

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "mandate-auditor", "version": __version__}

    @app.get("/v1/audit/{req_kid}/{mandate_id}", response_model=AuditReport, dependencies=audit_deps)
    async def audit_report(req_kid: str, mandate_id: str) -> AuditReport:
        """Live audit report — all authorized charges with their chain refs, chain verified."""
        report = await _report(req_kid, mandate_id)
        valid, reason = verify_audit_report(report)
        # Surface verification state in a response header; the body is always returned.
        headers = {"X-Chain-Verified": "true" if valid else f"false:{reason}"}
        return JSONResponse(content=report.model_dump(), headers=headers)

    @app.get("/v1/audit/{req_kid}/{mandate_id}/export", dependencies=audit_deps)
    async def audit_export(req_kid: str, mandate_id: str) -> Response:
        """Downloadable audit pack — self-contained JSON the payer can verify offline."""
        report = await _report(req_kid, mandate_id)
        valid, reason = verify_audit_report(report)
        payload = report.model_dump()
        payload["_chain_verified_at_export"] = report.generated_at
        payload["_chain_valid"] = valid
        if reason:
            payload["_chain_failure"] = reason
        filename = f"mandate-audit-{mandate_id[:8]}.json"
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return app


def main() -> None:
    """Console entry point — serve the mandate auditor."""
    import uvicorn

    store_path = os.environ.get("MANDATE_STORE_PATH", "mandates.db")
    kid_filter = os.environ.get("MANDATE_KID") or None
    store = SqliteStore(store_path)

    bind = os.environ.get("MANDATE_AUDITOR_BIND", "127.0.0.1:8097")
    host, _, port = bind.partition(":")
    token = os.environ.get("MANDATE_AUDITOR_TOKEN") or None
    # SECURITY (2026-08-19): the audit ledger must never be exposed unauthenticated on a public bind.
    # A non-loopback bind REQUIRES a bearer token; loopback may run open for local/dev use.
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            "refusing to bind the mandate auditor to a non-loopback address without MANDATE_AUDITOR_TOKEN "
            "(the audit endpoints disclose the full charge history)")
    auth = bearer_token_auth(token) if token else None
    app = create_auditor_app(store, kid=kid_filter, auth_dependency=auth)

    uvicorn.run(app, host=host, port=int(port or "8097"))
