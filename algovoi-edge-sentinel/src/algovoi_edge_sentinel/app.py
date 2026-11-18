"""Optional FastAPI surface + ASGI middleware for the edge sentinel.

``create_app(sentinel)`` exposes ``POST /evaluate`` (evaluate an explicit RequestContext and return the
signed decision), ``GET /policy`` (the policy in force + its ``policy_ref``) and ``GET /chain``.
``EdgeMiddleware`` runs the sentinel ahead of the app for real traffic: it builds a RequestContext from
the connection + headers, and on BLOCK returns 403 with the named reason code (the signed decision is
already chained). Depends on fastapi/pydantic/starlette.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from algovoi_edge_sentinel.models import RequestContext
from algovoi_edge_sentinel.sentinel import EdgeSentinel


class EvaluateRequest(BaseModel):
    ip: str | None = None
    country: str | None = None
    asn: int | None = None
    agent_did: str | None = None
    key_id: str | None = None
    wallet: str | None = None
    nonce: str | None = None
    timestamp: str | None = None


def _result_dict(r) -> dict:
    return {"allowed": r.allowed, "decision": r.decision, "check": r.check,
            "reason_code": r.reason_code, "policy_ref": r.policy_ref, "subject_ref": r.subject_ref,
            "edge_decision_ref": r.edge_decision_ref, "evaluated_at": r.evaluated_at,
            "hybrid": r.hybrid, "envelope": r.envelope}


def bearer_token_auth(token: str) -> Callable:
    async def _dep(authorization: str | None = Header(default=None)) -> None:
        if authorization != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")
    return _dep


def create_app(sentinel: EdgeSentinel, *, auth_dependency: Callable | None = None) -> FastAPI:
    app = FastAPI(title="AlgoVoi Edge Sentinel", version="0.1.0")
    deps = [Depends(auth_dependency)] if auth_dependency else []

    @app.get("/policy", dependencies=deps)
    def policy() -> dict:
        return {"policy_ref": sentinel.policy_ref, "policy": sentinel.policy.snapshot()}

    @app.post("/evaluate", dependencies=deps)
    def evaluate(req: EvaluateRequest) -> dict:
        return _result_dict(sentinel.evaluate(RequestContext(**req.model_dump())))

    @app.get("/chain", dependencies=deps)
    def chain() -> dict:
        return {"count": sentinel.ledger.seq, "envelopes": sentinel.ledger.envelopes}

    return app


class EdgeMiddleware(BaseHTTPMiddleware):
    """Run the sentinel ahead of the wrapped app; BLOCK -> 403 with the named reason code.

    ``context_from`` maps a Starlette request to a RequestContext (override to pull DID / nonce from your
    auth headers). The default uses the real TCP peer as the client IP and reads the ``CF-IPCountry`` /
    nonce / timestamp headers.

    SECURITY: ``X-Forwarded-For`` is client-settable, so the default does NOT trust it. If the app runs
    behind reverse proxies, set ``trusted_proxy_hops`` to the number of trusted proxies that append to XFF;
    the client IP is then taken from the entry just left of those trusted hops. With ``trusted_proxy_hops=0``
    (default) the immediate TCP peer (``request.client.host``) is used and XFF is ignored, so a spoofed
    leftmost XFF cannot forge the IP used for geo/CIDR/rate-limit decisions."""

    def __init__(self, app, sentinel: EdgeSentinel, context_from: Callable | None = None,
                 *, trusted_proxy_hops: int = 0) -> None:
        super().__init__(app)
        self.sentinel = sentinel
        self.trusted_proxy_hops = max(0, int(trusted_proxy_hops))
        self.context_from = context_from or self._default_context

    def _client_ip(self, request) -> str | None:
        peer = request.client.host if request.client else None
        hops = self.trusted_proxy_hops
        if hops <= 0:
            return peer  # do not trust client-settable X-Forwarded-For
        xff = request.headers.get("x-forwarded-for")
        if not xff:
            return peer
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        # entries [-hops:] were appended by trusted proxies; the client is the one just left of them
        idx = len(parts) - hops - 1
        return parts[idx] if 0 <= idx < len(parts) else peer

    def _default_context(self, request) -> RequestContext:
        return RequestContext(ip=self._client_ip(request), country=request.headers.get("cf-ipcountry"),
                              agent_did=request.headers.get("x-agent-did"),
                              nonce=request.headers.get("x-nonce"),
                              timestamp=request.headers.get("x-timestamp"))

    async def dispatch(self, request, call_next):
        result = self.sentinel.evaluate(self.context_from(request))
        if not result.allowed:
            return JSONResponse(status_code=403, content={"error": "blocked",
                                "reason_code": result.reason_code, "check": result.check,
                                "edge_decision_ref": result.edge_decision_ref})
        return await call_next(request)


__all__ = ["create_app", "bearer_token_auth", "EvaluateRequest", "EdgeMiddleware"]
