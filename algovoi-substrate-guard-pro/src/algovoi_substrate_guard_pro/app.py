"""Optional FastAPI surface for the admission gate.

``POST /guard`` evaluates a JSON value and returns the signed admission decision; ``GET /profile``
returns the bounds in force and their ``profile_ref``; ``GET /chain`` returns the current envelope chain.
Bearer-token auth is optional (pass ``auth_dependency``). Depends on fastapi/pydantic (the ``serve`` extra
adds uvicorn).
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from algovoi_substrate_guard_pro.service import GuardService


class GuardRequest(BaseModel):
    value: Any
    expires_in_s: int | None = None


def bearer_token_auth(token: str) -> Callable:
    async def _dep(authorization: str | None = Header(default=None)) -> None:
        if authorization != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")
    return _dep


def create_app(service: GuardService, *, auth_dependency: Callable | None = None) -> FastAPI:
    app = FastAPI(title="AlgoVoi Substrate Guard (Pro)", version="0.1.0")
    deps = [Depends(auth_dependency)] if auth_dependency else []

    @app.get("/profile", dependencies=deps)
    def profile() -> dict:
        return {"profile_ref": service.profile_ref, "profile": service.profile.snapshot()}

    @app.post("/guard", dependencies=deps)
    def guard_endpoint(req: GuardRequest) -> dict:
        r = service.evaluate(req.value, expires_in_s=req.expires_in_s)
        return {
            "admitted": r.admitted, "decision": r.decision, "reject_code": r.reject_code,
            "profile_ref": r.profile_ref, "guard_decision_ref": r.guard_decision_ref,
            "subject_ref": r.subject_ref, "evaluated_at": r.evaluated_at,
            "hybrid": r.hybrid, "envelope": r.envelope,
        }

    @app.get("/chain", dependencies=deps)
    def chain() -> dict:
        return {"count": service.ledger.seq, "envelopes": service.ledger.envelopes}

    return app


__all__ = ["create_app", "bearer_token_auth", "GuardRequest"]
