"""Bearer-token auth dependency factory for the screening endpoint (verify stays public)."""
from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable

from fastapi import Header, HTTPException


def bearer_token_auth(expected_token: str | None) -> Callable[..., Awaitable[None]]:
    """Return a FastAPI dependency enforcing ``Authorization: Bearer <token>``.

    If ``expected_token`` is falsy, auth is disabled (no-op) — for local dev only; a production
    deployment must configure a token and should never bind a protected endpoint publicly without one.
    """

    async def _dep(authorization: str | None = Header(default=None)) -> None:
        if not expected_token:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        # constant-time compare so the token cannot be recovered by response timing
        if not hmac.compare_digest(authorization[7:].strip(), expected_token):
            raise HTTPException(status_code=403, detail="invalid token")

    return _dep
