"""Bearer-token auth dependency factory for issue endpoints (verify endpoints stay public)."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Header, HTTPException


def bearer_token_auth(expected_token: str | None) -> Callable[..., Awaitable[None]]:
    """Return a FastAPI dependency enforcing ``Authorization: Bearer <token>``.

    If ``expected_token`` is falsy, auth is disabled (dependency is a no-op) — useful for local dev.
    """

    async def _dep(authorization: str | None = Header(default=None)) -> None:
        if not expected_token:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        if authorization[7:].strip() != expected_token:
            raise HTTPException(status_code=403, detail="invalid token")

    return _dep
