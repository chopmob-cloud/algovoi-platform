"""Bearer-token auth dependency factory for write endpoints (verify stays public)."""
from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable

from fastapi import Header, HTTPException


def bearer_token_auth(expected_token: str | None) -> Callable[..., Awaitable[None]]:
    """Return a FastAPI dependency enforcing ``Authorization: Bearer <token>``.

    If ``expected_token`` is falsy, auth is disabled (no-op) — useful for local dev.
    """

    async def _dep(authorization: str | None = Header(default=None)) -> None:
        if not expected_token:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        # constant-time compare — must not be timing-observable; encode so a non-ASCII token
        # yields a clean 403 (compare_digest on str rejects non-ASCII) rather than a 500
        if not hmac.compare_digest(authorization[7:].strip().encode("utf-8"),
                                   expected_token.encode("utf-8")):
            raise HTTPException(status_code=403, detail="invalid token")

    return _dep
