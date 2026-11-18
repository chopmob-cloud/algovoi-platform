"""
Optional auth dependencies for the issue/revoke endpoints.

``create_app`` accepts any FastAPI dependency as ``auth_dependency``. ``bearer_token_auth`` is
a bundled constant-time bearer check for a single shared token; in production plug in your own
(OIDC, mTLS, your platform's API-key auth). If no dependency is supplied the write endpoints
are OPEN — set one before deploying.
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException


def bearer_token_auth(expected_token: str):
    """Return a FastAPI dependency that requires ``Authorization: Bearer <expected_token>``."""

    async def _dep(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization.split(" ", 1)[1].strip()
        if not hmac.compare_digest(token, expected_token):
            raise HTTPException(status_code=401, detail="invalid token")
        return token

    return _dep
