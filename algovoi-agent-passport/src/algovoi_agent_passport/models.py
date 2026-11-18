"""Request/response models for the Agent Passport app."""
from __future__ import annotations

from pydantic import BaseModel, field_validator

VALID_WINDOWS = {"per_tx", "per_day", "per_week", "per_month", "total"}
MAX_TTL_SECS = 31_536_000  # 1 year


class IssueRequest(BaseModel):
    agent_did: str
    scopes: list[str] = []
    spend_limit_microusd: int | None = None
    spend_window: str | None = None
    ttl_secs: int = 2_592_000  # 30 days

    @field_validator("agent_did")
    @classmethod
    def _did(cls, v: str) -> str:
        if not v.startswith("did:") or len(v) > 256:
            raise ValueError("agent_did must be a DID (did:web:… / did:key:…) ≤ 256 chars")
        return v

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        if len(v) > 64 or any((not isinstance(s, str)) or len(s) > 128 for s in v):
            raise ValueError("scopes must be ≤ 64 strings of ≤ 128 chars")
        return v

    @field_validator("spend_window")
    @classmethod
    def _window(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_WINDOWS:
            raise ValueError(f"spend_window must be one of {sorted(VALID_WINDOWS)}")
        return v

    @field_validator("ttl_secs")
    @classmethod
    def _ttl(cls, v: int) -> int:
        if v < 60 or v > MAX_TTL_SECS:
            raise ValueError(f"ttl_secs must be 60..{MAX_TTL_SECS}")
        return v


class IssueResponse(BaseModel):
    passport_id: str
    credential: str
    kid: str
    expires_at: str
    status_url: str


class VerifyRequest(BaseModel):
    credential: str
    required_scope: str | None = None
    expected_agent_did: str | None = None


class VerifyResult(BaseModel):
    verified: bool
    status: str  # active | revoked | expired | invalid | unknown
    agent_did: str | None = None
    scopes: list[str] | None = None
    spend_limit_microusd: int | None = None
    kid: str | None = None
    expires_at: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class RevokeRequest(BaseModel):
    passport_id: str
    reason: str | None = None
