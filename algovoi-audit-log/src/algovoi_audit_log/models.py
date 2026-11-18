"""Request/response models for the Verifiable Audit Log app."""
from __future__ import annotations

from pydantic import BaseModel, field_validator

MAX_EVENT_KEYS = 256


class AppendRequest(BaseModel):
    event_type: str
    event: dict
    actor: str | None = None

    @field_validator("event_type")
    @classmethod
    def _etype(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("event_type must be a non-empty string ≤ 256 chars")
        return v

    @field_validator("event")
    @classmethod
    def _event(cls, v: dict) -> dict:
        if len(v) > MAX_EVENT_KEYS:
            raise ValueError(f"event must have ≤ {MAX_EVENT_KEYS} keys")
        return v


class AppendResponse(BaseModel):
    seq: int
    event_id: str
    event_type: str
    event_hash: str
    prev_entry_hash: str | None = None
    receipt: str                  # the Falcon-signed entry envelope (base64url)
    kid: str
    recorded_at: str


class VerifyEntryRequest(BaseModel):
    receipt: str


class VerifyEntryResult(BaseModel):
    verified: bool
    status: str  # valid | invalid
    seq: int | None = None
    event_id: str | None = None
    event_type: str | None = None
    event_hash: str | None = None
    actor: str | None = None
    prev_entry_hash: str | None = None
    recorded_at: str | None = None
    kid: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class VerifyChainResult(BaseModel):
    valid: bool
    length: int
    head_entry_hash: str | None = None
    broken_at: int | None = None
    reason: str | None = None
