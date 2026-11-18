"""Request models for the Archive Auditor app (responses are returned as plain dicts)."""
from __future__ import annotations

from pydantic import BaseModel, field_validator


class RetentionPolicyIn(BaseModel):
    default_days: int | None = None
    by_content_type: dict[str, int] = {}

    @field_validator("default_days")
    @classmethod
    def _days(cls, v: int | None) -> int | None:
        if v is not None and (v < 0 or v > 365_000):
            raise ValueError("default_days must be 0..365000")
        return v


class AttestRequest(BaseModel):
    prev_attestation_hash: str | None = None


class EvidencePackRequest(BaseModel):
    seqs: list[int] | None = None
