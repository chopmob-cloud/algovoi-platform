"""Request/response models for the Compliance Gate app."""
from __future__ import annotations

from pydantic import BaseModel, field_validator


class ScreenRequest(BaseModel):
    network: str
    address: str                          # the payer/recipient address — used to screen, never echoed
    amount_microusd: int | None = None
    context: dict | None = None

    @field_validator("network", "address")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or len(v) > 512:
            raise ValueError("must be a non-empty string ≤ 512 chars")
        return v


class CertifiedScreenResult(BaseModel):
    result: str                           # ALLOW | REFER | DENY
    screen_provider_did: str
    payer_ref: str                        # sha256(network:address) — content-addressed, NO PII
    receipt: dict                         # the no-PII compliance receipt (proofs-compatible)
    receipt_envelope: str                 # Falcon-1024-signed, offline-verifiable
    receipt_hash: str                     # sha256 of the JCS receipt — binds into algovoi-proofs
    kid: str
    screen_timestamp_ms: int
    jurisdiction_flags: list[str]
    risk_score: int | None = None
    reasons: list[str] | None = None


class VerifyRequest(BaseModel):
    receipt_envelope: str


class VerifyResult(BaseModel):
    verified: bool
    screen_result: str | None = None
    payer_ref: str | None = None
    screen_provider_did: str | None = None
    canon_version: str | None = None
    screen_timestamp_ms: int | None = None
    jurisdiction_flags: list[str] | None = None
    kid: str | None = None
    error: str | None = None
