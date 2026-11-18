"""Request/response models for the Proofs app."""
from __future__ import annotations

from pydantic import BaseModel, field_validator

SCREEN_RESULTS = {"ALLOW", "REFER", "DENY"}
MAX_TTL_SECS = 31_536_000


class PaymentIn(BaseModel):
    payment_id: str
    chain: str
    amount_microusd: int
    recipient: str
    tx_id: str
    settled_at: str | None = None


class IssueRequest(BaseModel):
    payment: PaymentIn
    screen_result: str = "ALLOW"
    score_milliunits: int
    threshold_milliunits: int
    ttl_secs: int = 604_800  # 7 days
    jurisdiction_flags: list[str] = ["UK", "EU"]

    @field_validator("screen_result")
    @classmethod
    def _screen(cls, v: str) -> str:
        if v not in SCREEN_RESULTS:
            raise ValueError(f"screen_result must be one of {sorted(SCREEN_RESULTS)}")
        return v

    @field_validator("score_milliunits", "threshold_milliunits")
    @classmethod
    def _milli(cls, v: int) -> int:
        if v < 0 or v > 1000:
            raise ValueError("milliunits must be 0..1000")
        return v

    @field_validator("ttl_secs")
    @classmethod
    def _ttl(cls, v: int) -> int:
        if v < 60 or v > MAX_TTL_SECS:
            raise ValueError(f"ttl_secs must be 60..{MAX_TTL_SECS}")
        return v


class IssueResponse(BaseModel):
    proof_envelope: str
    compliance_receipt: dict | None = None
    kid: str
    expires_at: str


class VerifyRequest(BaseModel):
    proof_envelope: str
    verify_range_proof: bool = True
    compliance_receipt: dict | None = None


class VerifyResult(BaseModel):
    verified: bool
    payment_id: str | None = None
    chain: str | None = None
    amount_microusd: int | None = None
    tx_id: str | None = None
    threshold_milliunits: int | None = None
    compliance_verified: bool | None = None
    range_proof_valid: bool | None = None
    issuer_did: str | None = None
    kid: str | None = None
    expires_at: str | None = None
    failure_reason: str | None = None
