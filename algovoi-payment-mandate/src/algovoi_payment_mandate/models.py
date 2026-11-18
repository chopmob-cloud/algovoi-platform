"""Request/response models for the Payment Mandate app."""
from __future__ import annotations

from pydantic import BaseModel, field_validator

from algovoi_payment_mandate.periods import VALID_PERIODS

MAX_TTL_SECS = 31_536_000 * 5  # 5 years — mandates can be long-lived
MAX_AMOUNT = 10**18            # sanity ceiling, minor units


class IssueRequest(BaseModel):
    payer: str                          # account / wallet ref or DID being charged
    payee: str                          # who may charge (merchant / agent ref or DID)
    asset: str = "USDC"
    chain: str = "*"
    max_amount: int                     # per-period cap, minor units (e.g. micro-USD)
    period: str = "month"
    max_per_charge: int | None = None   # optional single-charge ceiling
    scope: list[str] = []               # what it may be charged for
    ttl_secs: int = 31_536_000          # 1 year

    @field_validator("payer", "payee")
    @classmethod
    def _ref(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("payer/payee must be a non-empty ref ≤ 256 chars")
        return v

    @field_validator("max_amount")
    @classmethod
    def _amt(cls, v: int) -> int:
        if v <= 0 or v > MAX_AMOUNT:
            raise ValueError(f"max_amount must be 1..{MAX_AMOUNT} (minor units)")
        return v

    @field_validator("max_per_charge")
    @classmethod
    def _mpc(cls, v: int | None) -> int | None:
        if v is not None and (v <= 0 or v > MAX_AMOUNT):
            raise ValueError(f"max_per_charge must be 1..{MAX_AMOUNT}")
        return v

    @field_validator("period")
    @classmethod
    def _period(cls, v: str) -> str:
        if v not in VALID_PERIODS:
            raise ValueError(f"period must be one of {sorted(VALID_PERIODS)}")
        return v

    @field_validator("scope")
    @classmethod
    def _scope(cls, v: list[str]) -> list[str]:
        if len(v) > 64 or any((not isinstance(s, str)) or len(s) > 128 for s in v):
            raise ValueError("scope must be ≤ 64 strings of ≤ 128 chars")
        return v

    @field_validator("ttl_secs")
    @classmethod
    def _ttl(cls, v: int) -> int:
        if v < 60 or v > MAX_TTL_SECS:
            raise ValueError(f"ttl_secs must be 60..{MAX_TTL_SECS}")
        return v


class IssueResponse(BaseModel):
    mandate_id: str
    mandate: str            # the signed mandate credential (base64url envelope)
    kid: str
    expires_at: str
    status_url: str


class VerifyRequest(BaseModel):
    mandate: str
    required_scope: str | None = None
    expected_payee: str | None = None


class VerifyResult(BaseModel):
    verified: bool
    status: str  # active | revoked | expired | invalid | unknown
    mandate_id: str | None = None
    payer: str | None = None
    payee: str | None = None
    asset: str | None = None
    chain: str | None = None
    max_amount: int | None = None
    period: str | None = None
    max_per_charge: int | None = None
    scope: list[str] | None = None
    kid: str | None = None
    expires_at: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class ChargeAuthorizationRequest(BaseModel):
    mandate: str
    charge_id: str          # idempotency key — re-presenting returns the prior decision
    amount: int
    payee: str | None = None
    asset: str | None = None
    at: str | None = None   # ISO8601 instant of the charge; defaults to now (UTC)

    @field_validator("charge_id")
    @classmethod
    def _cid(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("charge_id must be a non-empty string ≤ 128 chars")
        return v

    @field_validator("amount")
    @classmethod
    def _amt(cls, v: int) -> int:
        if v <= 0 or v > MAX_AMOUNT:
            raise ValueError(f"amount must be 1..{MAX_AMOUNT} (minor units)")
        return v


class ChargeAuthorizationResult(BaseModel):
    authorized: bool
    mandate_id: str | None = None
    kid: str | None = None
    charge_id: str | None = None
    amount: int | None = None
    asset: str | None = None
    period: str | None = None
    period_key: str | None = None
    period_total_after: int | None = None       # sum of authorized charges in the period (incl. this one)
    remaining_this_period: int | None = None
    idempotent: bool = False
    decline_reason: str | None = None
    chain_seq: int | None = None                # position in the mandate's retention chain (authorized charges only)
    chain_ref: str | None = None                # sha256:<64-hex> linking this charge into the audit chain


class RevokeRequest(BaseModel):
    mandate_id: str
    reason: str | None = None
