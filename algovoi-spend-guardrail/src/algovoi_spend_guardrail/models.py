"""Request/response models for the Spend Guardrail app."""
from __future__ import annotations

from pydantic import BaseModel, field_validator

MAX_AMOUNT = 10**18


class AuthorizeRequest(BaseModel):
    passport_credential: str          # the agent's Agent Passport
    mandate: str                      # the payer's Payment Mandate
    charge_id: str                    # idempotency key for the mandate ledger
    amount: int                       # minor units
    payee: str
    asset: str | None = None
    at: str | None = None             # ISO8601 instant of the charge; defaults to now
    expected_agent_did: str | None = None

    @field_validator("passport_credential", "mandate", "charge_id", "payee")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or len(v) > 4096:
            raise ValueError("must be a non-empty string")
        return v

    @field_validator("amount")
    @classmethod
    def _amt(cls, v: int) -> int:
        if v <= 0 or v > MAX_AMOUNT:
            raise ValueError(f"amount must be 1..{MAX_AMOUNT}")
        return v


class DecisionResult(BaseModel):
    allowed: bool
    decision: str                     # ALLOW | DENY | REFER
    reasons: list[str] = []
    decision_id: str | None = None
    decision_receipt: str | None = None   # Falcon-signed, offline-verifiable
    agent_did: str | None = None
    charge_id: str | None = None
    amount: int | None = None
    asset: str | None = None
    payee: str | None = None
    mandate_id: str | None = None
    remaining_this_period: int | None = None
    passport_kid: str | None = None
    kid: str | None = None
    evaluated_at: str | None = None
    expires_at: str | None = None             # decision freshness window (replay protection)
    # content-addressed refs — decision_ref recomputes the published lite guardrail_ref byte-for-byte
    agent_ref: str | None = None
    mandate_ref: str | None = None
    policy_bound_ref: str | None = None
    decision_ref: str | None = None
    # position in the tamper-evident decision chain
    seq: int | None = None
    prev_entry_hash: str | None = None


class VerifyDecisionRequest(BaseModel):
    decision_receipt: str


class VerifyDecisionResult(BaseModel):
    verified: bool
    decision: str | None = None
    decision_id: str | None = None
    agent_did: str | None = None
    charge_id: str | None = None
    amount: int | None = None
    payee: str | None = None
    reasons: list[str] | None = None
    kid: str | None = None
    evaluated_at: str | None = None
    expires_at: str | None = None
    decision_ref: str | None = None
    expired: bool | None = None       # True if the freshness window has passed (still signature-valid)
    hybrid: bool | None = None        # True if a second (ML-DSA-65) signature was present and verified
    error: str | None = None


class ChainVerifyResult(BaseModel):
    """Result of verifying a whole exported decision chain."""
    verified: bool
    count: int = 0
    first_bad_seq: int | None = None
    hybrid: bool | None = None        # True if every entry carried a verified ML-DSA-65 co-signature
    error: str | None = None
