"""Result dataclasses for evaluation and offline verification."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GuardResult:
    """Outcome of evaluating one value against the gate."""
    admitted: bool
    decision: str                      # "ADMIT" | "REJECT"
    profile_ref: str
    guard_decision_ref: str
    evaluated_at: str
    reject_code: str | None = None     # set on REJECT (e.g. REJECT_INVALID_UTF8)
    subject_ref: str | None = None     # set on ADMIT
    envelope: str | None = None        # signed chain envelope, if a ledger is attached
    hybrid: bool = False


@dataclass(frozen=True)
class VerifyDecisionResult:
    verified: bool
    decision: str | None = None
    reject_code: str | None = None
    profile_ref: str | None = None
    subject_ref: str | None = None
    guard_decision_ref: str | None = None
    kid: str | None = None
    evaluated_at: str | None = None
    hybrid: bool = False
    error: str | None = None


@dataclass(frozen=True)
class ChainVerifyResult:
    verified: bool
    count: int = 0
    first_bad_seq: int | None = None
    hybrid: bool = False
    error: str | None = None
