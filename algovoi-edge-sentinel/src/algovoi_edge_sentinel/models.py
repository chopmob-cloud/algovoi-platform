"""Request context and result dataclasses."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RequestContext:
    """What the edge layer evaluates. All fields optional; checks that lack their input no-op (a check
    cannot block on a signal it was not given). ``timestamp`` is the request's claimed ISO-8601 Z time
    (for freshness); ``country``/``asn`` may be pre-resolved (e.g. from a CDN header) or left to the geo
    provider to resolve from ``ip``."""
    ip: str | None = None
    country: str | None = None
    asn: int | None = None
    agent_did: str | None = None
    key_id: str | None = None
    wallet: str | None = None
    nonce: str | None = None
    timestamp: str | None = None


@dataclass(frozen=True)
class EdgeResult:
    allowed: bool
    decision: str                  # "ALLOW" | "BLOCK"
    check: str                     # which check decided ("geo"|"identity"|"rate"|"replay"|"none")
    reason_code: str               # named code (e.g. BLOCK_GEO_COUNTRY) or "ALLOW"
    policy_ref: str
    subject_ref: str
    edge_decision_ref: str
    evaluated_at: str
    envelope: str | None = None    # signed chain envelope, if recorded
    hybrid: bool = False


@dataclass(frozen=True)
class VerifyDecisionResult:
    verified: bool
    decision: str | None = None
    check: str | None = None
    reason_code: str | None = None
    policy_ref: str | None = None
    subject_ref: str | None = None
    edge_decision_ref: str | None = None
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
