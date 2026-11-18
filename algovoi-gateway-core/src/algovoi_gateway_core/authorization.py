"""
Bind an outbound payout to an authorizing Spend Guardrail decision.

The gateway proves *settlement*; the Spend Guardrail decides *whether a spend is allowed* (verify the
Agent Passport + Payment Mandate + policy, return a signed ALLOW/DENY decision). Cap D closes the loop:
when configured to, the gateway will sign a custody payout **only** against a fresh, signature-valid
``ALLOW`` decision for the same amount and destination, and records the decision's ``decision_ref`` into
the payout receipt as ``authorized_by_ref`` — so an auditor sees authorized -> settled as one chain in the
Compliance Command Center.

This verifies the guardrail's decision envelope with the gateway's own crypto core (``substrate2`` Falcon),
so the two products are tied by the signed wire format, not by a code dependency.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import substrate2
from substrate2.pqc import verify_falcon_1024 as _falcon_verify

DECISION_TYPE = "spend_decision"


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _expired(iso: str | None) -> bool:
    if not iso:
        return False
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return False
    return datetime.now(timezone.utc) >= exp


@dataclass
class AuthorizationResult:
    ok: bool
    decision_ref: str | None = None
    decision_id: str | None = None
    reason: str = "ok"


def verify_authorization(
    decision_receipt: str,
    guardrail_public_key: bytes,
    *,
    amount_minor: int,
    pay_to: str | None = None,
) -> AuthorizationResult:
    """Verify a Spend Guardrail decision authorizes *this* payout (never raises).

    Passes only when the receipt is a signature-valid ``spend_decision`` that is ``ALLOW``, not past its
    freshness window, for exactly ``amount_minor`` and (if given) ``pay_to``. The payout destination must
    equal the decision's ``payee`` — issue the authorizing decision with ``payee`` set to the destination.
    """
    try:
        env = json.loads(_b64u_decode(decision_receipt))
        payload = env["payload"]
        sig = _b64u_decode(env["sig"])
    except Exception:  # noqa: BLE001
        return AuthorizationResult(False, reason="malformed_decision")
    if payload.get("type") != DECISION_TYPE:
        return AuthorizationResult(False, reason="not_a_spend_decision")
    if not _falcon_verify(guardrail_public_key, substrate2.canonicalize_bytes(payload), sig):
        return AuthorizationResult(False, reason="bad_signature")
    d_ref, d_id = payload.get("decision_ref"), payload.get("decision_id")
    if payload.get("decision") != "ALLOW":
        return AuthorizationResult(False, d_ref, d_id, reason=f"not_allow:{payload.get('decision')}")
    if _expired(payload.get("expires_at")):
        return AuthorizationResult(False, d_ref, d_id, reason="decision_expired")
    if int(payload.get("amount") or -1) != int(amount_minor):
        return AuthorizationResult(False, d_ref, d_id, reason="amount_mismatch")
    # SECURITY (2026-08-19): bind the destination fail-closed. Previously a decision with no `payee`
    # skipped this check, so an ALLOW that omitted the payee authorized a payout to ANY address. When
    # the caller passes the destination, the decision must name that exact payee.
    if pay_to is not None and payload.get("payee") != pay_to:
        return AuthorizationResult(False, d_ref, d_id, reason="payee_mismatch")
    return AuthorizationResult(True, d_ref, d_id, reason="ok")


__all__ = ["AuthorizationResult", "verify_authorization", "DECISION_TYPE"]
