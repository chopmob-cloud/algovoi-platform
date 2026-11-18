"""
Content-addressed decision refs — the bridge from the open *lite* surface to the commercial gate.

The open ``algovoi-spend-guardrail-lite`` package publishes a content-addressed
``guardrail_ref`` that AP2/A2A adopters pin (corpus set ``spend_guardrail_lite_v1``)::

    guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))

The commercial gate computes the *same* construction over refs it **derives from the credentials it
actually verified** (not opaque refs taken on faith), so a paid ALLOW/DENY recomputes byte-for-byte the
ref the lite adopter pinned. That is what makes the lite tier a true feeder: the commercial decision is
provably the same decision, now signed, chained, and CCC-ingestable.

Every ref here is the RFC 8785 (JCS) canonical hash used across the suite; ``_prefixed`` reproduces
``algovoi_substrate.sha256_jcs`` byte-for-byte (verified against the published corpus vectors), so this
module carries no new dependency beyond the ``rfc8785`` the signing layer already pulls in.
"""
from __future__ import annotations

import hashlib
import re

import rfc8785

VERDICTS = ("ALLOW", "DENY", "REFER")  # closed enum; lite is {ALLOW, DENY}, commercial adds REFER (Cap C)
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _prefixed(value) -> str:
    """``"sha256:" + SHA-256(JCS(value))`` — identical bytes to ``algovoi_substrate.sha256_jcs``."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def is_ref(value) -> bool:
    return isinstance(value, str) and bool(_REF_RE.match(value))


def passport_ref(passport_payload: dict) -> str:
    """Derive the agent's content address from a *verified* Agent Passport payload.

    ``passport_ref = "sha256:" + SHA-256(JCS({agent_id, issuer, scope, validity_window}))`` — the open
    ``passport_ref`` construction, computed here from the credential the gate just checked.
    """
    return _prefixed({
        "agent_id": passport_payload.get("agent_did"),
        "issuer": passport_payload.get("issuer_did"),
        "scope": list(passport_payload.get("scopes") or []),
        "validity_window": {
            "issued_at": passport_payload.get("issued_at"),
            "expires_at": passport_payload.get("expires_at"),
        },
    })


def mandate_ref(mandate_payload: dict, *, revocation_state: str) -> str:
    """Derive the spend authority's content address from a Payment Mandate payload.

    ``mandate_ref = "sha256:" + SHA-256(JCS({payer, cap, period, revocation_state}))``. ``revocation_state``
    is the live status the gate observed (``"active"`` / ``"revoked"``) so a revoked mandate addresses
    differently from the same mandate while live.
    """
    return _prefixed({
        "payer": mandate_payload.get("payer"),
        "cap": int(mandate_payload.get("max_amount") or 0),
        "period": mandate_payload.get("period"),
        "revocation_state": revocation_state,
    })


def policy_ref(policy_document: dict) -> str:
    """``policy_ref = "sha256:" + SHA-256(JCS(policy_document))`` (algovoi-policy-binding construction)."""
    return _prefixed(policy_document)


def policy_bound_ref(*, policy_ref_: str, subject_ref: str) -> str:
    """``policy_bound_ref = "sha256:" + SHA-256(JCS({policy_ref, subject_ref}))`` — binds the policy
    snapshot in force to the subject it was applied to (here, the agent)."""
    return _prefixed({"policy_ref": policy_ref_, "subject_ref": subject_ref})


def decision_ref(*, verdict: str, agent_ref: str, mandate_ref_: str, policy_bound_ref_: str) -> str:
    """The published ``guardrail_ref`` construction — byte-identical to corpus ``spend_guardrail_lite_v1``.

    Raises ``ValueError`` on an out-of-enum verdict or a non-``sha256:`` input ref (fail-closed; the lite
    runner does the same).
    """
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    for name, val in (("agent_ref", agent_ref), ("mandate_ref", mandate_ref_),
                      ("policy_bound_ref", policy_bound_ref_)):
        if not is_ref(val):
            raise ValueError(f"{name} must be a sha256: ref")
    return _prefixed({
        "agent_ref": agent_ref,
        "mandate_ref": mandate_ref_,
        "policy_bound_ref": policy_bound_ref_,
        "verdict": verdict,
    })
