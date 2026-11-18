"""substrate2.keystone_secure — flow-point hardening refs for the keystone lifecycle.

Each canonical flow point emits an open content-addressed ref (the recomputable ruler). Several points
are *bare*: the ref proves a fact was recorded but not that it was recorded *correctly* or *freshly*.
This module adds four securing refs, each a pure ``"sha256:" + SHA-256(JCS(preimage))`` (byte-identical
to every other keystone ref), that a verifier recomputes offline:

  decision_audit_ref   binds a decision to the exact passport / mandate / policy / screen it consumed,
                       so the authorization is auditable instead of a black box (secures DECISION).
  revocation_ref       one link of a hash-linked revocation chain (reason + timestamp + status delta),
                       so revocation is witnessed and offline-verifiable, not a silent DB flip (REVOCATION).
  guard_context_ref    pins the exact inputs the admission gate saw at a moment in time, so the guard
                       decision is reproducible (secures GUARD).
  with_validity / check_freshness   attach and enforce an integer-ms validity window on any ref preimage
                       (policy / screen / trust_query), closing replay/staleness (FRESHNESS).

The refs are open (anyone can recompute them). Signing them into a Falcon-1024 keystone evidence chain
and ingesting them into the Compliance Command Center stays the commercial attestation. Timestamps are
epoch-millisecond integers hashed directly (Substrate Rule 2); no floating point, no RFC 3339 strings.
"""
from __future__ import annotations

import re

from .digest import sha256_jcs

# \A...\Z, never ^...$: `$` also matches before a trailing newline, so a dirty ref would
# validate and change the digest. See the note in execution.py.
_SHA256_REF_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

REVOCATION_REASONS = (
    "USER_REQUESTED", "COMPLIANCE_TRIGGERED", "EXPIRED", "KEY_COMPROMISE", "SUPERSEDED", "ADMIN",
)
STATUS_VALUES = ("active", "suspended", "revoked", "inactive")


class KeystoneSecureError(ValueError):
    pass


# ── shared validators (same style as substrate2.execution) ────────────────────────────────────────────
def _require_str(field: str, value) -> str:
    if not isinstance(value, str) or value == "":
        raise KeystoneSecureError(f"{field} must be a non-empty string")
    return value


def _require_ref(field: str, value) -> str:
    if not isinstance(value, str) or not _SHA256_REF_RE.match(value):
        raise KeystoneSecureError(f"{field} must be 'sha256:<lowercase 64-char hex>'")
    return value


def _require_int_ms(field: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise KeystoneSecureError(f"{field} must be int (Substrate Rule 2)")
    if value < 0:
        raise KeystoneSecureError(f"{field} must be non-negative")
    return value


def _require_enum(field: str, value, allowed: tuple) -> str:
    if value not in allowed:
        raise KeystoneSecureError(f"{field} must be one of {allowed}, got {value!r}")
    return value


# ── 1) DECISION — audit binding ───────────────────────────────────────────────────────────────────────
def decision_audit_ref(decision_ref: str, *, passport_credential_ref: str, mandate_ref: str,
                       policy_bound_ref: str, screen_binding_ref: str | None = None) -> str:
    """Bind a decision to the exact materials it consumed.

    ``decision_audit_ref = "sha256:" + SHA-256(JCS({decision_ref, passport_credential_ref, mandate_ref,
    policy_bound_ref[, screen_binding_ref]}))``. A verifier recomputes this from the four refs to confirm
    the decision bound THIS live passport, THIS mandate, THIS policy snapshot, and (if a compliance screen
    applied) THIS screen. Turns the opaque decision_ref into an auditable one. ``screen_binding_ref`` is
    omitted from the preimage when the flow has no screen (non-screened action)."""
    obj = {
        "decision_ref": _require_ref("decision_ref", decision_ref),
        "passport_credential_ref": _require_ref("passport_credential_ref", passport_credential_ref),
        "mandate_ref": _require_ref("mandate_ref", mandate_ref),
        "policy_bound_ref": _require_ref("policy_bound_ref", policy_bound_ref),
    }
    if screen_binding_ref is not None:
        obj["screen_binding_ref"] = _require_ref("screen_binding_ref", screen_binding_ref)
    return "sha256:" + sha256_jcs(obj)


def verify_decision_audit(audit_ref: str, decision_ref: str, *, passport_credential_ref: str,
                          mandate_ref: str, policy_bound_ref: str,
                          screen_binding_ref: str | None = None) -> bool:
    """Recompute and compare: True iff ``audit_ref`` binds exactly these materials to this decision."""
    return audit_ref == decision_audit_ref(
        decision_ref, passport_credential_ref=passport_credential_ref, mandate_ref=mandate_ref,
        policy_bound_ref=policy_bound_ref, screen_binding_ref=screen_binding_ref)


# ── 2) REVOCATION — hash-linked revocation chain ──────────────────────────────────────────────────────
def revocation_ref(*, subject_ref: str, revoked_at_ms: int, reason_code: str, issuer_did: str,
                   prev_status: str, new_status: str, seq: int,
                   prev_revocation_ref: str | None = None) -> str:
    """One link of a hash-linked revocation chain (genesis has ``prev_revocation_ref=None``, ``seq=0``).

    Content-addresses the exact revocation event: what was revoked, when (integer ms), why (closed reason
    code), by whom, and the status transition, linked to the prior link. Recomputable offline, so the
    revocation history is tamper-evident and witnessed, not a silent status flip."""
    obj = {
        "canon_version": "jcs-rfc8785-v1",
        "type": "revocation_link",
        "subject_ref": _require_ref("subject_ref", subject_ref),
        "revoked_at_ms": _require_int_ms("revoked_at_ms", revoked_at_ms),
        "reason_code": _require_enum("reason_code", reason_code, REVOCATION_REASONS),
        "issuer_did": _require_str("issuer_did", issuer_did),
        "prev_status": _require_enum("prev_status", prev_status, STATUS_VALUES),
        "new_status": _require_enum("new_status", new_status, STATUS_VALUES),
        "seq": _require_int_ms("seq", seq),
        "prev_revocation_ref": None if prev_revocation_ref is None
        else _require_ref("prev_revocation_ref", prev_revocation_ref),
    }
    return "sha256:" + sha256_jcs(obj)


def verify_revocation_chain(links: list[dict]) -> bool:
    """Verify an ordered list of revocation-link preimage dicts: seq is 0..n-1, each ``prev_revocation_ref``
    equals the prior link's ref, and genesis has ``prev_revocation_ref is None``.

    An empty list is NOT a valid chain (it used to return True vacuously, so stripping the chain
    to nothing "proved" a subject was never revoked). Each link must also be a WELL-FORMED
    revocation_link preimage -- the old code only checked hash-linkage, so a chain of arbitrary
    dicts with incrementing ``seq`` verified. Every link is re-derived from its validated fields
    and must match byte-for-byte, and ``seq`` is a real int (bool rejected)."""
    if not isinstance(links, list) or not links:
        return False
    prev_ref = None
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            return False
        seq = link.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != i:
            return False
        if link.get("prev_revocation_ref") != prev_ref:
            return False
        # Re-derive the canonical link body from validated fields; a link carrying rogue/extra
        # fields or a malformed value will not match its own recomputed form and is rejected.
        try:
            body = {
                "canon_version": "jcs-rfc8785-v1",
                "type": "revocation_link",
                "subject_ref": _require_ref("subject_ref", link.get("subject_ref")),
                "revoked_at_ms": _require_int_ms("revoked_at_ms", link.get("revoked_at_ms")),
                "reason_code": _require_enum("reason_code", link.get("reason_code"), REVOCATION_REASONS),
                "issuer_did": _require_str("issuer_did", link.get("issuer_did")),
                "prev_status": _require_enum("prev_status", link.get("prev_status"), STATUS_VALUES),
                "new_status": _require_enum("new_status", link.get("new_status"), STATUS_VALUES),
                "seq": _require_int_ms("seq", seq),
                "prev_revocation_ref": None if link.get("prev_revocation_ref") is None
                else _require_ref("prev_revocation_ref", link.get("prev_revocation_ref")),
            }
        except KeystoneSecureError:
            return False
        if sha256_jcs(link) != sha256_jcs(body):
            return False
        prev_ref = "sha256:" + sha256_jcs(link)
    return True


# ── 3) GUARD — admission-context ref ──────────────────────────────────────────────────────────────────
def guard_context_ref(*, guard_timestamp_ms: int, policy_ref: str, mandate_ref: str,
                      passport_credential_ref: str) -> str:
    """Pin the exact inputs the admission gate saw at ``guard_timestamp_ms`` so the guard decision is
    reproducible: which policy, which mandate, which passport credential were in force at the gate."""
    return "sha256:" + sha256_jcs({
        "canon_version": "jcs-rfc8785-v1",
        "type": "guard_context",
        "guard_timestamp_ms": _require_int_ms("guard_timestamp_ms", guard_timestamp_ms),
        "policy_ref": _require_ref("policy_ref", policy_ref),
        "mandate_ref": _require_ref("mandate_ref", mandate_ref),
        "passport_credential_ref": _require_ref("passport_credential_ref", passport_credential_ref),
    })


# ── 4) FRESHNESS — validity window on any ref preimage ────────────────────────────────────────────────
def with_validity(preimage: dict, *, issued_at_ms: int, expires_at_ms: int) -> dict:
    """Return a copy of a ref preimage with an integer-ms validity window added. Recomputing the ref over
    the returned preimage yields a fresher-or-staler ref that ``check_freshness`` enforces at verify time.
    Apply to policy / screen / trust_query preimages that today carry no expiry."""
    i = _require_int_ms("issued_at_ms", issued_at_ms)
    e = _require_int_ms("expires_at_ms", expires_at_ms)
    if e <= i:
        raise KeystoneSecureError("expires_at_ms must be greater than issued_at_ms")
    out = dict(preimage)
    out["issued_at_ms"] = i
    out["expires_at_ms"] = e
    return out


def check_freshness(preimage: dict, now_ms: int) -> bool:
    """True iff ``issued_at_ms <= now_ms < expires_at_ms`` (the window is closed-open). Raises if the
    preimage carries no integer validity window (a caller must attach one with ``with_validity`` first)."""
    i, e = preimage.get("issued_at_ms"), preimage.get("expires_at_ms")
    if not isinstance(i, int) or isinstance(i, bool) or not isinstance(e, int) or isinstance(e, bool):
        raise KeystoneSecureError("preimage has no integer validity window (call with_validity first)")
    return i <= _require_int_ms("now_ms", now_ms) < e


__all__ = [
    "KeystoneSecureError", "REVOCATION_REASONS", "STATUS_VALUES",
    "decision_audit_ref", "verify_decision_audit",
    "revocation_ref", "verify_revocation_chain",
    "guard_context_ref",
    "with_validity", "check_freshness",
]
