"""Content-addressed references for the admission gate.

  profile_ref         = "sha256:" + SHA-256(JCS(profile))                  (the bounds in force)
  subject_ref         = "sha256:" + SHA-256(JCS(admitted_value))           (only defined for ADMIT)
  guard_decision_ref  = "sha256:" + SHA-256(JCS({profile_ref, verdict, subject_ref|reject_code}))

A guard decision binds the verdict to the exact profile that produced it, and — for an admitted value —
to that value's canonical content address. So a downstream record can prove WHICH bounds admitted it and,
for a rejection, WHY (the named code) without carrying the payload itself (no-PII). ``_prefixed`` is
byte-identical to ``algovoi_substrate.sha256_jcs`` (rfc8785 + SHA-256).
"""
from __future__ import annotations

import hashlib

import rfc8785

from algovoi_substrate_guard_pro.bounds import DEFAULT_PROFILE, Profile, profile_ref

__all__ = ["profile_ref", "subject_ref", "guard_decision_ref", "_prefixed", "DEFAULT_PROFILE", "Profile"]


def _prefixed(value) -> str:
    """``"sha256:" + SHA-256(JCS(value))`` — identical bytes to ``algovoi_substrate.sha256_jcs``."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def subject_ref(value) -> str:
    """Canonical content address of an ADMITTED value. Undefined (and never computed) for a rejected
    value, which by construction may not be canonicalisable."""
    return _prefixed(value)


def guard_decision_ref(*, profile_ref_: str, decision: str,
                       subject_ref_: str | None = None, reject_code: str | None = None) -> str:
    """Bind the verdict to the profile in force and to either the admitted subject or the reject code."""
    core: dict = {"profile_ref": profile_ref_, "verdict": decision}
    if decision == "ADMIT":
        core["subject_ref"] = subject_ref_
    else:
        core["reject_code"] = reject_code
    return _prefixed(core)
