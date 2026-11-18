"""The admission gate: bounds + signed, content-addressed, chain-linked decisions.

``GuardService.evaluate(value)`` runs the hardened bounds, then records the verdict as a signed
admission decision bound to the ``profile_ref`` in force. An ADMIT carries the value's ``subject_ref``
(its canonical content address); a REJECT carries the named ``reject_code`` and never canonicalises the
payload (no-PII, and a rejected value may not be canonicalisable). Every decision is appended to the
hash-linked admission chain, so an operator can prove the *sequence* of what the gate admitted and
refused, offline-verifiable in the Compliance Command Center.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from algovoi_substrate_guard_pro.bounds import DEFAULT_PROFILE, GuardError, Profile, guard, profile_ref
from algovoi_substrate_guard_pro.ledger import AdmissionLedger
from algovoi_substrate_guard_pro.licensing import require_license
from algovoi_substrate_guard_pro.models import GuardResult
from algovoi_substrate_guard_pro.refs import guard_decision_ref, subject_ref


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class GuardService:
    """Admission gate over one signing key and one bounds profile. Fail-closed on licence."""

    def __init__(self, *, decision_secret_key: bytes, decision_public_key: bytes,
                 profile: Profile = DEFAULT_PROFILE,
                 mldsa_secret_key: bytes | None = None, mldsa_public_key: bytes | None = None,
                 store=None, _skip_license: bool = False) -> None:
        if not _skip_license:
            require_license()
        self.profile = profile
        self.profile_ref = profile_ref(profile)
        self.ledger = AdmissionLedger(decision_secret_key, decision_public_key,
                                      mldsa_secret_key, mldsa_public_key, store)

    @property
    def hybrid(self) -> bool:
        return self.ledger.mldsa_pk is not None

    def evaluate(self, value, *, expires_in_s: int | None = None) -> GuardResult:
        """Bounds-check ``value`` and append a signed admission decision to the chain."""
        now = _utcnow_iso()
        try:
            guard(value, self.profile)
            decision, code, sref = "ADMIT", None, subject_ref(value)
        except GuardError as e:
            decision, code, sref = "REJECT", e.code, None
        gdref = guard_decision_ref(profile_ref_=self.profile_ref, decision=decision,
                                   subject_ref_=sref, reject_code=code)
        core = {
            "decision": decision,
            "profile_ref": self.profile_ref,
            "guard_decision_ref": gdref,
            "subject_ref": sref,
            "reject_code": code,
            "evaluated_at": now,
        }
        if expires_in_s is not None:
            exp = datetime.now(timezone.utc) + timedelta(seconds=expires_in_s)
            core["expires_at"] = exp.strftime("%Y-%m-%dT%H:%M:%SZ")
        envelope, _payload = self.ledger.append(core)
        return GuardResult(admitted=(decision == "ADMIT"), decision=decision, reject_code=code,
                           profile_ref=self.profile_ref, guard_decision_ref=gdref, subject_ref=sref,
                           evaluated_at=now, envelope=envelope, hybrid=self.hybrid)

    def export_pack(self, out_dir: str) -> str:
        return self.ledger.export_pack(out_dir)


__all__ = ["GuardService"]
