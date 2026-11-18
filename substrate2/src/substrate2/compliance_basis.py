"""substrate2.compliance_basis — the COMMERCIAL decision-basis layer for the keystone compliance
gate. The 7 closed decision standards + a no-PII per-check content-addressed manifest, bound to a
keystone decision EXTERNALLY (basis_binding_ref) so the open Compliance Receipt is never mutated.

This is the commercial keep: the open tier (algovoi-substrate / the a2a Compliance Receipt edition)
carries the verdict + geo_ref; this layer proves WHICH of the 7 standards drove it, signed and
CCC-ingestable. Intentionally NOT part of the open substrate, the public corpus, IETF, or docs.

    check_entry      -> {check, result, provider_did, reason_code, [risk_score], [geo_ref], check_ref}
    compliance_basis -> {canon_version, checks[], obligations[sorted], reason_codes[sorted]}
    basis_ref        -> "sha256:" + SHA-256(JCS(compliance_basis))
    basis_binding_ref-> "sha256:" + SHA-256(JCS({basis_ref, screen_ref}))   # screen_ref = open receipt_ref
"""
from __future__ import annotations

from typing import Iterable

from .digest import SHA256_PREFIX, sha256_jcs_prefixed

CANON_VERSION = "jcs-rfc8785-v1"

# the 7 closed decision standards + 4 obligations (mirror algovoi_compliance_gate.checks)
REASON_CODES = frozenset({
    "CLEAR", "DENYLIST", "SANCTIONS_HIT", "PEP_MATCH", "RISK_THRESHOLD",
    "JURISDICTION_BLOCK", "TRAVEL_RULE_REQUIRED",
})
OBLIGATIONS = frozenset({"SAR_REQUIRED", "EDD_REQUIRED", "STEP_UP_KYC", "TRAVEL_RULE_FILING"})
SCREEN_RESULTS = frozenset({"ALLOW", "REFER", "DENY"})


class ComplianceBasisError(ValueError):
    pass


def _is_ref(s: object) -> bool:
    return isinstance(s, str) and s.startswith(SHA256_PREFIX)


def check_entry(*, check: str, result: str, provider_did: str, reason_code: str,
                risk_score: int | None = None, geo_ref: str | None = None) -> dict:
    """One no-PII check, content-addressed. The jurisdiction check passes geo_ref so the block is
    provably derived from a specific geo determination."""
    if result not in SCREEN_RESULTS:
        raise ComplianceBasisError(f"result must be one of {sorted(SCREEN_RESULTS)}")
    if reason_code not in REASON_CODES:
        raise ComplianceBasisError(f"reason_code must be one of {sorted(REASON_CODES)}")
    if risk_score is not None and (isinstance(risk_score, bool) or not isinstance(risk_score, int)):
        raise ComplianceBasisError("risk_score must be an integer (milliunits) or None")
    if geo_ref is not None and not _is_ref(geo_ref):
        raise ComplianceBasisError("geo_ref must be a 'sha256:' reference or None")
    d: dict = {"check": check, "result": result, "provider_did": provider_did, "reason_code": reason_code}
    if risk_score is not None:
        d["risk_score"] = risk_score
    if geo_ref is not None:
        d["geo_ref"] = geo_ref
    d["check_ref"] = sha256_jcs_prefixed(d)
    return d


def compliance_basis(*, reason_codes: Iterable[str], obligations: Iterable[str],
                     checks: list, canon_version: str = CANON_VERSION) -> dict:
    """The commercial decision basis. reason_codes/obligations are normalized to a sorted, unique
    closed-enum list so the basis is byte-stable regardless of producer order."""
    rc = sorted(set(reason_codes))
    ob = sorted(set(obligations))
    for c in rc:
        if c not in REASON_CODES:
            raise ComplianceBasisError(f"reason_code {c!r} not in the 7 standards")
    for o in ob:
        if o not in OBLIGATIONS:
            raise ComplianceBasisError(f"obligation {o!r} not recognized")
    if not isinstance(checks, list) or not all(isinstance(c, dict) and "check_ref" in c for c in checks):
        raise ComplianceBasisError("checks must be a list of check_entry dicts")
    return {"canon_version": canon_version, "checks": checks, "obligations": ob, "reason_codes": rc}


def basis_ref(basis: dict) -> str:
    return sha256_jcs_prefixed(basis)


def basis_binding_ref(*, screen_ref: str, basis_ref: str) -> str:
    """Bind the basis to the OPEN receipt without mutating it. screen_ref = the open receipt_ref."""
    if not (_is_ref(screen_ref) and _is_ref(basis_ref)):
        raise ComplianceBasisError("screen_ref and basis_ref must be 'sha256:' references")
    return sha256_jcs_prefixed({"basis_ref": basis_ref, "screen_ref": screen_ref})


__all__ = [
    "REASON_CODES", "OBLIGATIONS", "SCREEN_RESULTS", "ComplianceBasisError",
    "check_entry", "compliance_basis", "basis_ref", "basis_binding_ref",
]
