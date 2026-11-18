"""Tests for substrate2.keystone_secure — the four flow-point hardening refs."""
from __future__ import annotations

import hashlib

import pytest

from substrate2.canon import canonicalize_bytes
from substrate2 import keystone_secure as KS


def _r(c):  # a valid sha256: ref from a single hex char
    return "sha256:" + (c * 64)


def _manual(obj):
    return "sha256:" + hashlib.sha256(canonicalize_bytes(obj)).hexdigest()


# ── 1) decision_audit_ref ─────────────────────────────────────────────────────────────────────────────
def test_decision_audit_byte_parity_and_determinism():
    kw = dict(passport_credential_ref=_r("a"), mandate_ref=_r("b"),
              policy_bound_ref=_r("c"), screen_binding_ref=_r("d"))
    got = KS.decision_audit_ref(_r("0"), **kw)
    assert got == _manual({"decision_ref": _r("0"), "passport_credential_ref": _r("a"),
                           "mandate_ref": _r("b"), "policy_bound_ref": _r("c"),
                           "screen_binding_ref": _r("d")})
    assert got == KS.decision_audit_ref(_r("0"), **kw)  # deterministic


def test_decision_audit_screen_optional_and_verify():
    with_screen = KS.decision_audit_ref(_r("0"), passport_credential_ref=_r("a"), mandate_ref=_r("b"),
                                        policy_bound_ref=_r("c"), screen_binding_ref=_r("d"))
    no_screen = KS.decision_audit_ref(_r("0"), passport_credential_ref=_r("a"), mandate_ref=_r("b"),
                                      policy_bound_ref=_r("c"))
    assert with_screen != no_screen  # screen changes the binding
    assert KS.verify_decision_audit(with_screen, _r("0"), passport_credential_ref=_r("a"),
                                    mandate_ref=_r("b"), policy_bound_ref=_r("c"), screen_binding_ref=_r("d"))
    # swap the mandate -> verify fails (the decision did not bind that mandate)
    assert not KS.verify_decision_audit(with_screen, _r("0"), passport_credential_ref=_r("a"),
                                        mandate_ref=_r("e"), policy_bound_ref=_r("c"), screen_binding_ref=_r("d"))


def test_decision_audit_rejects_bad_ref():
    with pytest.raises(KS.KeystoneSecureError):
        KS.decision_audit_ref("not-a-ref", passport_credential_ref=_r("a"), mandate_ref=_r("b"),
                              policy_bound_ref=_r("c"))


# ── 2) revocation chain ───────────────────────────────────────────────────────────────────────────────
def _rev_link(seq, prev_ref, new_status="revoked"):
    return {"canon_version": "jcs-rfc8785-v1", "type": "revocation_link", "subject_ref": _r("a"),
            "revoked_at_ms": 1720000000000 + seq, "reason_code": "COMPLIANCE_TRIGGERED",
            "issuer_did": "did:web:api.algovoi.co.uk", "prev_status": "active", "new_status": new_status,
            "seq": seq, "prev_revocation_ref": prev_ref}


def test_revocation_ref_and_chain_verify():
    l0 = _rev_link(0, None)
    r0 = KS.revocation_ref(subject_ref=_r("a"), revoked_at_ms=l0["revoked_at_ms"],
                           reason_code="COMPLIANCE_TRIGGERED", issuer_did="did:web:api.algovoi.co.uk",
                           prev_status="active", new_status="revoked", seq=0)
    assert r0 == _manual(l0)
    l1 = _rev_link(1, r0)
    assert KS.verify_revocation_chain([l0, l1])
    # tamper: break the link
    bad = dict(l1); bad["prev_revocation_ref"] = _r("f")
    assert not KS.verify_revocation_chain([l0, bad])
    # tamper: wrong seq
    badseq = _rev_link(5, r0)
    assert not KS.verify_revocation_chain([l0, badseq])


def test_revocation_rejects_bad_reason_and_status():
    with pytest.raises(KS.KeystoneSecureError):
        KS.revocation_ref(subject_ref=_r("a"), revoked_at_ms=1, reason_code="NOPE",
                          issuer_did="d", prev_status="active", new_status="revoked", seq=0)
    with pytest.raises(KS.KeystoneSecureError):
        KS.revocation_ref(subject_ref=_r("a"), revoked_at_ms=1, reason_code="ADMIN",
                          issuer_did="d", prev_status="active", new_status="gone", seq=0)


# ── 3) guard_context_ref ──────────────────────────────────────────────────────────────────────────────
def test_guard_context_byte_parity_and_int_rule():
    got = KS.guard_context_ref(guard_timestamp_ms=1720000000000, policy_ref=_r("a"),
                               mandate_ref=_r("b"), passport_credential_ref=_r("c"))
    assert got == _manual({"canon_version": "jcs-rfc8785-v1", "type": "guard_context",
                           "guard_timestamp_ms": 1720000000000, "policy_ref": _r("a"),
                           "mandate_ref": _r("b"), "passport_credential_ref": _r("c")})
    with pytest.raises(KS.KeystoneSecureError):
        KS.guard_context_ref(guard_timestamp_ms=1.5, policy_ref=_r("a"), mandate_ref=_r("b"),
                             passport_credential_ref=_r("c"))  # float ms banned (Rule 2)


# ── 4) freshness ──────────────────────────────────────────────────────────────────────────────────────
def test_with_validity_and_check_freshness_window():
    base = {"canon_version": "jcs-rfc8785-v1", "policy_ref": _r("a")}
    p = KS.with_validity(base, issued_at_ms=1000, expires_at_ms=2000)
    assert p["issued_at_ms"] == 1000 and p["expires_at_ms"] == 2000
    assert not KS.check_freshness(p, 999)     # before window
    assert KS.check_freshness(p, 1000)         # inclusive start
    assert KS.check_freshness(p, 1999)         # inside
    assert not KS.check_freshness(p, 2000)     # exclusive end
    # the window is part of the ref: changing it changes the ref
    assert _manual(p) != _manual(KS.with_validity(base, issued_at_ms=1000, expires_at_ms=3000))


def test_freshness_errors():
    with pytest.raises(KS.KeystoneSecureError):
        KS.with_validity({"x": 1}, issued_at_ms=2000, expires_at_ms=1000)  # expires <= issued
    with pytest.raises(KS.KeystoneSecureError):
        KS.check_freshness({"x": 1}, 1500)  # no validity window attached
