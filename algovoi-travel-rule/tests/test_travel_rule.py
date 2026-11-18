"""Travel Rule engine tests — signed no-PII receipt, threshold applicability, PQC IVMS101 exchange."""
from __future__ import annotations

import json

import pytest

from algovoi_travel_rule import (
    IVMS101,
    Person,
    TravelRule,
    TravelRuleError,
    generate_mlkem_keypair,
    signing,
    verify_ivms101_binding,
    verify_travel_rule_receipt,
)


@pytest.fixture()
def vasp():
    pk, sk = signing.generate_keypair()
    return pk, sk, TravelRule(secret_key=sk, public_key=pk, originating_vasp_did="did:web:vasp.acme")


@pytest.fixture()
def ivms():
    return IVMS101(
        originator=Person(name="Alice Smith", account="0xAAA", country="GB"),
        beneficiary=Person(name="Bob Jones", account="0xBBB", country="DE"),
    )


def test_certify_signs_and_verifies(vasp, ivms):
    pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx-1", beneficiary_vasp_did="did:web:vasp.beta",
                     amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
    assert out["applies"] is True
    r = verify_travel_rule_receipt(out["receipt_envelope"], pk)
    assert r.verified and r.applies and r.transfer_ref == "tx-1"
    assert out["receipt"]["canon_version"] == "jcs-rfc8785-v1"


def test_receipt_carries_no_pii(vasp, ivms):
    pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx-1", beneficiary_vasp_did="did:web:vasp.beta",
                     amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
    blob = json.dumps(out["receipt"]) + out["receipt_envelope"]
    for pii in ("Alice Smith", "Bob Jones", "0xAAA", "0xBBB"):
        assert pii not in blob, f"PII {pii!r} leaked into the receipt"
    assert out["receipt"]["ivms101_hash"].startswith("sha256:")


def test_threshold_applicability(vasp):
    pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx-small", beneficiary_vasp_did="did:web:b",
                     amount_minor=50000, currency="USD")          # below $1,000 de-minimis
    assert out["applies"] is False and "ivms101_hash" not in out["receipt"]
    assert verify_travel_rule_receipt(out["receipt_envelope"], pk).verified


def test_applies_but_no_ivms101_rejected(vasp):
    _pk, _sk, tr = vasp
    with pytest.raises(TravelRuleError, match="no IVMS101"):
        tr.certify(transfer_ref="tx", beneficiary_vasp_did="did:web:b",
                   amount_minor=500000, currency="USD")           # applies, but no payload


def test_cross_currency_certify_refused(vasp, ivms):
    """Security fix 2026-08-19: a transfer denominated in a unit other than the threshold currency cannot
    be evaluated for de-minimis, so certify REFUSES rather than silently emitting applies=False (which
    would skip the PII exchange for every asset-denominated transfer yet sign a 'not applicable' receipt)."""
    _pk, _sk, tr = vasp                                            # threshold currency defaults to USD
    with pytest.raises(TravelRuleError, match="not the threshold currency"):
        tr.certify(transfer_ref="tx-eth", beneficiary_vasp_did="did:web:b",
                   amount_minor=5_000_000_000, currency="ETH", ivms101=ivms, result="SENT")


def test_stale_receipt_rejected_by_max_age(vasp, ivms):
    """Security fix 2026-08-19: a receipt older than max_age_ms is rejected so a stale 'compliance met'
    attestation can't be replayed indefinitely."""
    pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx-1", beneficiary_vasp_did="did:web:b",
                     amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
    assert verify_travel_rule_receipt(out["receipt_envelope"], pk, max_age_ms=10_000_000).verified
    r = verify_travel_rule_receipt(out["receipt_envelope"], pk, max_age_ms=0)  # zero window -> stale
    assert r.verified is False and "freshness" in r.reason


def test_combined_ivms_binding_requires_verified_receipt(vasp, ivms):
    """Security fix 2026-08-19: passing ivms101 to verify_travel_rule_receipt checks the PII binding
    against a signature-verified receipt in one call; a wrong ivms is rejected."""
    pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx-1", beneficiary_vasp_did="did:web:b",
                     amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
    assert verify_travel_rule_receipt(out["receipt_envelope"], pk, ivms101=ivms).verified
    from algovoi_travel_rule import IVMS101, Person
    wrong = IVMS101(originator=Person(name="Mallory", account="0xEVIL", country="RU"),
                    beneficiary=Person(name="Bob Jones", account="0xBBB", country="DE"))
    r = verify_travel_rule_receipt(out["receipt_envelope"], pk, ivms101=wrong)
    assert r.verified is False and "ivms101" in r.reason


def test_verifier_surfaces_signer_kid_and_enforces_expected(vasp, ivms):
    """Security fix 2026-08-19: verification proves signature validity, NOT the claimed VASP identity.
    The result surfaces signer_kid, and a pinned expected_signer_kid is enforced."""
    pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx-1", beneficiary_vasp_did="did:web:vasp.beta",
                     amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
    real_kid = signing.kid_for(pk)
    r = verify_travel_rule_receipt(out["receipt_envelope"], pk)
    assert r.verified and r.signer_kid == real_kid
    # a pinned kid that does not match the signing key is rejected even though the signature is valid
    r2 = verify_travel_rule_receipt(out["receipt_envelope"], pk, expected_signer_kid="deadbeefdeadbeef")
    assert r2.verified is False and r2.signer_kid == real_kid


def test_pqc_ivms101_exchange_roundtrip(vasp, ivms):
    _pk, _sk, tr = vasp
    bpk, bsk = generate_mlkem_keypair()
    sealed = tr.seal_ivms101(ivms101=ivms, beneficiary_mlkem_pubkey=bpk)
    received = TravelRule.open_ivms101(sealed_b64=sealed, mlkem_secret=bsk)
    assert received["originator"]["name"] == "Alice Smith"
    _wpk, wsk = generate_mlkem_keypair()
    with pytest.raises(Exception):                                 # wrong VASP key can't open
        TravelRule.open_ivms101(sealed_b64=sealed, mlkem_secret=wsk)


def test_ivms101_binding(vasp, ivms):
    _pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx", beneficiary_vasp_did="did:web:b",
                     amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
    assert verify_ivms101_binding(out["receipt"], ivms) is True
    tampered = IVMS101(originator=Person(name="Mallory", account="0xAAA"), beneficiary=ivms.beneficiary)
    assert verify_ivms101_binding(out["receipt"], tampered) is False


def test_tampered_or_wrong_key_fails(vasp, ivms):
    _pk, _sk, tr = vasp
    out = tr.certify(transfer_ref="tx", beneficiary_vasp_did="did:web:b",
                     amount_minor=250000, currency="USD", ivms101=ivms)
    wrong_pk, _ = signing.generate_keypair()
    assert verify_travel_rule_receipt(out["receipt_envelope"], wrong_pk).verified is False


def test_free_for_any_suite_licence(monkeypatch):
    """Included free: ANY valid suite OEM licence unlocks Travel Rule — not just a Travel-Rule one."""
    import base64
    import json
    from datetime import datetime, timedelta, timezone

    from algovoi_travel_rule import licensing

    monkeypatch.setattr(licensing, "_falcon_verify", lambda *a, **k: True)   # pretend signature valid
    future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    # a licence issued for a DIFFERENT suite package
    payload = {"type": "oem_license", "package": "algovoi-compliance-gate", "expires_at": future}
    key = b64u(json.dumps({"payload": payload, "sig": b64u(b"x")}).encode())
    ok, reason = licensing.verify_license_offline(key)
    assert ok is True and reason == "active"        # free for any suite customer
    assert licensing.INCLUDED_FREE_FOR_ANY_SUITE_LICENCE is True
