"""Hybrid Falcon-1024 + ML-DSA-65 co-signing of admission decisions."""
from algovoi_substrate_guard_pro import hybrid, verify_guard_chain, verify_guard_decision
from conftest import make_service


def test_hybrid_decision_requires_both_signatures():
    svc, pk, mpk = make_service(mldsa=True)
    r = svc.evaluate({"a": 1})
    assert verify_guard_decision(r.envelope, pk, mldsa_public_key=mpk).hybrid is True
    assert verify_guard_decision(r.envelope, pk).verified is True            # Falcon-only still accepts
    other_pk, _ = hybrid.generate_keypair()
    assert verify_guard_decision(r.envelope, pk, mldsa_public_key=other_pk).verified is False


def test_hybrid_chain_verifies_with_mldsa_key():
    svc, pk, mpk = make_service(mldsa=True)
    svc.evaluate({"a": 1})
    svc.evaluate({"a": chr(0xD800)})
    assert verify_guard_chain(svc.ledger.envelopes, pk, mldsa_public_key=mpk).verified
    bad_pk, _ = hybrid.generate_keypair()
    assert verify_guard_chain(svc.ledger.envelopes, pk, mldsa_public_key=bad_pk).verified is False
