"""The signed, hash-linked admission chain + CCC-shaped evidence pack."""
import json

from algovoi_substrate_guard_pro import (
    AdmissionStore,
    signing,
    verify_guard_chain,
    verify_guard_decision,
)
from algovoi_substrate_guard_pro.ledger import CHAIN_FILE, ENTRY_TYPE
from algovoi_substrate_guard_pro.refs import guard_decision_ref
from conftest import make_service


def test_admit_and_reject_form_a_verifiable_chain():
    svc, pk, _ = make_service()
    svc.evaluate({"a": 1})
    svc.evaluate({"a": chr(0xD800)})       # rejected, still chained as evidence
    svc.evaluate({"a": [1, 2, 3]})
    res = verify_guard_chain(svc.ledger.envelopes, pk)
    assert res.verified and res.count == 3


def test_each_decision_receipt_verifies_and_binds_profile():
    svc, pk, _ = make_service()
    r = svc.evaluate({"a": 1})
    v = verify_guard_decision(r.envelope, pk)
    assert v.verified and v.decision == "ADMIT"
    assert v.profile_ref == svc.profile_ref and v.subject_ref == r.subject_ref
    # guard_decision_ref recomputes from its public parts
    assert r.guard_decision_ref == guard_decision_ref(
        profile_ref_=svc.profile_ref, decision="ADMIT", subject_ref_=r.subject_ref)


def test_tampered_chain_breaks_at_offending_entry():
    svc, pk, _ = make_service()
    for i in range(3):
        svc.evaluate({"a": i})
    env = list(svc.ledger.envelopes)
    e = json.loads(signing.b64u_decode(env[1]))
    e["payload"]["decision"] = "REJECT"      # tamper
    env[1] = signing.b64u_encode(json.dumps(e, separators=(",", ":"), sort_keys=True).encode())
    res = verify_guard_chain(env, pk)
    assert not res.verified and res.first_bad_seq == 1


def test_export_pack_is_ccc_shaped(tmp_path):
    svc, _pk, _ = make_service()
    svc.evaluate({"a": 1})
    svc.export_pack(str(tmp_path))
    assert (tmp_path / "public_key.b64").exists()
    chain = json.loads((tmp_path / CHAIN_FILE).read_text())
    payload = json.loads(signing.b64u_decode(chain[0]))["payload"]
    assert payload["type"] == ENTRY_TYPE and payload["prev_entry_hash"] is None and payload["seq"] == 0


def test_chain_survives_restart_with_store(tmp_path):
    dsn = "sqlite:///" + str(tmp_path / "g.db")
    svc1, pk, _ = make_service(store=AdmissionStore(dsn))
    svc1.evaluate({"a": 1})
    svc1.evaluate({"a": 2})
    # "restart": a fresh service over the same store resumes seq + hash links
    svc2 = type(svc1)(decision_secret_key=svc1.ledger.sk, decision_public_key=svc1.ledger.pk,
                      store=AdmissionStore(dsn), _skip_license=True)
    assert svc2.ledger.seq == 2
    svc2.evaluate({"a": 3})
    res = verify_guard_chain(svc2.ledger.envelopes, pk)
    assert res.verified and res.count == 3
