"""The signed edge chain: verify, tamper-detect, hybrid, no-PII, and CCC shape."""
import json

from algovoi_edge_sentinel import (
    EdgePolicy,
    RequestContext,
    hybrid,
    signing,
    verify_edge_chain,
    verify_edge_decision,
)
from algovoi_edge_sentinel.geo import InMemoryGeoProvider
from algovoi_edge_sentinel.ledger import CHAIN_FILE, ENTRY_TYPE
from algovoi_edge_sentinel.refs import edge_decision_ref
from conftest import make_sentinel

GEO = InMemoryGeoProvider([{"cidr": "203.0.113.0/24", "country": "KP", "asn": 64500}])


def test_blocks_form_a_verifiable_chain():
    s, pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    for _ in range(3):
        assert not s.evaluate(RequestContext(ip="203.0.113.5")).allowed
    res = verify_edge_chain(s.ledger.envelopes, pk)
    assert res.verified and res.count == 3


def test_allows_not_chained_by_default_but_blocks_are():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    s.evaluate(RequestContext(ip="203.0.113.5"))      # BLOCK -> chained
    s.evaluate(RequestContext(ip="8.8.8.8"))          # ALLOW (unknown geo) -> not chained
    assert s.ledger.seq == 1


def test_log_allows_chains_everything():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",), log_allows=True), geo=GEO)
    s.evaluate(RequestContext(ip="203.0.113.5"))      # BLOCK
    s.evaluate(RequestContext(ip="8.8.8.8"))          # ALLOW, now chained
    assert s.ledger.seq == 2


def test_decision_receipt_binds_policy_and_recomputes_ref():
    s, pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    r = s.evaluate(RequestContext(ip="203.0.113.5"))
    v = verify_edge_decision(r.envelope, pk)
    assert v.verified and v.decision == "BLOCK" and v.reason_code == "BLOCK_GEO_COUNTRY"
    assert v.policy_ref == s.policy_ref
    assert r.edge_decision_ref == edge_decision_ref(
        policy_ref_=s.policy_ref, decision="BLOCK", check="geo",
        reason_code="BLOCK_GEO_COUNTRY", subject_ref_=r.subject_ref)


def test_decision_is_no_pii():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_dids=("did:web:evil",), checks=("identity",)))
    r = s.evaluate(RequestContext(ip="203.0.113.5", agent_did="did:web:evil", wallet="0xabc"))
    payload = json.loads(signing.b64u_decode(r.envelope))["payload"]
    for pii in ("ip", "agent_did", "wallet", "key_id"):
        assert pii not in payload                     # only the hashed subject_ref is carried
    assert payload["subject_ref"].startswith("sha256:")


def test_tampered_chain_breaks_at_offending_entry():
    s, pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    for _ in range(3):
        s.evaluate(RequestContext(ip="203.0.113.5"))
    env = list(s.ledger.envelopes)
    e = json.loads(signing.b64u_decode(env[1]))
    e["payload"]["reason_code"] = "ALLOW"
    env[1] = signing.b64u_encode(json.dumps(e, separators=(",", ":"), sort_keys=True).encode())
    res = verify_edge_chain(env, pk)
    assert not res.verified and res.first_bad_seq == 1


def test_export_pack_is_ccc_shaped(tmp_path):
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    s.evaluate(RequestContext(ip="203.0.113.5"))
    s.export_pack(str(tmp_path))
    assert (tmp_path / "public_key.b64").exists()
    chain = json.loads((tmp_path / CHAIN_FILE).read_text())
    payload = json.loads(signing.b64u_decode(chain[0]))["payload"]
    assert payload["type"] == ENTRY_TYPE and payload["prev_entry_hash"] is None and payload["seq"] == 0


def test_hybrid_chain_requires_both_signatures():
    s, pk, mpk = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO, mldsa=True)
    s.evaluate(RequestContext(ip="203.0.113.5"))
    assert verify_edge_chain(s.ledger.envelopes, pk, mldsa_public_key=mpk).verified
    bad, _ = hybrid.generate_keypair()
    assert verify_edge_chain(s.ledger.envelopes, pk, mldsa_public_key=bad).verified is False
