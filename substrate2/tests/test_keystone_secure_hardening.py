"""Regression tests: verify_revocation_chain must reject empty/malformed chains,
and refs_consistent must require per-field equality (not substring presence)."""
from substrate2.keystone_secure import revocation_ref, verify_revocation_chain
from substrate2.keystone_exports import refs_consistent

REF = "sha256:" + "a" * 64


def _link(seq, prev):
    body = {
        "canon_version": "jcs-rfc8785-v1",
        "type": "revocation_link",
        "subject_ref": REF,
        "revoked_at_ms": 1000 + seq,
        "reason_code": "USER_REQUESTED",
        "issuer_did": "did:algo:issuer",
        "prev_status": "active",
        "new_status": "revoked",
        "seq": seq,
        "prev_revocation_ref": prev,
    }
    return body


def _chain(n):
    links, prev = [], None
    for i in range(n):
        b = _link(i, prev)
        links.append(b)
        prev = "sha256:" + __import__("substrate2.digest", fromlist=["sha256_jcs"]).sha256_jcs(b)
    return links


def test_valid_chain_verifies():
    assert verify_revocation_chain(_chain(3)) is True


def test_empty_chain_rejected():
    assert verify_revocation_chain([]) is False


def test_arbitrary_dicts_rejected():
    # incrementing seq + correct linkage but NOT well-formed revocation links
    bogus = [{"seq": 0, "prev_revocation_ref": None, "foo": "bar"}]
    assert verify_revocation_chain(bogus) is False


def test_bool_seq_rejected():
    ch = _chain(1)
    ch[0]["seq"] = True  # bool masquerading as int 1... but position 0
    assert verify_revocation_chain(ch) is False


def test_refs_consistent_requires_equality_and_nonempty():
    good = {"native": {"decision_ref": REF, "execution_ref": REF}}
    assert refs_consistent(good, REF, REF) is True
    # a format artifact carrying a DIFFERENT ref must fail
    bad = {"a": {"decision_ref": REF, "execution_ref": REF},
           "b": {"execution_ref": "sha256:" + "b" * 64}}
    assert refs_consistent(bad, REF, REF) is False
    # empty expected ref rejected
    assert refs_consistent(good, "", REF) is False
    # no ref present at all -> not consistent (nothing proven)
    assert refs_consistent({"x": 1}, REF, REF) is False
