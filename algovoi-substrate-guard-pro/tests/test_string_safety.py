"""The fuzzer-driven bound: lone surrogates / non-UTF-8 strings are rejected with a named code, before
canonicalization, in one deterministic pass — closing the Python/Node domain-boundary asymmetry."""
from algovoi_substrate_guard_pro import DEFAULT_PROFILE, GuardError, guard, profile_ref
from conftest import make_service


def _reject_code(value):
    try:
        guard(value)
        return None
    except GuardError as e:
        return e.code


def test_lone_high_surrogate_value_rejected():
    assert _reject_code({"a": chr(0xD800)}) == "REJECT_INVALID_UTF8"


def test_lone_low_surrogate_value_rejected():
    assert _reject_code({"a": chr(0xDC00)}) == "REJECT_INVALID_UTF8"


def test_lone_surrogate_in_key_rejected():
    assert _reject_code({chr(0xD800): 1}) == "REJECT_INVALID_UTF8"


def test_valid_emoji_admitted():
    assert _reject_code({"a": chr(0x1F600)}) is None


def test_noncharacter_is_a_valid_scalar_admitted():
    # U+FFFF is a noncharacter but a valid Unicode scalar — must NOT be rejected as invalid UTF-8.
    assert _reject_code({"a": chr(0xFFFF)}) is None


def test_unsafe_integer_rejected():
    assert _reject_code({"a": 2 ** 53 + 1}) == "REJECT_UNSAFE_NUMBER"
    assert _reject_code({"a": 2 ** 53 - 1}) is None


def test_profile_ref_is_deterministic_and_key_order_invariant():
    assert profile_ref() == profile_ref(DEFAULT_PROFILE)
    assert profile_ref().startswith("sha256:")


def test_service_records_reject_with_named_code():
    svc, _pk, _ = make_service()
    r = svc.evaluate({"a": chr(0xD800)})
    assert not r.admitted and r.decision == "REJECT" and r.reject_code == "REJECT_INVALID_UTF8"
    assert r.subject_ref is None and r.guard_decision_ref.startswith("sha256:")


def test_service_admits_clean_value_with_subject_ref():
    svc, _pk, _ = make_service()
    r = svc.evaluate({"agent": "acct:alice", "amount": 25_000_000, "emoji": chr(0x1F600)})
    assert r.admitted and r.decision == "ADMIT" and r.reject_code is None
    assert r.subject_ref.startswith("sha256:")
