import pytest

from algovoi_substrate_guard_pro.bounds import GuardError, guard


def _reject_code(value):
    with pytest.raises(GuardError) as exc_info:
        guard(value)
    return exc_info.value.code


def test_non_string_object_key_rejected_with_named_code():
    assert _reject_code({1: "x"}) == "REJECT_NON_STRING_KEY"


def test_set_value_rejected_as_unsupported_type():
    assert _reject_code({"a": {1, 2}}) == "REJECT_UNSUPPORTED_TYPE"


def test_tuple_value_rejected_as_unsupported_type():
    assert _reject_code({"a": (1, 2)}) == "REJECT_UNSUPPORTED_TYPE"


def test_bytes_value_rejected_as_unsupported_type():
    assert _reject_code({"a": b"x"}) == "REJECT_UNSUPPORTED_TYPE"


def test_nan_still_rejected_as_unsafe_number():
    assert _reject_code(float("nan")) == "REJECT_UNSAFE_NUMBER"


def test_lone_surrogate_still_rejected_as_invalid_utf8():
    assert _reject_code({"a": "\ud800"}) == "REJECT_INVALID_UTF8"


def test_booleans_are_admitted():
    assert guard(True) is True
    assert guard(False) is True
