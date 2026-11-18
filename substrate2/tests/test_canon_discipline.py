"""
Discipline-layer tests for canon.py

Tests the validation ("discipline") layer of the JCS canonicaliser.
Each test pins a real part of the contract.
"""
import math

import pytest

from substrate2.canon import canonicalize_bytes, canonicalize, CanonicalizationError, CANON_VERSION


class TestAcceptedValueSpace:
    """Values that MUST NOT raise CanonicalizationError."""

    def test_none(self):
        assert canonicalize_bytes(None) == b"null"

    def test_bool_true(self):
        # bool serialises as true, NOT as 1
        result = canonicalize_bytes(True)
        assert result == b"true"

    def test_bool_false(self):
        # bool serialises as false, NOT as 0
        result = canonicalize_bytes(False)
        assert result == b"false"

    def test_int_zero(self):
        assert canonicalize_bytes(0) == b"0"

    def test_int_positive(self):
        assert canonicalize_bytes(42) == b"42"

    def test_int_negative(self):
        assert canonicalize_bytes(-17) == b"-17"

    def test_float_finite_positive(self):
        assert canonicalize_bytes(3.14) == b"3.14"

    def test_float_finite_negative(self):
        assert canonicalize_bytes(-2.5) == b"-2.5"

    def test_float_zero(self):
        # RFC 8785 JCS serializes 0.0 as "0" not "0.0"
        assert canonicalize_bytes(0.0) == b"0"

    def test_str_empty(self):
        assert canonicalize_bytes("") == b'""'

    def test_str_non_empty(self):
        assert canonicalize_bytes("hello") == b'"hello"'

    def test_list_empty(self):
        assert canonicalize_bytes([]) == b"[]"

    def test_list_homogeneous(self):
        assert canonicalize_bytes([1, 2, 3]) == b"[1,2,3]"

    def test_list_heterogeneous(self):
        result = canonicalize_bytes([None, True, "x", 1, 2.5, []])
        assert result == b'[null,true,"x",1,2.5,[]]'

    def test_dict_empty(self):
        assert canonicalize_bytes({}) == b"{}"

    def test_dict_string_keys(self):
        result = canonicalize_bytes({"a": 1, "b": 2})
        assert result == b'{"a":1,"b":2}'

    def test_dict_nested(self):
        value = {"x": [1, 2, {"y": True}]}
        result = canonicalize_bytes(value)
        assert result == b'{"x":[1,2,{"y":true}]}'

    def test_deeply_nested_under_limit(self):
        # Build a structure at exactly _MAX_DEPTH (64)
        value = 0
        for _ in range(64):
            value = [value]
        # Should not raise - depth is counted from 0
        # The outermost list is depth 1, innermost is depth 64
        # But _validate starts at depth=0, so 64 nested lists = depth 64
        # which is NOT > _MAX_DEPTH, so it passes
        result = canonicalize_bytes(value)
        assert result is not None


class TestRejectedValueSpace:
    """Values that MUST raise CanonicalizationError."""

    # --- NaN/Infinity floats ---

    @pytest.mark.parametrize("bad_float", [float("nan"), float("inf"), float("-inf")])
    def test_float_special_values(self, bad_float):
        with pytest.raises(CanonicalizationError, match="NaN/Infinity has no canonical JSON form"):
            canonicalize_bytes(bad_float)

    def test_float_nan_explicit(self):
        with pytest.raises(CanonicalizationError, match="NaN/Infinity has no canonical JSON form"):
            canonicalize_bytes(math.nan)

    def test_float_pos_inf_explicit(self):
        with pytest.raises(CanonicalizationError, match="NaN/Infinity has no canonical JSON form"):
            canonicalize_bytes(math.inf)

    def test_float_neg_inf_explicit(self):
        with pytest.raises(CanonicalizationError, match="NaN/Infinity has no canonical JSON form"):
            canonicalize_bytes(math.inf * -1)

    # --- Non-string dict keys ---

    @pytest.mark.parametrize("bad_key", [1, 2.5, True, None, (1, 2), b"bytes"])
    def test_dict_non_string_key(self, bad_key):
        with pytest.raises(CanonicalizationError, match="non-string object key"):
            canonicalize_bytes({bad_key: "value"})

    def test_dict_int_key(self):
        with pytest.raises(CanonicalizationError, match="non-string object key"):
            canonicalize_bytes({42: "answer"})

    def test_dict_tuple_key(self):
        with pytest.raises(CanonicalizationError, match="non-string object key"):
            canonicalize_bytes({(1, 2): "pair"})

    def test_dict_none_key(self):
        with pytest.raises(CanonicalizationError, match="non-string object key"):
            canonicalize_bytes({None: "null_key"})

    # --- Depth limit ---

    def test_depth_exceeds_limit(self):
        # Build a structure deeper than _MAX_DEPTH (64)
        value = 0
        for _ in range(65):
            value = [value]
        with pytest.raises(CanonicalizationError, match="structure deeper than 64"):
            canonicalize_bytes(value)

    def test_depth_exactly_at_limit_boundary(self):
        # 65 levels deep should fail
        value = 0
        for _ in range(65):
            value = [value]
        with pytest.raises(CanonicalizationError, match="structure deeper than 64"):
            canonicalize_bytes(value)

    # --- Non-canonicalisable types ---

    @pytest.mark.parametrize("bad_type", [object(), set(), bytes(b"x"), frozenset({1})])
    def test_non_canonicalisable_type(self, bad_type):
        with pytest.raises(CanonicalizationError, match="non-canonicalisable type"):
            canonicalize_bytes(bad_type)

    def test_bytes_value(self):
        with pytest.raises(CanonicalizationError, match="non-canonicalisable type"):
            canonicalize_bytes(b"hello")

    def test_set_value(self):
        with pytest.raises(CanonicalizationError, match="non-canonicalisable type"):
            canonicalize_bytes({1, 2, 3})

    def test_object_value(self):
        with pytest.raises(CanonicalizationError, match="non-canonicalisable type"):
            canonicalize_bytes(object())

    def test_nested_non_canonicalisable(self):
        with pytest.raises(CanonicalizationError, match="non-canonicalisable type"):
            canonicalize_bytes({"a": set([1, 2])})

    def test_nested_non_string_key(self):
        with pytest.raises(CanonicalizationError, match="non-string object key"):
            canonicalize_bytes({"outer": {1: "inner"}})

    def test_nested_nan(self):
        with pytest.raises(CanonicalizationError, match="NaN/Infinity has no canonical JSON form"):
            canonicalize_bytes({"a": [1, float("nan")]})


class TestBehavioralPoints:
    """Specific behavioural guarantees."""

    def test_bool_not_treated_as_int(self):
        # True should serialize as "true", not "1"
        result = canonicalize_bytes(True)
        assert result == b"true"
        assert result != b"1"

    def test_false_not_treated_as_int(self):
        # False should serialize as "false", not "0"
        result = canonicalize_bytes(False)
        assert result == b"false"
        assert result != b"0"

    def test_canonicalize_returns_str(self):
        result = canonicalize(True)
        assert isinstance(result, str)
        assert result == "true"

    def test_canonicalize_matches_bytes_decoded(self):
        value = {"key": [1, 2, 3]}
        bytes_result = canonicalize_bytes(value)
        str_result = canonicalize(value)
        assert str_result == bytes_result.decode("utf-8")

    def test_canon_version_pin(self):
        assert CANON_VERSION == "jcs-rfc8785-v1"


class TestExceptionType:
    """Ensure the specific exception type is raised."""

    def test_exception_is_canonicalization_error(self):
        with pytest.raises(CanonicalizationError):
            canonicalize_bytes(float("nan"))

    def test_exception_is_value_error_subclass(self):
        with pytest.raises(ValueError):
            canonicalize_bytes(float("nan"))

    def test_not_bare_exception(self):
        # Verify we're not catching a broader exception
        with pytest.raises(CanonicalizationError):
            canonicalize_bytes(set())

        # This should NOT pass if we were raising a different exception
        try:
            canonicalize_bytes(set())
            assert False, "Should have raised"
        except Exception as e:
            assert type(e) is CanonicalizationError
