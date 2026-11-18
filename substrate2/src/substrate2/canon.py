"""
substrate2.canon — JCS (RFC 8785) canonicalisation with the substrate discipline layer.

Implemented from draft-hopley-x402-canonicalisation-jcs-v1 (Rules 1-4) and the public
conformance vectors (manifest canon_version "jcs-rfc8785-v1"). The byte-producing
primitive is the third-party `rfc8785` library (the same primitive the five-impl
convergence set was generated with); the independently-authored part is the discipline
layer that validates input *before* canonicalisation rather than coercing it.

Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import math
from typing import Any

import rfc8785

# In-band canonicalisation rule pin. Byte-load-bearing where embedded in a receipt.
CANON_VERSION = "jcs-rfc8785-v1"

# Discipline limit: reject absurdly deep structures rather than recurse unbounded.
_MAX_DEPTH = 64


class CanonicalizationError(ValueError):
    """Raised when input is not safe to canonicalise deterministically."""


def _validate(value: Any, *, depth: int = 0, path: str = "$") -> None:
    """
    Type-validate-before-canonicalise (Rule 3: reject, do not coerce).

    Permits the JSON value space (None, bool, int, str, finite float, list, dict with
    str keys). Rejects NaN/Infinity (no deterministic JSON form) and non-string object
    keys (JCS sorts by key; non-string keys are ambiguous). Float values are permitted
    here at the canonicalisation layer; field-level "integer-minor-unit only" discipline
    is enforced by the receipt builders that know each field's type, not by canonicalise.
    """
    if depth > _MAX_DEPTH:
        raise CanonicalizationError(f"{path}: structure deeper than {_MAX_DEPTH}")
    if value is None or isinstance(value, (str, int)) and not isinstance(value, bool):
        return
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(f"{path}: NaN/Infinity has no canonical JSON form")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _validate(item, depth=depth + 1, path=f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"{path}: non-string object key {k!r}")
            _validate(v, depth=depth + 1, path=f"{path}.{k}")
        return
    raise CanonicalizationError(f"{path}: non-canonicalisable type {type(value).__name__}")


def canonicalize_bytes(value: Any) -> bytes:
    """Return the RFC 8785 (JCS) canonical byte serialisation of `value`."""
    _validate(value)
    return rfc8785.dumps(value)


def canonicalize(value: Any) -> str:
    """Return the RFC 8785 (JCS) canonical form of `value` as a UTF-8 string."""
    return canonicalize_bytes(value).decode("utf-8")


__all__ = ["CANON_VERSION", "CanonicalizationError", "canonicalize", "canonicalize_bytes"]
