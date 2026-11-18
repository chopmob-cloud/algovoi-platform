"""Hardened input-bounds gate (commercial) — run BEFORE canonicalization.

This is the commercial parent of the open ``algovoi-substrate-guard`` lite tier. It keeps every
structural bound of the lite gate (size / depth / keys / array / string-length / nodes / number-safety)
and adds the bound a differential fuzz of 9 independent JCS implementations proved was missing:

  * ``string_safety`` -> ``REJECT_INVALID_UTF8``: a string (value OR object key) that is not encodable
    as UTF-8 — a lone surrogate (e.g. ``"\\ud800"``) or any non-scalar code unit — is rejected with a
    named code before canonicalization. The fuzzer showed that on such input AlgoVoi's Python
    canonicalizer (rfc8785) fail-closes while the Node canonicalizer (canonicalize 3.0.0) accepts and
    emits bytes, so two conforming impls disagree at the input-domain boundary. Rejecting it here, in
    one deterministic pre-canonicalization pass, makes the two impls behave identically regardless of
    which canonicalizer runs next.

The gate can raise the following stable codes:

  * ``REJECT_OVER_SIZE``: canonical JCS form exceeds ``max_bytes``.
  * ``REJECT_OVER_DEPTH``: nesting depth exceeds ``max_depth``.
  * ``REJECT_TOO_MANY_KEYS``: an object has more than ``max_object_keys`` keys.
  * ``REJECT_OVER_ARRAY``: an array has more than ``max_array_length`` items.
  * ``REJECT_OVER_STRING``: a string (value or object key) exceeds ``max_string_length``.
  * ``REJECT_OVER_NODES``: total visited values exceed ``max_total_nodes``.
  * ``REJECT_UNSAFE_NUMBER``: an integer is outside safe-integer range or a float is non-finite.
  * ``REJECT_INVALID_UTF8``: a string (value or object key) is not encodable as UTF-8.
  * ``REJECT_NON_STRING_KEY``: an object key is not a string.
  * ``REJECT_UNSUPPORTED_TYPE``: a value is not a JSON type (e.g. set, tuple, bytes).

Like the lite gate it changes no hash and adds no crypto primitive: a pure structural validator over the
parsed value, so every bound is identical in every language. Accept or reject — never truncate, never repair.

Commercial — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from algovoi_substrate import canonicalize_bytes, sha256_jcs

__all__ = ["Profile", "DEFAULT_PROFILE", "GuardError", "profile_ref", "guard"]

SHA256_PREFIX = "sha256:"
_SAFE_INT = 2 ** 53 - 1  # JSON safe-integer bound (largest exact IEEE-754 double integer)


class GuardError(ValueError):
    """Raised when a value violates a bound. ``code`` is the stable, named reject reason."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utf8_safe(s: str) -> bool:
    """True iff ``s`` is a sequence of Unicode scalar values (encodable as UTF-8). A lone surrogate —
    which ``json.loads('"\\ud800"')`` happily produces in Python and ``JSON.parse`` produces in JS —
    is NOT a scalar value and raises here, so it is rejected before it can reach a canonicalizer that
    might silently accept it."""
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


@dataclass(frozen=True)
class Profile:
    """The bounds in force. ``name`` is part of the content address so a renamed-but-identical-limits
    profile is still distinguishable. ``string_safety`` is the commercial addition: reject strings that
    are not valid UTF-8 (lone surrogates / non-scalar code units)."""
    name: str = "guard-pro-v1"
    max_bytes: int = 65536          # UTF-8 length of the canonical (JCS) form
    max_depth: int = 32             # nesting depth (root = 1)
    max_object_keys: int = 256      # keys in any single object
    max_array_length: int = 1024    # items in any single array
    max_string_length: int = 8192   # length of any single string (and object key)
    max_total_nodes: int = 4096     # total values visited (containers + scalars)
    number_safety: bool = True      # ints in safe range; reject non-finite floats
    string_safety: bool = True      # reject non-UTF-8 strings (lone surrogates) — fuzzer-driven

    def snapshot(self) -> dict:
        """Deterministic, JSON-safe document of the profile — the preimage of ``profile_ref``."""
        return {
            "name": self.name,
            "max_bytes": self.max_bytes,
            "max_depth": self.max_depth,
            "max_object_keys": self.max_object_keys,
            "max_array_length": self.max_array_length,
            "max_string_length": self.max_string_length,
            "max_total_nodes": self.max_total_nodes,
            "number_safety": self.number_safety,
            "string_safety": self.string_safety,
        }


DEFAULT_PROFILE = Profile()


def profile_ref(profile: Profile = DEFAULT_PROFILE) -> str:
    """``"sha256:" + SHA-256(JCS(profile))`` — the pinnable address of the bounds in force.
    Key order does not matter (JCS sorts), so the ref is invariant to how the profile was constructed."""
    return SHA256_PREFIX + sha256_jcs(profile.snapshot())


def _check_string(s: str, profile: Profile) -> None:
    if len(s) > profile.max_string_length:
        raise GuardError("REJECT_OVER_STRING")
    if profile.string_safety and not _utf8_safe(s):
        raise GuardError("REJECT_INVALID_UTF8")


def guard(value, profile: Profile = DEFAULT_PROFILE) -> bool:
    """Validate ``value`` against ``profile``. Return ``True`` or raise :class:`GuardError` (never both,
    never a partial result). Structural + safety bounds are checked in a single pass (fail-fast); the
    canonical-size bound is checked last, on an already-bounded value."""
    nodes = 0

    def walk(v, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > profile.max_total_nodes:
            raise GuardError("REJECT_OVER_NODES")
        if depth > profile.max_depth:
            raise GuardError("REJECT_OVER_DEPTH")
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, int):
            if profile.number_safety and abs(v) > _SAFE_INT:
                raise GuardError("REJECT_UNSAFE_NUMBER")
        elif isinstance(v, float):
            if profile.number_safety and not math.isfinite(v):
                raise GuardError("REJECT_UNSAFE_NUMBER")
        elif isinstance(v, str):
            _check_string(v, profile)
        elif isinstance(v, dict):
            if len(v) > profile.max_object_keys:
                raise GuardError("REJECT_TOO_MANY_KEYS")
            for k, val in v.items():
                if not isinstance(k, str):
                    raise GuardError("REJECT_NON_STRING_KEY")
                _check_string(k, profile)
                walk(val, depth + 1)
        elif isinstance(v, list):
            if len(v) > profile.max_array_length:
                raise GuardError("REJECT_OVER_ARRAY")
            for item in v:
                walk(item, depth + 1)
        else:
            raise GuardError("REJECT_UNSUPPORTED_TYPE")  # not a JSON value; cannot be canonicalised

    walk(value, 1)

    if len(canonicalize_bytes(value)) > profile.max_bytes:
        raise GuardError("REJECT_OVER_SIZE")
    return True
