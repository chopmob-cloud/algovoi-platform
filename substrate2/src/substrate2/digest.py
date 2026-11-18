"""
substrate2.digest — SHA-256 over JCS canonical bytes, and the "sha256:" prefix convention.

Implemented from canonicalisation-substrate.mdx (content_hash = SHA-256 of the JCS
canonical bytes; multibase-free lowercase hex; "sha256:" prefix for ref fields).
Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .canon import canonicalize_bytes

SHA256_PREFIX = "sha256:"


def sha256_jcs(value: Any) -> str:
    """SHA-256 (lowercase hex) of the JCS canonical bytes of `value`."""
    return hashlib.sha256(canonicalize_bytes(value)).hexdigest()


def sha256_jcs_prefixed(value: Any) -> str:
    """`sha256:` + sha256_jcs(value), for *_ref / *_payment_ref style fields."""
    return SHA256_PREFIX + sha256_jcs(value)


# Alias matching the shared.utils.jcs_canonical surface (bytes-returning callers).
sha256_hex = sha256_jcs


__all__ = ["SHA256_PREFIX", "sha256_jcs", "sha256_jcs_prefixed", "sha256_hex"]
