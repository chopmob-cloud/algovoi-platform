"""
Shared receipt-field discipline (Substrate Rules 2/3: validate, do not coerce).

Independently authored from the receipt drafts. Used by settlement / refund /
cancellation / composite-trust-query builders. (compliance.py predates this and keeps its
own copies; behaviour is identical.)
"""
from __future__ import annotations

import os
from typing import Any, Iterable

from ..caip import CaipError, require_caip2, require_caip19

#: Env var enabling the fail-closed CAIP tier. OFF by default, and deliberately so: a
#: record built without it serialises byte-for-byte as it always has, so every already
#: anchored attestation keeps recomputing. Turning it on makes chain and asset identifiers
#: mandatory CAIP, which is what a new deployment should want from its first record.
STRICT_ENV = "SUBSTRATE2_CAIP_STRICT"


def caip_strict() -> bool:
    """True when the fail-closed CAIP tier is enabled.

    Read per call rather than cached at import so a process (or a test) can toggle it
    without a reimport.
    """
    return os.environ.get(STRICT_ENV, "") not in ("", "0", "false", "False")


class ReceiptError(ValueError):
    """Raised when a receipt field violates the format discipline."""


def require_str(field: str, value: Any) -> str:
    if not isinstance(value, str) or value == "":
        raise ReceiptError(f"{field} must be a non-empty string")
    return value


def require_int_ms(field: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReceiptError(f"{field} must be int (Substrate Rule 2); RFC 3339 strings rejected")
    if value < 0:
        raise ReceiptError(f"{field} must be non-negative")
    return value


def require_positive_int(field: str, value: Any) -> int:
    """A strictly positive integer (Substrate Rule 2: validate, do not coerce).

    Used for chain round/block numbers — round 0 is the genesis allocation and
    can never carry a settlement, so it is rejected along with negatives,
    bools and any non-int type.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReceiptError(f"{field} must be int (Substrate Rule 2); numeric strings rejected")
    if value <= 0:
        raise ReceiptError(f"{field} must be a positive integer")
    return value


def require_jurisdiction_flags(value: Any) -> list:
    if not isinstance(value, (list, tuple)):
        raise ReceiptError("jurisdiction_flags must be list of non-empty strings")
    if not all(isinstance(x, str) and x for x in value):
        raise ReceiptError("jurisdiction_flags entries must be non-empty strings")
    return list(value)


def require_enum(field: str, value: Any, allowed: Iterable[str]) -> str:
    allowed = tuple(allowed)
    if value not in allowed:
        raise ReceiptError(f"{field} must be one of {allowed}, got {value!r}")
    return value


def require_amount(field: str, value: Any) -> dict:
    """A monetary amount object: exactly {amount_minor: decimal-digit string, asset_id: string}."""
    if not isinstance(value, dict):
        raise ReceiptError(f"{field} must be an object")
    if set(value.keys()) != {"amount_minor", "asset_id"}:
        raise ReceiptError(f"{field} must have exactly the keys amount_minor and asset_id")
    amount_minor = value["amount_minor"]
    asset_id = value["asset_id"]
    if not isinstance(amount_minor, str) or not amount_minor.isdigit():
        raise ReceiptError(f"{field}.amount_minor must be a string of decimal digits")
    if not isinstance(asset_id, str) or not asset_id:
        raise ReceiptError(f"{field}.asset_id must be a non-empty string")
    if caip_strict():
        # Only under the opt-in tier: a bare ticker like "USDC" names no chain, so two
        # parties can agree on the string and still mean different assets. CAIP-19 makes
        # the asset self-describing before it reaches the digest.
        try:
            require_caip19(asset_id)
        except CaipError as exc:
            raise ReceiptError(f"{field}.asset_id: {exc}") from exc
    return {"amount_minor": amount_minor, "asset_id": asset_id}


def require_caip2_chain(field: str, value: Any) -> str:
    """Pre-hash gate for a CAIP-2 chain id, raising :class:`ReceiptError` on failure.

    Wraps :func:`substrate2.caip.require_caip2` so callers in this package see one
    exception type. Rejects ``"eip155:1\\n"`` and friends: the module anchors with
    ``\\A``/``\\Z``, never ``^``/``$``.
    """
    try:
        return require_caip2(value)
    except CaipError as exc:
        raise ReceiptError(f"{field}: {exc}") from exc
