"""
substrate2.action — action_ref primitive.

action_ref = sha256_jcs({agent_id, action_type, scope, timestamp_ms}); scope is a
non-empty string at the canonicalisation layer (no closed enum), timestamp_ms an integer.
From draft-hopley-x402-canonicalisation-jcs-v1 + action_ref_namespace_v0 /
action_ref_transactional_v0 vectors. Not derived from v1 source.
"""
from __future__ import annotations

from .digest import sha256_jcs


class ActionRefError(ValueError):
    pass


def _require_str(field: str, value) -> str:
    if not isinstance(value, str):
        raise ActionRefError(f"{field} must be str, got {type(value).__name__}")
    if value == "":
        raise ActionRefError(f"{field} must be a non-empty string")
    return value


def _require_int_ms(value) -> int:
    if isinstance(value, bool):
        raise ActionRefError("timestamp_ms must be int, got bool")
    if not isinstance(value, int):
        raise ActionRefError(f"timestamp_ms must be int (Substrate Rule 1), got {type(value).__name__}")
    if value < 0:
        raise ActionRefError("timestamp_ms must be non-negative")
    return value


def action_ref_object(agent_id: str, action_type: str, scope: str, timestamp_ms: int) -> dict:
    """The canonical action_ref preimage object."""
    return {
        "agent_id": _require_str("agent_id", agent_id),
        "action_type": _require_str("action_type", action_type),
        "scope": _require_str("scope", scope),
        "timestamp_ms": _require_int_ms(timestamp_ms),
    }


def action_ref(agent_id: str, action_type: str, scope: str, timestamp_ms: int) -> str:
    """SHA-256 (lowercase hex) of the JCS canonical preimage."""
    return sha256_jcs(action_ref_object(agent_id, action_type, scope, timestamp_ms))


__all__ = ["ActionRefError", "action_ref", "action_ref_object"]
