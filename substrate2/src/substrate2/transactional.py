"""
substrate2.transactional — transactional action chain (state transitions).

A transition preimage is
  {action_ref, state, transition_timestamp_ms, authority_verified_at_ms, revocation_check_at_ms}
and transition_hash = sha256_jcs(preimage). build_transactional_action_chain binds an
action_ref to an ordered set of transitions and returns
  {"action_ref": <hex>, "transitions": [{"state", "transition_hash", "prev_transition_hash"}, ...]}.
From draft-hopley-x402-canonicalisation-jcs-v1 + action_ref_transactional_v0 vectors.
Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .digest import sha256_jcs

# \A...\Z, never ^...$: `$` also matches before a trailing newline, so "<64 hex>\n" would be
# accepted as an action_ref and produce a divergent transition_hash. See execution.py.
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_TRANSITION_FIELDS = ("state", "transition_timestamp_ms", "authority_verified_at_ms", "revocation_check_at_ms")


class TransactionalError(ValueError):
    pass


def _s(field: str, value) -> str:
    if not isinstance(value, str) or value == "":
        raise TransactionalError(f"{field} must be a non-empty string")
    return value


def _action_ref(value) -> str:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise TransactionalError("action_ref must be 64-char lowercase hex")
    return value


def _i(field: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TransactionalError(f"{field} must be int")
    if value < 0:
        raise TransactionalError(f"{field} must be non-negative")
    return value


def transition_preimage(action_ref, state, transition_timestamp_ms, authority_verified_at_ms, revocation_check_at_ms) -> dict:
    return {
        "action_ref": _action_ref(action_ref),
        "state": _s("state", state),
        "transition_timestamp_ms": _i("transition_timestamp_ms", transition_timestamp_ms),
        "authority_verified_at_ms": _i("authority_verified_at_ms", authority_verified_at_ms),
        "revocation_check_at_ms": _i("revocation_check_at_ms", revocation_check_at_ms),
    }


def transition_hash(action_ref, state, transition_timestamp_ms, authority_verified_at_ms, revocation_check_at_ms) -> str:
    return sha256_jcs(
        transition_preimage(action_ref, state, transition_timestamp_ms, authority_verified_at_ms, revocation_check_at_ms)
    )


@dataclass
class TransitionPreimage:
    action_ref: str
    state: str
    transition_timestamp_ms: int
    authority_verified_at_ms: int
    revocation_check_at_ms: int


@dataclass
class TransitionInput:
    state: str
    transition_timestamp_ms: int
    authority_verified_at_ms: int
    revocation_check_at_ms: int


@dataclass
class TransitionRecord:
    state: str
    transition_hash: str
    prev_transition_hash: str | None


class TransactionalChain(dict):
    """{"action_ref": <hex>, "transitions": [...]} (dict subclass)."""


def build_transactional_action_chain(agent_id, action_type, scope, timestamp_ms, transitions) -> TransactionalChain:
    """Bind an action_ref to an ordered set of state transitions (each hashed over the action_ref)."""
    from .action import action_ref as _ar

    if not isinstance(transitions, list):
        raise TransactionalError("transitions must be a list")
    if not transitions:
        raise TransactionalError("transitions must be non-empty")
    ar = _ar(agent_id, action_type, scope, timestamp_ms)
    out = []
    prev = None
    for t in transitions:
        td = t.__dict__ if isinstance(t, (TransitionInput, TransitionPreimage)) else t
        if not isinstance(td, dict):
            raise TransactionalError("transition must be an object")
        for f in _TRANSITION_FIELDS:
            if f not in td:
                raise TransactionalError(f"transition missing required field: {f}")
        th = transition_hash(ar, td["state"], td["transition_timestamp_ms"], td["authority_verified_at_ms"], td["revocation_check_at_ms"])
        out.append({"state": td["state"], "transition_hash": th, "prev_transition_hash": prev})
        prev = th
    return TransactionalChain(action_ref=ar, transitions=out)


__all__ = [
    "TransactionalError", "TransitionPreimage", "TransitionInput", "TransitionRecord",
    "TransactionalChain", "transition_preimage", "transition_hash",
    "build_transactional_action_chain",
]
