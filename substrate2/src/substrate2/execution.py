"""
substrate2.execution — execution_ref primitive (decision-bound execution evidence).

execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope,
                                        outcome, executed_at_ms}))

Byte-identical to the open algovoi-substrate execution_ref and the
execution_ref_v1 conformance set. Binds an executed action back to the exact
decision_ref (the keystone decision) that authorized it, so a verifier confirms
the execution is consistent with the decision, not merely correlated with an
identity. executed_at_ms is an epoch-millisecond integer hashed directly
(Substrate Rule 2); outcome is the closed enum below. No raw agent_id (it is
bound inside decision_ref) -> no-PII.
"""
from __future__ import annotations

import re

from .digest import sha256_jcs

# \A...\Z, never ^...$: in Python `$` also matches just before a trailing newline, so
# "sha256:<64 hex>\n" would validate and then be folded into the digest, producing a ref the
# verifying side cannot reproduce. \Z has no such exception. Pinned by caip_edge_v1.
_SHA256_REF_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
EXECUTION_OUTCOMES = ("COMMITTED", "SKIPPED", "FAILED", "REVERSED")


class ExecutionRefError(ValueError):
    pass


def _require_str(field: str, value) -> str:
    if not isinstance(value, str):
        raise ExecutionRefError(f"{field} must be str, got {type(value).__name__}")
    if value == "":
        raise ExecutionRefError(f"{field} must be a non-empty string")
    return value


def _require_decision_ref(value) -> str:
    if not isinstance(value, str):
        raise ExecutionRefError(f"decision_ref must be str, got {type(value).__name__}")
    if not _SHA256_REF_RE.match(value):
        raise ExecutionRefError("decision_ref must be 'sha256:<lowercase 64-char hex>'")
    return value


def _require_outcome(value) -> str:
    if not isinstance(value, str):
        raise ExecutionRefError(f"outcome must be str, got {type(value).__name__}")
    if value not in EXECUTION_OUTCOMES:
        raise ExecutionRefError(f"outcome must be one of {EXECUTION_OUTCOMES}, got {value!r}")
    return value


def _require_int_ms(value) -> int:
    if isinstance(value, bool):
        raise ExecutionRefError("executed_at_ms must be int, got bool")
    if not isinstance(value, int):
        raise ExecutionRefError(
            f"executed_at_ms must be int (Substrate Rule 2), got {type(value).__name__}"
        )
    if value < 0:
        raise ExecutionRefError("executed_at_ms must be non-negative")
    return value


def execution_ref_object(decision_ref: str, action_type: str, scope: str,
                         outcome: str, executed_at_ms: int) -> dict:
    """The canonical execution_ref preimage object."""
    return {
        "decision_ref": _require_decision_ref(decision_ref),
        "action_type": _require_str("action_type", action_type),
        "scope": _require_str("scope", scope),
        "outcome": _require_outcome(outcome),
        "executed_at_ms": _require_int_ms(executed_at_ms),
    }


def execution_ref(decision_ref: str, action_type: str, scope: str,
                  outcome: str, executed_at_ms: int) -> str:
    """execution_ref = "sha256:" + SHA-256(JCS(preimage))."""
    return "sha256:" + sha256_jcs(
        execution_ref_object(decision_ref, action_type, scope, outcome, executed_at_ms)
    )


def _require_ref(field: str, value) -> str:
    if not isinstance(value, str) or not _SHA256_REF_RE.match(value):
        raise ExecutionRefError(f"{field} must be 'sha256:<lowercase 64-char hex>'")
    return value


def screen_binding_ref(decision_ref: str, screen_ref: str) -> str:
    """Bind a decision to the compliance screen that preceded it (consistency, not correlation).

    screen_binding_ref = "sha256:" + SHA-256(JCS({decision_ref, screen_ref}))

    ``screen_ref`` is the content-addressed reference of a Compliance Receipt (e.g. the
    seven-field receipt of algovoi-compliance-gate-a2a), issued by the compliance tier. Byte
    identical to the open algovoi-substrate screen_binding_ref.
    """
    return "sha256:" + sha256_jcs({
        "decision_ref": _require_decision_ref(decision_ref),
        "screen_ref": _require_ref("screen_ref", screen_ref),
    })


__all__ = [
    "ExecutionRefError",
    "EXECUTION_OUTCOMES",
    "execution_ref",
    "execution_ref_object",
    "screen_binding_ref",
]
