"""
substrate2.receipts.ctq — composite trust query response
(TRUSTED / PROVISIONAL / INSUFFICIENT_EVIDENCE / UNTRUSTED).

From draft-hopley-x402-composite-trust-query-02 + composite_trust_query_v1 vectors.
Not derived from v1 source.
"""
from __future__ import annotations

from ..canon import CANON_VERSION
from ._common import (
    ReceiptError,
    require_enum,
    require_int_ms,
    require_jurisdiction_flags,
    require_str,
)

TRUST_OUTCOMES = frozenset({"TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED"})


class CtqResponseError(ReceiptError):
    pass


def build_ctq_response(
    *,
    trust_outcome: str,
    chain_ref: str,
    query_ref: str,
    ctq_timestamp_ms: int,
    verifier_did: str,
    jurisdiction_flags: list,
    canon_version: str = CANON_VERSION,
) -> dict:
    try:
        return {
            "canon_version": require_str("canon_version", canon_version),
            "chain_ref": require_str("chain_ref", chain_ref),
            "ctq_timestamp_ms": require_int_ms("ctq_timestamp_ms", ctq_timestamp_ms),
            "jurisdiction_flags": require_jurisdiction_flags(jurisdiction_flags),
            "query_ref": require_str("query_ref", query_ref),
            "trust_outcome": require_enum("trust_outcome", trust_outcome, TRUST_OUTCOMES),
            "verifier_did": require_str("verifier_did", verifier_did),
        }
    except ReceiptError as exc:
        raise CtqResponseError(str(exc)) from exc


__all__ = ["TRUST_OUTCOMES", "CtqResponseError", "build_ctq_response"]
