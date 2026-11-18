"""
substrate2.composite_trust_query — verifier-of-verifier aggregation hash.

composite_trust_query_hash(rows) = sha256_jcs over the rows after (a) dropping each row's
`sig` field and (b) sorting by `source_id`. So the hash is over the trust *evidence*, not the
signatures, and is invariant to row emission order (set semantics keyed by source_id). A
subset of rows, or any payload change, yields a distinct hash.

From draft-hopley-x402-composite-trust-query + the v1 test contract. Distinct from
receipts.ctq.build_ctq_response (the CTQ receipt builder). Not derived from v1 source.
See PROVENANCE.md.
"""
from __future__ import annotations

from .digest import sha256_jcs


class CompositeTrustQueryError(ValueError):
    pass


def composite_trust_query_hash(rows) -> str:
    if not isinstance(rows, (list, tuple)) or len(rows) == 0:
        raise CompositeTrustQueryError("rows must contain at least one row")
    cleaned = []
    for row in rows:
        if not isinstance(row, dict):
            raise CompositeTrustQueryError("each row must be a mapping")
        source_id = row.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            raise CompositeTrustQueryError("each row must have a non-empty string source_id")
        cleaned.append({k: v for k, v in row.items() if k != "sig"})
    cleaned.sort(key=lambda r: r["source_id"])
    return sha256_jcs(cleaned)


__all__ = ["CompositeTrustQueryError", "composite_trust_query_hash"]
