"""
substrate2.audit — content_hash / prev_hash audit chain (runtime API).

A chain row is a dict {chain_position, prev_hash, content_hash, payload}:
  - head row has chain_position 0 and prev_hash None;
  - row N has chain_position N, prev_hash == row N-1's content_hash;
  - content_hash == sha256_jcs(payload).
verify_audit_chain walks the chain and raises AuditChainError on the first break.

(The on-the-wire serialised audit row in the compliance_receipt_v1 vectors is a separate
form, {prev_hash, receipt_content_hash, row_number}; the conformance harness validates that
form directly.) From draft-hopley-x402-compliance-receipt-02 §5. Not derived from v1 source.
"""
from __future__ import annotations

from .digest import sha256_jcs

GENESIS_PREV_HASH = "0" * 64


class AuditChainError(ValueError):
    pass


class AuditChainRow(dict):
    """A chain row (dict subclass: chain_position, content_hash, prev_hash, payload).

    Key INSERTION order matches the open ``algovoi_substrate.audit_chain.AuditChainRow``
    deliberately. It affects no digest -- JCS sorts keys, and ``dict`` equality ignores
    order -- but it is what ``repr(row)``, ``tuple(row)`` and ``list(row.values())`` follow.
    Aligning it means a customer moving from the open package sees byte-identical output
    even in logs, with no asterisk on the drop-in claim. Do not reorder.
    """


def append_to_chain(*, payload, prev_row=None) -> AuditChainRow:
    """Append `payload` to the chain, returning the new row."""
    content_hash = sha256_jcs(payload)
    if prev_row is None:
        return AuditChainRow(chain_position=0, content_hash=content_hash, prev_hash=None, payload=payload)
    return AuditChainRow(
        chain_position=prev_row["chain_position"] + 1,
        content_hash=content_hash,
        prev_hash=prev_row["content_hash"],
        payload=payload,
    )


def verify_audit_chain(rows) -> bool:
    """Verify chain integrity; raise AuditChainError on the first break. Returns True if intact."""
    rows = list(rows)
    for i, row in enumerate(rows):
        if row["chain_position"] != i:
            raise AuditChainError(f"chain_position {row['chain_position']} != expected {i}")
        if sha256_jcs(row["payload"]) != row["content_hash"]:
            raise AuditChainError(f"content_hash mismatch at position {i}")
        if i == 0:
            if row["prev_hash"] is not None:
                raise AuditChainError("head row prev_hash must be None")
        else:
            if row["prev_hash"] != rows[i - 1]["content_hash"]:
                raise AuditChainError(f"prev_hash break at position {i}")
    return True


__all__ = ["GENESIS_PREV_HASH", "AuditChainError", "AuditChainRow", "append_to_chain", "verify_audit_chain"]
