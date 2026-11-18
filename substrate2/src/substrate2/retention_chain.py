"""
substrate2.retention_chain — retention chain substrate.

Implements the retention_chain_ref primitive and verify_signed_chain_link using
substrate2's own JCS digest and RFC 9421 verifier — no external package dependency.

Preimage schema (JCS-canonical, lexicographic field order):
    {
        "chain_seq":         int    -- zero-indexed sequence position
        "issuer_id":         str    -- non-empty issuer identifier
        "prev_receipt_hash": str    -- "sha256:<hex>" or "" for genesis
        "receipt_hash":      str    -- "sha256:<hex>" of current receipt JCS bytes
    }

Output: "sha256:" + SHA-256(JCS(preimage)).
From draft-hopley-x402-retention-chain-02 + retention_chain_v0/v1 vectors.
Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence, Union

from .digest import sha256_jcs

PublicKey = Union[bytes, str]


class RetentionChainError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_hash(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    h = value[7:]
    return len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def _require_str(field_name: str, value) -> str:
    if not isinstance(value, str) or not value:
        raise RetentionChainError(f"{field_name} must be a non-empty string")
    return value


# ---------------------------------------------------------------------------
# Core primitive
# ---------------------------------------------------------------------------

def retention_chain_ref(
    *,
    prev_receipt_hash: str,
    receipt_hash: str,
    chain_seq: int,
    issuer_id: str,
) -> str:
    """Compute the retention_chain_ref for a receipt link.

    Returns:
        "sha256:<64-lowercase-hex>" of the JCS-canonical preimage.
    """
    if isinstance(chain_seq, bool) or not isinstance(chain_seq, int) or chain_seq < 0:
        raise RetentionChainError("chain_seq must be a non-negative integer")
    _require_str("issuer_id", issuer_id)
    if chain_seq == 0 and prev_receipt_hash != "":
        raise RetentionChainError('genesis record (chain_seq=0) must have prev_receipt_hash=""')
    if chain_seq > 0 and not _valid_hash(prev_receipt_hash):
        raise RetentionChainError('prev_receipt_hash must be "sha256:<64-hex>" for chain_seq > 0')
    if not _valid_hash(receipt_hash):
        raise RetentionChainError('receipt_hash must be "sha256:<64-hex>"')
    preimage = {
        "chain_seq": chain_seq,
        "issuer_id": issuer_id,
        "prev_receipt_hash": prev_receipt_hash,
        "receipt_hash": receipt_hash,
    }
    return "sha256:" + sha256_jcs(preimage)


def verify_chain_link(
    *,
    chain_ref: str,
    prev_receipt_hash: str,
    receipt_hash: str,
    chain_seq: int,
    issuer_id: str,
) -> bool:
    """Verify a single chain link. Returns False on any mismatch or error."""
    try:
        return retention_chain_ref(
            prev_receipt_hash=prev_receipt_hash,
            receipt_hash=receipt_hash,
            chain_seq=chain_seq,
            issuer_id=issuer_id,
        ) == chain_ref
    except Exception:
        return False


def verify_chain_sequence(records: Sequence[dict]) -> bool:
    """Verify that a sequence of chain records forms a valid unbroken chain.

    Each record must contain: chain_ref, prev_receipt_hash, receipt_hash,
    chain_seq, issuer_id. Consecutive records must be adjacent (chain_seq N, N+1).
    """
    records = list(records)
    if not records:
        return True
    for i, rec in enumerate(records):
        if not verify_chain_link(
            chain_ref=rec["chain_ref"],
            prev_receipt_hash=rec["prev_receipt_hash"],
            receipt_hash=rec["receipt_hash"],
            chain_seq=rec["chain_seq"],
            issuer_id=rec["issuer_id"],
        ):
            return False
        if i > 0:
            prev = records[i - 1]
            if rec["chain_seq"] != prev["chain_seq"] + 1:
                return False
            if rec["prev_receipt_hash"] != prev["receipt_hash"]:
                return False
    return True


# ---------------------------------------------------------------------------
# Combined RFC 9421 + chain verification
# ---------------------------------------------------------------------------

@dataclass
class SignedChainLinkResult:
    """Result of verify_signed_chain_link."""
    signature_valid: bool = False
    chain_ref_valid: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.signature_valid and self.chain_ref_valid


def verify_signed_chain_link(
    *,
    method: str,
    authority: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    public_key: PublicKey,
    chain_ref: str,
    prev_receipt_hash: str,
    receipt_hash: str,
    chain_seq: int,
    issuer_id: str,
    scheme: str = "https",
    require_content_digest: bool = True,
    mode: str = "rfc9421",
) -> SignedChainLinkResult:
    """Verify an RFC 9421-signed HTTP request carrying a retention chain link.

    Checks two things independently in one call:
      1. The RFC 9421 HTTP signature (via substrate2.rfc9421_verifier).
      2. The retention_chain_ref integrity for that receipt link.

    Both must pass for SignedChainLinkResult.valid to be True. The checks are
    independent — a tampered chain ref and a valid signature returns
    chain_ref_valid=False, signature_valid=True.
    """
    from .rfc9421_verifier import verify_request

    result = SignedChainLinkResult()

    sig_result = verify_request(
        method=method,
        authority=authority,
        path=path,
        headers=headers,
        body=body,
        public_key=public_key,
        scheme=scheme,
        require_content_digest=require_content_digest,
        mode=mode,
    )
    result.signature_valid = sig_result.valid
    if not sig_result.valid:
        result.errors.extend(sig_result.errors)

    result.chain_ref_valid = verify_chain_link(
        chain_ref=chain_ref,
        prev_receipt_hash=prev_receipt_hash,
        receipt_hash=receipt_hash,
        chain_seq=chain_seq,
        issuer_id=issuer_id,
    )
    if not result.chain_ref_valid:
        result.errors.append("retention_chain_ref does not match")

    return result


__all__ = [
    "RetentionChainError",
    "PublicKey",
    "retention_chain_ref",
    "verify_chain_link",
    "verify_chain_sequence",
    "SignedChainLinkResult",
    "verify_signed_chain_link",
]
