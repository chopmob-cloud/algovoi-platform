"""SHA-256 Merkle tree for batch-notarising many records under one signature.

Batch notarisation is how Records Vault imports at volume: instead of one Falcon-1024 signature per
document (the throughput ceiling), a batch of documents is folded into one SHA-256 Merkle root, and only
that root is signed into the archive chain. Any single document's membership is then proven **offline**
with a short inclusion proof against the signed root, from the public key alone.

Domain separation prevents leaf/node second-preimage confusion:
  leaf = SHA256(0x00 || doc_digest)      node = SHA256(0x01 || left || right)
An odd level duplicates its last node (Bitcoin-style), and the proof mirrors that so it verifies.
"""
from __future__ import annotations

import hashlib


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _unhex(doc_sha: str) -> bytes:
    """Accept "sha256:<hex>" or a bare "<hex>" and return the raw digest bytes."""
    return bytes.fromhex(doc_sha.split(":", 1)[1] if ":" in doc_sha else doc_sha)


def leaf_hash(doc_sha: str) -> bytes:
    return _sha(b"\x00" + _unhex(doc_sha))


def _node(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def merkle_root(doc_shas: list[str]) -> str:
    """Root over the documents' content hashes, as "sha256:<hex>"."""
    if not doc_shas:
        return "sha256:" + _sha(b"\x00").hex()
    level = [leaf_hash(s) for s in doc_shas]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return "sha256:" + level[0].hex()


def inclusion_proof(doc_shas: list[str], index: int) -> list[tuple[str, bool]]:
    """Proof that ``doc_shas[index]`` is under ``merkle_root(doc_shas)``.
    Each step is (sibling_hex, sibling_is_right)."""
    level = [leaf_hash(s) for s in doc_shas]
    idx = index
    proof: list[tuple[str, bool]] = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = idx ^ 1
        proof.append((level[sib].hex(), sib > idx))
        idx //= 2
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return proof


def index_from_proof(proof: list[tuple[str, bool]]) -> int:
    """Recover the leaf index the proof was built for.

    Each step carries one bit: the sibling sits to the right when the current
    node is a left child, so that step contributes a zero. This is the only
    place the position is expressed, which is why a verifier that accepts an
    index it never reads is not checking position at all.
    """
    index = 0
    try:
        for level, (_sib_hex, sib_is_right) in enumerate(proof):
            if not sib_is_right:
                index |= 1 << level
    except (TypeError, ValueError):
        # The proof is not readable as a proof. Return a position that no caller
        # can have asked for so the comparison in verify_inclusion fails closed.
        return -1
    return index


def verify_inclusion(doc_sha: str, index: int, proof: list[tuple[str, bool]], root: str) -> bool:
    """Recompute the root from ``doc_sha`` + its proof and check it equals the signed ``root``.

    Offline, hash-only, no key material needed here (the root's signature is checked separately).

    ``index`` is enforced, not advisory. It used to be accepted and ignored, so a
    caller passing a wrong index still got a true result while believing the
    position had been checked. The index is now compared against the position the
    proof actually encodes, and a mismatch returns false.

    Two limits, stated because they are real rather than theoretical. The index is
    consistent with the proof and with the root, which binds the position to the
    signed leaf set, but it is not itself signed: only the root is. And the tree
    duplicates its last node at an odd level, so for an odd-sized tree the final
    leaf also verifies at the duplicate slot. A caller that needs position bound
    beyond doubt should verify a proof against the leaf list inside the signed
    batch envelope, as ``verify_document_in_batch`` does, rather than trust an
    index supplied with a bare proof.
    """
    try:
        if index_from_proof(proof) != index:
            return False
        cur = leaf_hash(doc_sha)
        for sib_hex, sib_is_right in proof:
            sib = bytes.fromhex(sib_hex)
            cur = _node(cur, sib) if sib_is_right else _node(sib, cur)
    except (TypeError, ValueError):
        # A verifier is fed hostile input by definition. Malformed hex, a proof
        # that is None, or a digest that is not a digest means "not verified",
        # not "crash the caller". The batch path wraps this in a catch-all, so
        # the difference only shows for callers using the primitive directly.
        return False
    return ("sha256:" + cur.hex()) == root

