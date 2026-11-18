"""Inclusion proof behaviour, including the two limits the verifier now states.

These tests are dependency free on purpose: ``merkle`` imports nothing but hashlib,
so the same file runs in a clean room with no package chain installed.
"""
from __future__ import annotations

import pytest

from algovoi_records_vault_importer import merkle


def _shas(n: int) -> list[str]:
    return [f"sha256:{i:064x}" for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17])
def test_each_leaf_verifies_at_its_own_position(n):
    shas = _shas(n)
    root = merkle.merkle_root(shas)
    for index, doc in enumerate(shas):
        assert merkle.verify_inclusion(doc, index, merkle.inclusion_proof(shas, index), root)


@pytest.mark.parametrize("claimed", [999, -7, 100])
def test_a_wrong_index_is_rejected(claimed):
    """The index used to be ignored, so any claim passed. It is enforced now."""
    shas = _shas(5)
    root = merkle.merkle_root(shas)
    proof = merkle.inclusion_proof(shas, 0)
    assert merkle.verify_inclusion(shas[0], claimed, proof, root) is False


def test_the_index_the_proof_encodes_is_recovered_exactly():
    shas = _shas(9)
    for index in range(len(shas)):
        assert merkle.index_from_proof(merkle.inclusion_proof(shas, index)) == index


@pytest.mark.parametrize("n", [3, 5, 7, 9])
def test_last_leaf_of_an_odd_tree_also_verifies_at_the_duplicate_slot(n):
    """Known limit, pinned so it cannot change silently.

    The tree duplicates its last node at an odd level, so the final leaf verifies
    at the duplicate position as well. Position for that one leaf is therefore
    ambiguous between the real slot and the copy. Binding position beyond doubt
    needs the leaf list inside a signed envelope, which is what
    ``importer.verify_document_in_batch`` verifies against.
    """
    shas = _shas(n)
    root = merkle.merkle_root(shas)
    last = n - 1
    assert merkle.verify_inclusion(shas[last], last, merkle.inclusion_proof(shas, last), root)
    assert merkle.verify_inclusion(shas[last], n, merkle.inclusion_proof(shas, n), root) is True


def test_a_document_not_in_the_batch_is_rejected():
    shas = _shas(5)
    root = merkle.merkle_root(shas)
    outsider = "sha256:" + "ff" * 32
    assert merkle.verify_inclusion(outsider, 0, merkle.inclusion_proof(shas, 0), root) is False


def test_a_tampered_sibling_is_rejected():
    shas = _shas(4)
    root = merkle.merkle_root(shas)
    proof = list(merkle.inclusion_proof(shas, 1))
    sib_hex, sib_right = proof[0]
    proof[0] = ("00" * 32 if sib_hex != "00" * 32 else "11" * 32, sib_right)
    assert merkle.verify_inclusion(shas[1], 1, proof, root) is False


def test_a_single_leaf_tree_root_is_the_leaf_hash():
    shas = _shas(1)
    assert merkle.merkle_root(shas) == "sha256:" + merkle.leaf_hash(shas[0]).hex()


@pytest.mark.parametrize(
    "doc_sha,index,proof",
    [
        ("sha256:zz", 0, [("aa" * 32, True)]),
        ("not a digest", 0, [("aa" * 32, True)]),
        ("sha256:" + "00" * 32, 0, None),
        ("sha256:" + "00" * 32, 0, ["not a pair"]),
        ("sha256:" + "00" * 32, 0, [(None, True)]),
    ],
)
def test_malformed_input_fails_closed_rather_than_raising(doc_sha, index, proof):
    """A verifier is fed hostile input by definition, so it returns False, not an exception."""
    root = merkle.merkle_root(_shas(2))
    assert merkle.verify_inclusion(doc_sha, index, proof, root) is False

