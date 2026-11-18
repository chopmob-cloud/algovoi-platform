"""Ed25519 public-key trust-boundary gate for the substrate2 RFC 9421 verifier.

Parity with algovoi-rfc9421-verifier's keycheck: small-order and non-canonical
public keys are rejected before signature verification, and verify_request fails
closed on such a key. Small-order detection is mathematical ([8]P == identity).
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from substrate2.rfc9421_keycheck import (
    WeakKeyError,
    check_ed25519_public_key,
    is_small_order,
)
from substrate2.rfc9421_verifier import verify_request

IDENTITY = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")
ORDER2_NEG1 = bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
ORDER4_YZERO = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
ORDER4_YZERO_HI = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080")
SMALL_ORDER = [IDENTITY, ORDER2_NEG1, ORDER4_YZERO, ORDER4_YZERO_HI]
NONCANONICAL_Y_EQ_P = bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
RFC8032_TEST1_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


@pytest.mark.parametrize("pk", SMALL_ORDER)
def test_small_order_detected(pk):
    assert is_small_order(pk) is True
    with pytest.raises(WeakKeyError):
        check_ed25519_public_key(pk)


def test_noncanonical_rejected():
    with pytest.raises(WeakKeyError):
        check_ed25519_public_key(NONCANONICAL_Y_EQ_P)


def test_wrong_length_rejected():
    with pytest.raises(WeakKeyError):
        check_ed25519_public_key(b"\x01" * 31)


def test_rfc8032_test1_key_accepted():
    check_ed25519_public_key(RFC8032_TEST1_PUB)  # must not raise
    assert is_small_order(RFC8032_TEST1_PUB) is False


def test_many_valid_keys_accepted():
    for _ in range(100):
        pk = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        check_ed25519_public_key(pk)
        assert is_small_order(pk) is False


def test_verify_request_fails_closed_on_small_order_key():
    # A small-order public key must make verify_request fail (not raise, not pass),
    # before/independent of signature validity.
    result = verify_request(
        method="POST",
        authority="api.algovoi.co.uk",
        path="/a2a",
        headers={
            "signature-input": 'sig=("@method");created=1750000000;keyid="k";alg="ed25519"',
            "signature": "sig=:" + "A" * 86 + "==:",
            "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
        },
        body=b"",
        public_key=IDENTITY,
        require_content_digest=False,
    )
    assert result.valid is False
