"""Pluggable signing backend (key custody) — mirrors the :mod:`backend` storage pattern.

The engine signs every receipt through a :class:`Signer`, so *where the private key lives* is
pluggable. :class:`LocalSigner` holds the Falcon-1024 key in-process (bundled, air-gap friendly, the
default). HSM / KMS / Vault custody ship as separate adapter packages
(``algovoi-doc-archive-kms`` / ``-pkcs11`` / ``-vault``) that implement the same interface.

The envelope output verifies identically regardless of custody — only *where* the key sits changes,
never the evidence format — so verifiers, conformance vectors, and the adversarial suite are
unaffected.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from algovoi_doc_archive import signing


@runtime_checkable
class Signer(Protocol):
    """Performs the private-key signing operation without exposing the key to the engine."""

    def public_key(self) -> bytes: ...
    def kid(self) -> str: ...
    def sign(self, message: bytes) -> bytes: ...
    def can_sign(self) -> bool: ...


class LocalSigner:
    """Holds the Falcon-1024 private key in-process. Air-gap friendly; the default custody mode.

    Construct with ``secret_key`` to sign, or public-key-only for a read-only / audit view
    (``can_sign()`` is then ``False`` and :meth:`sign` raises).
    """

    def __init__(self, public_key: bytes, secret_key: bytes | None = None) -> None:
        self._pk = public_key
        self._sk = secret_key
        self._kid = signing.kid_for(public_key)

    def public_key(self) -> bytes:
        return self._pk

    def kid(self) -> str:
        return self._kid

    def can_sign(self) -> bool:
        return self._sk is not None

    def sign(self, message: bytes) -> bytes:
        if self._sk is None:
            raise RuntimeError("LocalSigner is read-only (constructed without a secret key)")
        return signing.sign_bytes(self._sk, message)


def _zeroize(buf) -> None:
    """Best-effort wipe of a mutable buffer. Python cannot wipe immutable ``bytes``; an ``unwrap``
    that returns a ``bytearray`` gets wiped after signing."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


class WrappedKeySigner:
    """Signer whose Falcon-1024 private key is stored **wrapped** (encrypted) by an external KEK.

    Only the wrapped key is held here; the key-encryption-key lives in the enterprise's KMS / HSM /
    Vault and never leaves it. At sign time the ``unwrap`` callable asks that service to decrypt the
    wrapped key into memory, the engine signs, then the buffer is best-effort zeroized — the plaintext
    Falcon key is never persisted. Provider-agnostic by design: the ``algovoi-doc-archive-kms`` /
    ``-pkcs11`` / ``-vault`` adapters simply supply an ``unwrap`` backed by their service. Works with
    every provider today because the service performs only a classical unwrap, not a Falcon op.

    ``unwrap`` is ``Callable[[bytes], bytes | bytearray]`` mapping the wrapped key to the raw Falcon
    secret key. Provide ``kid`` to pin the published key id; it defaults to ``kid_for(public_key)``.
    """

    def __init__(self, public_key: bytes, wrapped_secret_key: bytes, unwrap, *,
                 kid: str | None = None) -> None:
        self._pk = public_key
        self._wrapped = wrapped_secret_key
        self._unwrap = unwrap
        self._kid = kid or signing.kid_for(public_key)

    def public_key(self) -> bytes:
        return self._pk

    def kid(self) -> str:
        return self._kid

    def can_sign(self) -> bool:
        return True

    def sign(self, message: bytes) -> bytes:
        sk = self._unwrap(self._wrapped)
        try:
            # pqcrypto's Falcon binding requires an immutable `bytes`, so this materialises one
            # transient copy that Python cannot wipe (immutable). The mutable `sk` buffer IS wiped
            # in `finally`; the copy is released immediately and never persisted.
            return signing.sign_bytes(bytes(sk), message)
        finally:
            _zeroize(sk)
