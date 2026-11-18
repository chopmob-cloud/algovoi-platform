"""PKCS#11 (HSM) key custody for the AlgoVoi engine.

The Falcon-1024 signing key and the ML-KEM encryption key are wrapped by an AES key that lives inside
your HSM, addressed by label. AlgoVoi only ever holds the wrapped blob; at sign / decrypt time the
adapter asks the HSM to unwrap the key into memory, the post-quantum operation runs in-process, and
the buffer is best-effort zeroized. The HSM performs only a classical unwrap, so this works with any
PKCS#11 HSM today (SoftHSM, Thales Luna, Entrust nCipher, AWS CloudHSM via PKCS#11).

You pass a ready ``python-pkcs11`` session and the label of the wrapping (KEK) key; this module imports
nothing HSM-specific itself, so the integrator owns the HSM connection and PIN handling.
"""
from __future__ import annotations

from typing import Any

from algovoi_doc_archive.encryption import WrappedKeyEncryptor
from algovoi_doc_archive.signer import WrappedKeySigner

from algovoi_doc_archive_pkcs11 import licensing


class Pkcs11AdapterError(RuntimeError):
    """Raised when the HSM unwrap fails (missing slot/label, PIN, mechanism) or returns nothing."""


def _kek(session: Any, key_label: str) -> Any:
    """Resolve the HSM-resident wrapping key by label via the python-pkcs11 session."""
    return session.get_key(label=key_label)


def pkcs11_wrap(plaintext_key: bytes, *, session: Any, key_label: str) -> bytes:
    """One-time setup: wrap a raw private key with your HSM key. Returns the IV-prefixed ciphertext
    (python-pkcs11 handles IV generation for the key's mechanism). Store it; the plaintext key never
    needs to touch disk again."""
    licensing.require_license()
    return bytes(_kek(session, key_label).encrypt(plaintext_key))


def _unwrapper(session: Any, key_label: str):
    def unwrap(wrapped: bytes) -> bytearray:
        try:
            pt = _kek(session, key_label).decrypt(bytes(wrapped))
        except Exception as e:  # noqa: BLE001
            raise Pkcs11AdapterError(f"HSM unwrap failed for key {key_label!r}: {e}") from e
        if not pt:
            raise Pkcs11AdapterError(f"HSM returned empty plaintext for key {key_label!r}")
        # MUTABLE bytearray so the engine can zeroize the plaintext key after the PQC op
        return bytearray(pt)
    return unwrap


def pkcs11_signer(public_key: bytes, wrapped_secret_key: bytes, *, session: Any, key_label: str,
                  kid: str | None = None) -> WrappedKeySigner:
    """A :class:`WrappedKeySigner` whose Falcon-1024 key is unwrapped via the HSM at sign time."""
    licensing.require_license()
    return WrappedKeySigner(public_key, wrapped_secret_key,
                            unwrap=_unwrapper(session, key_label), kid=kid)


def pkcs11_encryptor(mlkem_public_key: bytes, wrapped_secret_key: bytes, *, session: Any,
                     key_label: str) -> WrappedKeyEncryptor:
    """A :class:`WrappedKeyEncryptor` whose ML-KEM key is unwrapped via the HSM at decrypt time."""
    licensing.require_license()
    return WrappedKeyEncryptor(mlkem_public_key, wrapped_secret_key,
                               unwrap=_unwrapper(session, key_label))
