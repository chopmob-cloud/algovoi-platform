"""AWS KMS key custody for the AlgoVoi engine.

Your AWS KMS key (the KEK) wraps the Falcon-1024 signing key and the ML-KEM encryption key; AlgoVoi
only ever holds the wrapped blobs. At sign / decrypt time the adapter calls KMS ``Decrypt`` to unwrap
the key into memory, the post-quantum operation runs in-process, and the buffer is best-effort
zeroized. KMS itself performs only a classical unwrap, so this works with AWS KMS **today** — no
post-quantum support is required in KMS.

Both private keys are well under the KMS 4 KB plaintext limit (Falcon-1024 ~2.3 KB, ML-KEM-1024
~3.2 KB), so they wrap directly with a symmetric KMS key — no envelope-of-envelope needed.
"""
from __future__ import annotations

from typing import Any

from algovoi_doc_archive.encryption import WrappedKeyEncryptor
from algovoi_doc_archive.signer import WrappedKeySigner

from algovoi_doc_archive_kms import licensing


class KmsAdapterError(RuntimeError):
    """Raised when AWS KMS ``Decrypt`` fails or returns an unexpected response (no ``Plaintext``)."""


def _client(client: Any | None, **client_kwargs: Any) -> Any:
    if client is not None:
        return client
    import boto3  # deferred so the package imports without boto3 until actually used
    return boto3.client("kms", **client_kwargs)


def _unwrapper(c: Any):
    """Return an ``unwrap`` callable that KMS-``Decrypt``s the wrapped key into a mutable bytearray.

    Wraps provider failures (AccessDenied, throttling, network) in :class:`KmsAdapterError` and checks
    the response actually carried a non-empty ``Plaintext``, so a malformed KMS reply surfaces as a
    clear adapter error mid-sign rather than an opaque ``KeyError`` / empty-key Falcon failure.
    """
    def unwrap(w: bytes) -> bytearray:
        try:
            resp = c.decrypt(CiphertextBlob=w)
        except Exception as e:  # noqa: BLE001
            raise KmsAdapterError(f"KMS Decrypt failed: {e}") from e
        pt = resp.get("Plaintext") if isinstance(resp, dict) else None
        if not pt:
            raise KmsAdapterError("KMS Decrypt returned no Plaintext (unexpected response shape)")
        return bytearray(pt)
    return unwrap


def kms_wrap(plaintext_key: bytes, *, key_id: str, client: Any | None = None, **client_kwargs: Any) -> bytes:
    """One-time setup: wrap a raw private key with your KMS key (KMS ``Encrypt``). Store the returned
    blob; the plaintext key never needs to touch disk again."""
    licensing.require_license()
    return _client(client, **client_kwargs).encrypt(KeyId=key_id, Plaintext=plaintext_key)["CiphertextBlob"]


def kms_signer(public_key: bytes, wrapped_secret_key: bytes, *, client: Any | None = None,
               kid: str | None = None, **client_kwargs: Any) -> WrappedKeySigner:
    """A :class:`WrappedKeySigner` whose Falcon-1024 key is unwrapped via AWS KMS ``Decrypt`` at sign
    time. Hand it straight to ``Archive(signer=...)``."""
    licensing.require_license()
    c = _client(client, **client_kwargs)
    return WrappedKeySigner(public_key, wrapped_secret_key, unwrap=_unwrapper(c), kid=kid)


def kms_encryptor(mlkem_public_key: bytes, wrapped_secret_key: bytes, *, client: Any | None = None,
                  **client_kwargs: Any) -> WrappedKeyEncryptor:
    """A :class:`WrappedKeyEncryptor` whose ML-KEM key is unwrapped via AWS KMS ``Decrypt`` at decrypt
    time. Hand it straight to ``Archive(encryptor=...)``."""
    licensing.require_license()
    c = _client(client, **client_kwargs)
    return WrappedKeyEncryptor(mlkem_public_key, wrapped_secret_key, unwrap=_unwrapper(c))
