"""HashiCorp Vault key custody (transit secrets engine) for the AlgoVoi engine.

Vault's transit engine wraps the Falcon-1024 signing key and the ML-KEM encryption key as a service —
the key-encryption-key never leaves Vault. AlgoVoi holds only the transit ciphertext token
(``vault:v1:...``); at sign / decrypt time the adapter calls transit ``Decrypt`` to unwrap the key into
memory, the post-quantum operation runs in-process, and the buffer is best-effort zeroized. Transit
performs only a classical unwrap, so this works with Vault today — no post-quantum support required.

Ideal for self-hosted / air-gapped enterprises that already run Vault.
"""
from __future__ import annotations

import base64
from typing import Any

from algovoi_doc_archive.encryption import WrappedKeyEncryptor
from algovoi_doc_archive.signer import WrappedKeySigner

from algovoi_doc_archive_vault import licensing


class VaultAdapterError(RuntimeError):
    """Raised when Vault transit ``Decrypt`` fails (sealed/403/network) or returns an unexpected shape."""


def _client(client: Any | None, **client_kwargs: Any) -> Any:
    if client is not None:
        return client
    import hvac  # deferred so the package imports without hvac until actually used
    return hvac.Client(**client_kwargs)


def _unwrapper(client: Any, key_name: str):
    def unwrap(wrapped: bytes) -> bytearray:
        ct = wrapped.decode() if isinstance(wrapped, (bytes, bytearray)) else wrapped
        try:
            r = client.secrets.transit.decrypt_data(name=key_name, ciphertext=ct)
        except Exception as e:  # noqa: BLE001
            raise VaultAdapterError(
                f"Vault transit decrypt failed for key {key_name!r}: {e}") from e
        try:
            b64 = r["data"]["plaintext"]
        except (KeyError, TypeError) as e:
            raise VaultAdapterError(
                f"Vault transit response for key {key_name!r} missing data.plaintext") from e
        pt = base64.b64decode(b64)
        if not pt:
            raise VaultAdapterError(f"Vault transit returned an empty plaintext for key {key_name!r}")
        # MUTABLE bytearray so the engine can zeroize the plaintext key after the PQC op
        return bytearray(pt)
    return unwrap


def vault_wrap(plaintext_key: bytes, *, key_name: str, client: Any | None = None, **client_kwargs: Any) -> bytes:
    """One-time setup: wrap a raw private key with a Vault transit key. Returns the transit ciphertext
    token (``vault:v1:...``) as bytes; store it. The plaintext key never needs to touch disk again."""
    licensing.require_license()
    c = _client(client, **client_kwargs)
    r = c.secrets.transit.encrypt_data(name=key_name, plaintext=base64.b64encode(plaintext_key).decode())
    return r["data"]["ciphertext"].encode()


def vault_signer(public_key: bytes, wrapped_secret_key: bytes, *, key_name: str,
                 client: Any | None = None, kid: str | None = None, **client_kwargs: Any) -> WrappedKeySigner:
    """A :class:`WrappedKeySigner` whose Falcon-1024 key is unwrapped via Vault transit at sign time."""
    licensing.require_license()
    c = _client(client, **client_kwargs)
    return WrappedKeySigner(public_key, wrapped_secret_key, unwrap=_unwrapper(c, key_name), kid=kid)


def vault_encryptor(mlkem_public_key: bytes, wrapped_secret_key: bytes, *, key_name: str,
                    client: Any | None = None, **client_kwargs: Any) -> WrappedKeyEncryptor:
    """A :class:`WrappedKeyEncryptor` whose ML-KEM key is unwrapped via Vault transit at decrypt time."""
    licensing.require_license()
    c = _client(client, **client_kwargs)
    return WrappedKeyEncryptor(mlkem_public_key, wrapped_secret_key, unwrap=_unwrapper(c, key_name))
