"""
Encryption at rest — one method, applied in the engine so every backend stores ciphertext.

Two interchangeable encryptors implement the same :class:`Encryptor` interface; the engine encrypts
**before** handing bytes to any storage backend, so local-disk and S3 archives are encrypted
identically:

- :class:`HybridPqcEncryptor` — **post-quantum**: ML-KEM-1024 (KEM) encapsulates a fresh per-document
  key; the document is sealed with AES-256-GCM (DEM). Matches the Falcon-1024 signing — the archive is
  post-quantum on both axes. ``alg = "ML-KEM-1024+AES-256-GCM"``.
- :class:`AesGcmEncryptor` — symmetric AES-256-GCM under an injected 32-byte key. ``alg = "AES-256-GCM"``.

Blob framing: ``HybridPqcEncryptor`` → ``u16(len kem_ct) | kem_ct | nonce(12) | ciphertext+tag``;
``AesGcmEncryptor`` → ``nonce(12) | ciphertext+tag``.
"""
from __future__ import annotations

import hashlib
import os
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from pqcrypto.kem.ml_kem_1024 import (
        decrypt as _kem_decap,
        encrypt as _kem_encap,
        generate_keypair as _kem_generate_keypair,
    )

    HAS_MLKEM = True
except ImportError:  # pragma: no cover
    HAS_MLKEM = False

NONCE_BYTES = 12


@runtime_checkable
class Encryptor(Protocol):
    alg: str
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, blob: bytes) -> bytes: ...
    @property
    def can_decrypt(self) -> bool: ...


def _aes_key_from(secret: bytes) -> bytes:
    """Derive a 32-byte AES-256 key from a shared secret (SHA-256 — domain-stable, fixed length)."""
    return hashlib.sha256(secret).digest()


class AesGcmEncryptor:
    """Symmetric AES-256-GCM under an injected 32-byte key."""

    alg = "AES-256-GCM"

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext, None)

    def decrypt(self, blob: bytes) -> bytes:
        nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
        return AESGCM(self._key).decrypt(nonce, ct, None)

    @property
    def can_decrypt(self) -> bool:
        return True


def generate_mlkem_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) for ML-KEM-1024. Public key encrypts; secret key decrypts."""
    if not HAS_MLKEM:
        raise RuntimeError("pqcrypto.kem.ml_kem_1024 unavailable (pip install pqcrypto>=0.4.0)")
    return _kem_generate_keypair()


class HybridPqcEncryptor:
    """Post-quantum hybrid: ML-KEM-1024 KEM + AES-256-GCM DEM, fresh per-document key.

    Provide the ML-KEM public key to encrypt (archive). The secret key is needed only to decrypt
    (retrieve) — an archive node can be write-only by withholding it.
    """

    alg = "ML-KEM-1024+AES-256-GCM"

    def __init__(self, public_key: bytes, secret_key: bytes | None = None) -> None:
        if not HAS_MLKEM:
            raise RuntimeError("pqcrypto.kem.ml_kem_1024 unavailable (pip install pqcrypto>=0.4.0)")
        self._pk = public_key
        self._sk = secret_key

    def encrypt(self, plaintext: bytes) -> bytes:
        kem_ct, shared = _kem_encap(self._pk)           # (ciphertext, shared_secret)
        key = _aes_key_from(shared)
        nonce = os.urandom(NONCE_BYTES)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return len(kem_ct).to_bytes(2, "big") + kem_ct + nonce + ct

    def decrypt(self, blob: bytes) -> bytes:
        if self._sk is None:
            raise RuntimeError("ML-KEM secret key required to decrypt")
        n = int.from_bytes(blob[:2], "big")
        kem_ct, rest = blob[2:2 + n], blob[2 + n:]
        nonce, ct = rest[:NONCE_BYTES], rest[NONCE_BYTES:]
        key = _aes_key_from(_kem_decap(self._sk, kem_ct))
        return AESGCM(key).decrypt(nonce, ct, None)

    @property
    def can_decrypt(self) -> bool:
        return self._sk is not None
