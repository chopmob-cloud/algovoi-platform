"""
substrate2.pqc — post-quantum signatures + KEM over JCS canonical bytes.

Signatures:
  - Falcon-1024  (FN-DSA / FIPS 206 draft)   pk 1793B  sk 2305B
  - ML-DSA-65    (NIST FIPS 204)             pk 1952B  sk 4032B  sig 3309B
Key encapsulation (data protection):
  - ML-KEM-1024  (NIST FIPS 203)             pk 1568B  sk 3168B  ct 1568B  ss 32B

Implemented from draft-hopley-x402-pqc-credential-binding-00 and atb-reputation-credential.mdx.
The byte primitives are PQClean via `pqcrypto` (an external dependency, not v1 code).
Signing is randomised, so the acceptance gate verifies signatures / round-trips KEM rather
than reproducing bytes.

Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import hashlib

try:
    from pqcrypto.sign.falcon_1024 import (
        generate_keypair as _falcon_generate_keypair,
        sign as _falcon_sign,
        verify as _falcon_verify,
    )
    _AVAILABLE = True
except Exception:  # pragma: no cover
    _AVAILABLE = False

try:
    from pqcrypto.sign.ml_dsa_65 import (
        generate_keypair as _mldsa_generate_keypair,
        sign as _mldsa_sign,
        verify as _mldsa_verify,
    )
    _MLDSA_AVAILABLE = True
except Exception:  # pragma: no cover
    _MLDSA_AVAILABLE = False

try:
    from pqcrypto.kem.ml_kem_1024 import (
        generate_keypair as _mlkem_generate_keypair,
        encrypt as _mlkem_encrypt,
        decrypt as _mlkem_decrypt,
    )
    _MLKEM_AVAILABLE = True
except Exception:  # pragma: no cover
    _MLKEM_AVAILABLE = False

FALCON_PUBLIC_KEY_BYTES = 1793
FALCON_SECRET_KEY_BYTES = 2305
SIGNATURE_ALGORITHM_IDENTIFIER = "Falcon-1024"

ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SECRET_KEY_BYTES = 4032
ML_DSA_65_ALGORITHM_IDENTIFIER = "ML-DSA-65"

ML_KEM_1024_PUBLIC_KEY_BYTES = 1568
ML_KEM_1024_SECRET_KEY_BYTES = 3168
ML_KEM_1024_CIPHERTEXT_BYTES = 1568
ML_KEM_1024_SHARED_SECRET_BYTES = 32
KEM_ALGORITHM_IDENTIFIER = "ML-KEM-1024"

# Signature algorithm identifiers this module can verify.
SIGNATURE_ALGORITHMS = (SIGNATURE_ALGORITHM_IDENTIFIER, ML_DSA_65_ALGORITHM_IDENTIFIER)


def _require() -> None:
    if not _AVAILABLE:
        raise RuntimeError("pqcrypto not installed; `pip install substrate2[pqc]`")


def generate_falcon_1024_keypair() -> tuple[bytes, bytes]:
    """Return (public_key 1793B, secret_key 2305B)."""
    _require()
    pk, sk = _falcon_generate_keypair()
    return pk, sk


def sign_falcon_1024(secret_key: bytes, message: bytes) -> bytes:
    """Detached Falcon-1024 signature over `message` (caller passes JCS canonical bytes)."""
    _require()
    return _falcon_sign(secret_key, message)


def verify_falcon_1024(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a Falcon-1024 signature. Never raises; returns False on any failure."""
    if not _AVAILABLE:
        return False
    try:
        return bool(_falcon_verify(public_key, message, signature))
    except Exception:
        return False


def falcon_kid(public_key: bytes) -> str:
    """ATB key id: sha256(public_key) truncated to 16 hex chars (distinct from JWS kid[:32])."""
    return hashlib.sha256(public_key).hexdigest()[:16]


# ── ML-DSA-65 (NIST FIPS 204) signatures ─────────────────────────────────────

def _require_mldsa() -> None:
    if not _MLDSA_AVAILABLE:
        raise RuntimeError("ml_dsa_65 unavailable; `pip install substrate2[pqc]` (pqcrypto>=0.4)")


def generate_ml_dsa_65_keypair() -> tuple[bytes, bytes]:
    """Return (public_key 1952B, secret_key 4032B)."""
    _require_mldsa()
    pk, sk = _mldsa_generate_keypair()
    return pk, sk


def sign_ml_dsa_65(secret_key: bytes, message: bytes) -> bytes:
    """Detached ML-DSA-65 signature over `message` (caller passes JCS canonical bytes)."""
    _require_mldsa()
    return _mldsa_sign(secret_key, message)


def verify_ml_dsa_65(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Never raises; returns False on any failure."""
    if not _MLDSA_AVAILABLE:
        return False
    try:
        return bool(_mldsa_verify(public_key, message, signature))
    except Exception:
        return False


def verify_signature(alg: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Algorithm-dispatching verify for Falcon-1024 and ML-DSA-65. Never raises."""
    if alg == SIGNATURE_ALGORITHM_IDENTIFIER:
        return verify_falcon_1024(public_key, message, signature)
    if alg == ML_DSA_65_ALGORITHM_IDENTIFIER:
        return verify_ml_dsa_65(public_key, message, signature)
    return False


# ── ML-KEM-1024 (NIST FIPS 203) key encapsulation ────────────────────────────

def _require_mlkem() -> None:
    if not _MLKEM_AVAILABLE:
        raise RuntimeError("ml_kem_1024 unavailable; `pip install substrate2[pqc]` (pqcrypto>=0.4)")


def generate_ml_kem_1024_keypair() -> tuple[bytes, bytes]:
    """Return (public_key 1568B, secret_key 3168B)."""
    _require_mlkem()
    pk, sk = _mlkem_generate_keypair()
    return pk, sk


def ml_kem_1024_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to `public_key`. Returns (ciphertext 1568B, shared_secret 32B)."""
    _require_mlkem()
    ct, ss = _mlkem_encrypt(public_key)
    return ct, ss


def ml_kem_1024_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate `ciphertext` with `secret_key`. Returns the 32B shared secret."""
    _require_mlkem()
    return _mlkem_decrypt(secret_key, ciphertext)


__all__ = [
    "FALCON_PUBLIC_KEY_BYTES",
    "FALCON_SECRET_KEY_BYTES",
    "SIGNATURE_ALGORITHM_IDENTIFIER",
    "SIGNATURE_ALGORITHMS",
    "generate_falcon_1024_keypair",
    "sign_falcon_1024",
    "verify_falcon_1024",
    "falcon_kid",
    "ML_DSA_65_PUBLIC_KEY_BYTES",
    "ML_DSA_65_SECRET_KEY_BYTES",
    "ML_DSA_65_ALGORITHM_IDENTIFIER",
    "generate_ml_dsa_65_keypair",
    "sign_ml_dsa_65",
    "verify_ml_dsa_65",
    "verify_signature",
    "ML_KEM_1024_PUBLIC_KEY_BYTES",
    "ML_KEM_1024_SECRET_KEY_BYTES",
    "ML_KEM_1024_CIPHERTEXT_BYTES",
    "ML_KEM_1024_SHARED_SECRET_BYTES",
    "KEM_ALGORITHM_IDENTIFIER",
    "generate_ml_kem_1024_keypair",
    "ml_kem_1024_encapsulate",
    "ml_kem_1024_decapsulate",
]
