"""Hybrid post-quantum co-signing for admission receipts (crypto-agility).

An admission decision is signed with Falcon-1024 (suite default). In hybrid mode it is *also* co-signed
with ML-DSA-65 (FIPS 204), and a hybrid-aware verifier requires both. The two schemes rest on different
hard problems, so a future break of one still leaves forgery requiring a break of the other, and a
deployment can rotate Falcon-only -> hybrid -> ML-DSA-only without reissuing past receipts. Depends only
on ``pqcrypto`` — the dependency the gate already has.
"""
from __future__ import annotations

import hashlib

try:
    from pqcrypto.sign.ml_dsa_65 import (
        generate_keypair as _mldsa_generate_keypair,
        sign as _mldsa_sign,
        verify as _mldsa_verify,
    )
    HAS_MLDSA = True
except ImportError:  # pragma: no cover
    HAS_MLDSA = False

ALG = "ML-DSA-65"


class MlDsaUnavailable(RuntimeError):
    pass


def _require() -> None:
    if not HAS_MLDSA:
        raise MlDsaUnavailable("pqcrypto.sign.ml_dsa_65 not available (pip install pqcrypto>=0.4.0)")


def generate_keypair() -> tuple[bytes, bytes]:
    _require()
    pk, sk = _mldsa_generate_keypair()
    return pk, sk


def sign_bytes(secret_key: bytes, message: bytes) -> bytes:
    _require()
    return _mldsa_sign(secret_key, message)


def verify_bytes(public_key: bytes, message: bytes, signature: bytes) -> bool:
    _require()
    try:
        return bool(_mldsa_verify(public_key, message, signature))
    except Exception:  # noqa: BLE001
        return False


def kid_for(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]
