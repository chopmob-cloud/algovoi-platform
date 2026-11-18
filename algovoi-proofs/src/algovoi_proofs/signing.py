"""
Falcon-1024 (FIPS 206 / FN-DSA-1024) signing — bundled, standalone.

A proof is a Falcon-1024-signed envelope ``{"payload": {...}, "alg": "Falcon-1024",
"kid": sha256(pk)[:16], "sig": <b64url>}`` then base64url-encoded; the signature covers the
RFC 8785 (JCS) canonical bytes of the payload. Depends only on ``pqcrypto`` + ``rfc8785``.
"""
from __future__ import annotations

import base64
import hashlib
import json

import rfc8785

try:
    from pqcrypto.sign.falcon_1024 import (
        generate_keypair as _falcon_generate_keypair,
        sign as _falcon_sign,
        verify as _falcon_verify,
    )

    HAS_FALCON = True
except ImportError:  # pragma: no cover
    HAS_FALCON = False

PUBLIC_KEY_BYTES = 1793
SECRET_KEY_BYTES = 2305


class FalconUnavailable(RuntimeError):
    """Raised when pqcrypto is not installed."""


def _require() -> None:
    if not HAS_FALCON:
        raise FalconUnavailable("pqcrypto.sign.falcon_1024 not available (pip install pqcrypto>=0.4.0)")


def generate_keypair() -> tuple[bytes, bytes]:
    _require()
    pk, sk = _falcon_generate_keypair()
    return pk, sk


def sign_bytes(secret_key: bytes, message: bytes) -> bytes:
    _require()
    if len(secret_key) != SECRET_KEY_BYTES:
        raise ValueError(f"secret key must be {SECRET_KEY_BYTES} bytes, got {len(secret_key)}")
    return _falcon_sign(secret_key, message)


def verify_bytes(public_key: bytes, message: bytes, signature: bytes) -> bool:
    _require()
    if len(public_key) != PUBLIC_KEY_BYTES:
        return False
    try:
        return bool(_falcon_verify(public_key, message, signature))
    except Exception:  # noqa: BLE001
        return False


def kid_for(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def public_key_b64(public_key: bytes) -> str:
    return base64.b64encode(public_key).decode("ascii")


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def load_key_b64(b64: str) -> bytes:
    return base64.b64decode(b64)


def make_envelope(payload: dict, secret_key: bytes, public_key: bytes) -> str:
    sig = sign_bytes(secret_key, rfc8785.dumps(payload))
    env = {"payload": payload, "alg": "Falcon-1024", "kid": kid_for(public_key), "sig": b64u_encode(sig)}
    return b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())


def verify_payload(payload: dict, signature: bytes, public_key: bytes) -> bool:
    return verify_bytes(public_key, rfc8785.dumps(payload), signature)
