"""
Falcon-1024 (FIPS 206 / FN-DSA-1024) signing — bundled, standalone.

A compliance receipt is signed into a Falcon-1024 envelope ``{"payload": {...}, "alg": "Falcon-1024",
"kid": sha256(pk)[:16], "sig": <b64url>}`` then base64url-encoded; the signature covers the RFC 8785
(JCS) canonical bytes of the payload. Depends only on ``pqcrypto`` + ``rfc8785``.
"""
from __future__ import annotations

import base64
import hashlib
import json

# substrate2 is the single crypto core (Falcon-1024 + JCS canonicalisation). It
# wraps the same pqcrypto/rfc8785 primitives, so envelope bytes are identical to
# the prior direct-primitive path; every offline verifier still passes unchanged.
import substrate2
from substrate2.pqc import (
    generate_falcon_1024_keypair as _falcon_generate_keypair,
    sign_falcon_1024 as _falcon_sign,
    verify_falcon_1024 as _falcon_verify,
)

HAS_FALCON = True

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


def load_key_b64(b64: str) -> bytes:
    return base64.b64decode(b64)


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def make_envelope(payload: dict, secret_key: bytes, public_key: bytes) -> str:
    sig = sign_bytes(secret_key, substrate2.canonicalize_bytes(payload))
    env = {"payload": payload, "alg": "Falcon-1024", "kid": kid_for(public_key), "sig": b64u_encode(sig)}
    return b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())


def open_envelope(envelope_b64: str) -> tuple[dict, bytes, str]:
    env = json.loads(b64u_decode(envelope_b64))
    payload = env["payload"]
    if not isinstance(payload, dict) or env.get("alg") != "Falcon-1024":
        raise ValueError("unexpected envelope shape")
    return payload, b64u_decode(env["sig"]), str(env.get("kid", ""))


def verify_payload(payload: dict, signature: bytes, public_key: bytes) -> bool:
    return verify_bytes(public_key, substrate2.canonicalize_bytes(payload), signature)


def payload_hash(payload: dict) -> str:
    """Content hash of a payload's JCS canonical bytes (matches algovoi-proofs receipt binding)."""
    return "sha256:" + hashlib.sha256(substrate2.canonicalize_bytes(payload)).hexdigest()
