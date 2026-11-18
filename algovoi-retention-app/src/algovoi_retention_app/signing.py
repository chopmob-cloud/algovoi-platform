"""Falcon-1024 signing for retention evidence packs.

Produces envelopes byte-compatible with the Compliance Command Center ingest
engine: an envelope is ``base64url(json({"payload": <dict>, "sig":
base64url(falcon_sign(JCS(payload))), "kid": <hex16>}))`` and the pack carries
the signer's public key as standard base64 in ``public_key.b64``. CCC (and any
external auditor) re-verifies every signature offline against that public key
using only ``pqcrypto`` + ``rfc8785`` -- no AlgoVoi service is trusted.
"""
from __future__ import annotations

import base64
import hashlib
import json

# substrate2 is the single crypto core: JCS canonicalisation, Falcon-1024 keygen/
# sign, and the sha256:-prefixed digest all route through it. substrate2 wraps the
# same pqcrypto/rfc8785 primitives, so the wire bytes are identical to the prior
# direct-primitive path (CCC and every offline verifier keep passing unchanged).
import substrate2
from substrate2.pqc import generate_falcon_1024_keypair, sign_falcon_1024


def generate_keypair() -> tuple[bytes, bytes]:
    """Falcon-1024 (public_key, secret_key), via substrate2."""
    return generate_falcon_1024_keypair()


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Detached Falcon-1024 signature over `message`, via substrate2."""
    return sign_falcon_1024(secret_key, message)


def _b64u(b: bytes) -> str:
    """URL-safe base64, no padding (CCC re-pads on decode)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _jcs(payload: object) -> bytes:
    return substrate2.canonicalize_bytes(payload)


def payload_hash(payload: dict) -> str:
    """The per-entry link hash, identical to CCC engine._payload_hash."""
    return substrate2.sha256_jcs_prefixed(payload)


class LocalSigner:
    """An in-process Falcon-1024 signer. Holds the keypair in memory.

    For production custody this can be swapped for a KMS/HSM-backed signer; the
    envelope format and the verification path are unchanged.
    """

    def __init__(self, public_key: bytes, secret_key: bytes) -> None:
        self.pk = public_key
        self.sk = secret_key

    @classmethod
    def generate(cls) -> "LocalSigner":
        pk, sk = generate_keypair()
        return cls(pk, sk)

    @classmethod
    def from_b64(cls, pk_b64: str, sk_b64: str) -> "LocalSigner":
        return cls(base64.b64decode(pk_b64), base64.b64decode(sk_b64))

    @property
    def kid(self) -> str:
        return hashlib.sha256(self.pk).hexdigest()[:16]

    def public_key_b64(self) -> str:
        """Standard base64 of the public key, for the pack's ``public_key.b64``."""
        return base64.b64encode(self.pk).decode("ascii")

    def secret_key_b64(self) -> str:
        return base64.b64encode(self.sk).decode("ascii")

    def envelope(self, payload: dict) -> str:
        """Sign ``payload`` and return the CCC-compatible envelope string."""
        sig = sign(self.sk, _jcs(payload))
        env = {"payload": payload, "sig": _b64u(sig), "kid": self.kid}
        return _b64u(json.dumps(env, separators=(",", ":")).encode("utf-8"))
