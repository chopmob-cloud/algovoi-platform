"""
substrate2.atb_credential — ATB reputation credential (Falcon-1024) build + verify.

Implemented from atb-reputation-credential.mdx, atb-hub-conformance.mdx, and
draft-hopley-x402-atb-reputation-credential-00.

Envelope (per the published external verifier contract):
    {"payload": <dict>, "sig": b64url(Falcon(JCS(payload))), "alg": "Falcon-1024",
     "kid": sha256(pubkey)[:16]}
and the whole envelope JSON is then base64url-encoded. payload binds bench_kid == kid and
bench_issuer == the spec issuer; expires_at is an RFC 3339 "%Y-%m-%dT%H:%M:%SZ" instant.

Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from .canon import canonicalize_bytes
from . import pqc

SPEC_ISSUER = "did:web:agent-trust-bench.algovoi.co.uk"
ALG = "Falcon-1024"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64url_dec(s: str) -> bytes:
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    return base64.b64decode(s2)


@dataclass
class ATBVerifyResult:
    valid: bool
    reason: str = ""
    score: float | None = None
    passed: bool | None = None

    def __bool__(self) -> bool:
        return self.valid


def build_atb_envelope_b64(payload: dict, secret_key: bytes, public_key: bytes) -> str:
    """Build a base64url-encoded ATB envelope, binding payload to this signing key."""
    kid = pqc.falcon_kid(public_key)
    bound = {**payload, "bench_kid": kid, "bench_issuer": SPEC_ISSUER}
    canonical = canonicalize_bytes(bound)
    sig = pqc.sign_falcon_1024(secret_key, canonical)
    envelope = {"payload": bound, "sig": _b64url(sig), "alg": ALG, "kid": kid}
    return _b64url(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))


def decode_payload(envelope_b64: str) -> dict:
    """Return the inner payload dict of an envelope (no verification)."""
    return json.loads(_b64url_dec(envelope_b64))["payload"]


def verify_atb_envelope(envelope_b64: str, public_key: bytes) -> ATBVerifyResult:
    """Verify an ATB envelope against `public_key`. Never raises."""
    try:
        envelope = json.loads(_b64url_dec(envelope_b64))
        payload = envelope["payload"]
        sig = _b64url_dec(envelope["sig"])
    except Exception as exc:
        return ATBVerifyResult(False, f"decode: {exc}")
    if envelope.get("alg") != ALG:
        return ATBVerifyResult(False, f"alg: {envelope.get('alg')!r}")
    kid = pqc.falcon_kid(public_key)
    if envelope.get("kid") != kid:
        return ATBVerifyResult(False, "kid mismatch")
    if not pqc.verify_falcon_1024(public_key, canonicalize_bytes(payload), sig):
        return ATBVerifyResult(False, "sig invalid")
    if payload.get("bench_issuer") != SPEC_ISSUER:
        return ATBVerifyResult(False, f"issuer: {payload.get('bench_issuer')!r}")
    if payload.get("bench_kid") != kid:
        return ATBVerifyResult(False, "bench_kid inconsistent")
    return ATBVerifyResult(True, "ok", score=payload.get("score"), passed=payload.get("passed"))


__all__ = ["SPEC_ISSUER", "ATBVerifyResult", "build_atb_envelope_b64", "decode_payload", "verify_atb_envelope"]
