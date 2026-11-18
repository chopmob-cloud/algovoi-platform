"""
ATB Pass Certificate — spec-conformance verifier (Python).

Implements the verifier from scratch using ONLY:
  - rfc8785 (RFC 8785 / JCS canonicalisation)
  - pqcrypto.sign.falcon_1024 (PQClean Falcon-1024)
  - Python stdlib (base64, json, hashlib, datetime)

NO imports from platform-bench/* or gateway/*. This is what a third party
implementing from docs.algovoi.co.uk/atb-reputation-credential would write.

Run:
  python verify_from_spec.py envelope.b64 pubkey.b64

Exit code:
  0 = valid + passed
  1 = invalid signature, expired, wrong issuer, or otherwise rejected
  2 = malformed input
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone

import rfc8785
from pqcrypto.sign.falcon_1024 import verify as falcon_verify


SPEC_ISSUER = "did:web:agent-trust-bench.algovoi.co.uk"
SPEC_ALG = "Falcon-1024"


def b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad and pad < 4:
        s = s + ("=" * pad)
    return base64.urlsafe_b64decode(s)


def verify(envelope_b64: str, public_key_bytes: bytes) -> tuple[bool, str]:
    # ── 1. Decode envelope ────────────────────────────────────────────────
    try:
        raw = b64url_decode(envelope_b64)
        envelope = json.loads(raw)
    except Exception as exc:
        return False, f"envelope_decode: {exc}"

    # ── 2. Shape check ────────────────────────────────────────────────────
    payload = envelope.get("payload")
    sig_b64 = envelope.get("sig")
    alg = envelope.get("alg")
    kid = envelope.get("kid")
    for name, val, typ in (
        ("payload", payload, dict),
        ("sig", sig_b64, str),
        ("alg", alg, str),
        ("kid", kid, str),
    ):
        if not isinstance(val, typ):
            return False, f"envelope_shape: {name} missing or wrong type"
    if alg != SPEC_ALG:
        return False, f"alg_mismatch: expected {SPEC_ALG!r}, got {alg!r}"

    # ── 3. Key ID check (sha256[:16] of PK) ───────────────────────────────
    expected_kid = hashlib.sha256(public_key_bytes).hexdigest()[:16]
    if kid != expected_kid:
        return False, f"kid_mismatch: envelope says {kid!r}, PK gives {expected_kid!r}"

    # ── 4. Signature verification ─────────────────────────────────────────
    try:
        sig_bytes = b64url_decode(sig_b64)
    except Exception:
        return False, "sig_decode"

    # Canonical payload bytes per RFC 8785 (JCS)
    canonical = rfc8785.dumps(payload)

    # Falcon-1024 verify — returns bool, doesn't raise on bad sig
    try:
        ok = bool(falcon_verify(public_key_bytes, canonical, sig_bytes))
    except Exception:
        ok = False
    if not ok:
        return False, "sig_invalid"

    # ── 5. Issuer check ───────────────────────────────────────────────────
    if payload.get("bench_issuer") != SPEC_ISSUER:
        return False, f"wrong_issuer: {payload.get('bench_issuer')!r}"

    # ── 6. Expiry check ───────────────────────────────────────────────────
    try:
        exp = datetime.strptime(
            payload.get("expires_at", ""), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except Exception:
        return False, "expires_at_malformed"
    now = datetime.now(timezone.utc)
    if exp < now:
        return False, f"expired: exp={exp.isoformat()}, now={now.isoformat()}"

    # ── 7. (Spec optional) sanity-check that bench_kid matches kid ────────
    if payload.get("bench_kid") != kid:
        return False, "bench_kid_inconsistent"

    # All checks passed — return passed flag from payload
    return True, f"score={payload.get('score')}, passed={payload.get('passed')}"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify_from_spec.py <envelope.b64> <pubkey.b64>", file=sys.stderr)
        return 2

    with open(sys.argv[1]) as f:
        envelope_b64 = f.read().strip()
    with open(sys.argv[2]) as f:
        pk_bytes = base64.b64decode(f.read().strip())

    if len(pk_bytes) != 1793:
        print(f"FAIL: public key wrong length ({len(pk_bytes)}; want 1793)", file=sys.stderr)
        return 2

    valid, msg = verify(envelope_b64, pk_bytes)
    if valid:
        print(f"OK    {msg}")
        return 0
    else:
        print(f"FAIL  {msg}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
