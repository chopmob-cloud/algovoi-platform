# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""The verified-content cache must bind the verifying public key (security fix 2026-08-19).

Standalone runnable: python algovoi-command-center/tests/test_cache_key_binding.py

Without the key in the cache identity, a chain that verified under key A returned "verified (cached)"
when re-presented with a different key B, skipping the Falcon re-check (issuer misattribution).
"""
import base64
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from algovoi_command_center import licensing as _lic  # noqa: E402
_lic.require_license = lambda: {"test": True}

import rfc8785  # noqa: E402
from pqcrypto.sign.falcon_1024 import generate_keypair, sign  # noqa: E402

from algovoi_command_center.engine import verify_chain_cached  # noqa: E402

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _phash(p):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(p)).hexdigest()


def _chain(pk, sk, etype, rows):
    envs, prev = [], None
    for i, f in enumerate(rows):
        payload = {**f, "type": etype, "seq": i, "prev_entry_hash": prev}
        env = {"payload": payload, "sig": _b64u(sign(sk, rfc8785.dumps(payload))),
               "kid": hashlib.sha256(pk).hexdigest()[:16]}
        envs.append(_b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()))
        prev = _phash(payload)
    return envs


class _Cache:
    def __init__(self):
        self._s = set()

    def verified_seen(self, k):
        return k in self._s

    def verified_add(self, k):
        self._s.add(k)


def main():
    pkA, skA = generate_keypair()
    pkB, _skB = generate_keypair()
    cache = _Cache()
    envs = _chain(pkA, skA, "evt", [{"a": 1}, {"a": 2}])

    r1 = verify_chain_cached(envs, pkA, cache)
    check("chain verifies under its real key A (and is cached)", r1.verified)

    # Same envelopes, DIFFERENT public key B: must re-run Falcon (and fail), NOT hit the key-A cache.
    r2 = verify_chain_cached(envs, pkB, cache)
    check("key-swap to B is NOT served from the key-A cache (re-verifies -> fail)", not r2.verified)

    # Re-presenting under key A still fast-paths from cache.
    r3 = verify_chain_cached(envs, pkA, cache)
    check("unchanged chain under key A still cache-hits verified", r3.verified)

    print(f"\n=== CACHE-KEY-BINDING RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
