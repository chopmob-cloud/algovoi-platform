#!/usr/bin/env python3
"""Self-contained acceptance test for the ATB Credential Verifier service.

Proves, on the delivered image with NO external services:
  1. Out-of-box   — the service starts healthy with the issuer trust set loaded.
  2. Verify       — mint a real ATB Phase-2 credential (Falcon-1024 + Bulletproofs)
                    and verify it via /verify, fully offline.
  3. Fail-closed  — a credential that lies about its threshold is rejected.

    docker run --rm algovoi-atb-credential-verifier:clean python scripts/acceptance.py

Exit 0 = all green.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _mint(sk: bytes, pk: bytes, did: str, *, score_mu: int, prove_threshold_mu: int,
          claim_threshold_mu: int | None = None) -> str:
    import rfc8785
    import algovoi_bpverify as bp
    from pqcrypto.sign.falcon_1024 import sign as falcon_sign

    commitment, proof, _blinding = bp.prove_range_proof(score_mu, prove_threshold_mu)
    kid = hashlib.sha256(pk).hexdigest()[:16]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "atb_cert_version": "2",
        "agent_id_hash": hashlib.sha256(did.encode()).hexdigest(),
        "commitment_b64": _b64(commitment),
        "proof_b64": _b64(proof),
        "threshold_milliunits": claim_threshold_mu if claim_threshold_mu is not None else prove_threshold_mu,
        "zkp_curve": "ristretto255",
        "zkp_scheme": "bulletproofs-v1",
        "profile_set_hash": hashlib.sha256(b"acceptance").hexdigest(),
        "methodology_version": "atb-v1.0",
        "bench_issuer": did,
        "bench_kid": kid,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ietf_anchor": "draft-hopley-x402-canonicalisation-jcs-v1-04",
    }
    sig = falcon_sign(sk, rfc8785.dumps(payload))
    envelope = {"payload": payload, "alg": "Falcon-1024", "kid": kid, "sig": _b64url(sig)}
    return _b64url(json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode())


_failures: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        _failures.append(name)


def main() -> int:
    from pqcrypto.sign.falcon_1024 import generate_keypair

    pk, sk = generate_keypair()
    did = "did:web:acceptance-issuer"

    print("STEP 1 - service starts with the issuer trust set loaded")
    os.environ["ATB_VERIFIER_ISSUER_PKS"] = json.dumps({did: _b64(pk)})
    os.environ.pop("S2_HUB_URL", None)
    import app.main as m
    from fastapi.testclient import TestClient
    c = TestClient(m.app)
    h = c.get("/health").json()
    check("service healthy", h["status"] == "ok")
    check("issuer loaded into trust set", h["issuer_count"] == 1)

    print("STEP 2 - mint + verify a real Phase-2 credential (Falcon + Bulletproofs, offline)")
    cred = _mint(sk, pk, did, score_mu=820, prove_threshold_mu=700)
    r = c.post("/verify", json={"credential": cred}).json()
    check("credential verifies", bool(r.get("valid")))

    print("STEP 3 - fail-closed: a credential that lies about its threshold is rejected")
    liar = _mint(sk, pk, did, score_mu=820, prove_threshold_mu=700, claim_threshold_mu=950)
    rn = c.post("/verify", json={"credential": liar}).json()
    check("lying credential rejected", rn.get("valid") is False)

    print()
    if _failures:
        print(f"RESULT: FAIL - {len(_failures)} check(s): {', '.join(_failures)}")
        return 1
    print("RESULT: ALL GREEN - atb-credential-verifier service: trust loaded + real Phase-2 "
          "verify (Falcon + Bulletproofs, offline) + fail-closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
