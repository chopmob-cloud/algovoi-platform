#!/usr/bin/env python3
"""Self-contained acceptance test for the ZKP Receipt service.

Proves the service works out of the box on the delivered image, with NO external
services and NO configuration:

  1. Out-of-box  — the service imports/starts healthy with zero config (no secret
                   is required; an empty issuer registry is fine).
  2. Issuance    — a real ZKP-bound payment receipt is minted: a settled payment
                   plus a real ATB Phase-2 credential (Pedersen commitment +
                   Bulletproofs range proof), Falcon-1024 signed over the
                   JCS-canonical payload.
  3. Verify      — /verify confirms it (Falcon signature + real Bulletproofs range
                   proof + expiry + receipt fields).
  4. Fail-closed — a receipt that lies about its threshold is rejected by real
                   Bulletproofs verification.

Run inside the delivered image:

    docker run --rm algovoi-zkp-receipt:clean python scripts/acceptance.py

Exit 0 = all green; non-zero names the failed check(s).
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


def _mint_receipt(sk: bytes, pk: bytes, did: str, *, score_mu: int, prove_threshold_mu: int,
                  claim_threshold_mu: int | None = None) -> str:
    """Mint a real signed ZKP receipt. If claim_threshold_mu differs from
    prove_threshold_mu, the payload lies about the threshold (the Falcon signature
    stays valid but the Bulletproofs proof no longer verifies)."""
    import rfc8785
    import algovoi_bpverify as bp
    from pqcrypto.sign.falcon_1024 import sign as falcon_sign
    from algovoi_zkp_receipt import PaymentReceipt, build_zkp_receipt_payload

    commitment, proof, _blinding = bp.prove_range_proof(score_mu, prove_threshold_mu)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    receipt = PaymentReceipt(
        payment_id="pay-acc-0001",
        chain="base",
        amount_microusd=2_500_000,
        recipient="0xrecipientaddress",
        tx_id="0xdeadbeeftxhash",
        settled_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    payload = build_zkp_receipt_payload(
        receipt=receipt,
        commitment_b64=_b64(commitment),
        proof_b64=_b64(proof),
        threshold_milliunits=(claim_threshold_mu if claim_threshold_mu is not None else prove_threshold_mu),
        issuer_did=did,
        expires_at=(now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    kid = hashlib.sha256(pk).hexdigest()[:16]
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
    from algovoi_zkp_receipt import verify_zkp_receipt

    print("STEP 1 - out-of-box: the service imports/starts healthy with zero config")
    os.environ.pop("ZKP_RECEIPT_ISSUER_PKS", None)
    os.environ.pop("ZKP_RECEIPT_ISSUER_PKS_FILE", None)
    import app.main as m
    check("service module imports with no configuration (no required secret)", hasattr(m, "app"))
    check("empty issuer registry accepted (out-of-box clean)", m._issuer_pks == {})

    print("STEP 2 - mint a real ZKP-bound payment receipt (Falcon + Bulletproofs)")
    pk, sk = generate_keypair()
    did = "did:algovoi:acceptance:zkp-issuer"
    env = _mint_receipt(sk, pk, did, score_mu=820, prove_threshold_mu=700)
    check("receipt minted", bool(env))

    print("STEP 3 - verify the signed receipt")
    res = verify_zkp_receipt(env, _b64(pk))
    check("receipt verifies (Falcon + real Bulletproofs)", bool(res.valid))
    check("payment_id surfaced from the verified receipt", res.payment_id == "pay-acc-0001")

    print("STEP 4 - fail-closed: a receipt that lies about its threshold is rejected")
    liar = _mint_receipt(sk, pk, did, score_mu=820, prove_threshold_mu=700, claim_threshold_mu=950)
    resn = verify_zkp_receipt(liar, _b64(pk))
    check("lying receipt rejected", not resn.valid)
    check("rejected by real Bulletproofs verification (proof_invalid)",
          "proof_invalid" in (resn.failure_reason or ""))

    print()
    if _failures:
        print(f"RESULT: FAIL - {len(_failures)} check(s) failed: {', '.join(_failures)}")
        return 1
    print("RESULT: ALL GREEN - zkp-receipt works out of the box: zero-config start + "
          "real signed receipt verify + fail-closed range-proof check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
