#!/usr/bin/env python3
"""Self-contained acceptance test for the Federation Validator.

Proves the full federation flow on the delivered image, with NO external
services and NO pre-supplied validator secret:

  1. Independence — two separate issuers, no shared trust root.
  2. Bootstrap    — the app comes up with an auto-generated validator secret
                    (nothing supplied), issuers loaded.
  3. Issuance     — a real ATB ZKP Phase-2 credential per issuer: Falcon-1024
                    signature over the JCS-canonical payload + a real Bulletproofs
                    range proof (score >= threshold), exactly as atb-zkp-service
                    plus the bench would mint it.
  4. Compose      — both credentials compose into one federation token.
  5. Verify       — the token verifies (HMAC + expiry), binding both issuers.
  6. Fail-closed  — a credential that lies about its threshold is rejected by
                    real Bulletproofs verification.

Run inside the delivered image:

    docker run --rm algovoi-federation-validator:clean python scripts/acceptance.py

Exit 0 = all green; non-zero names the failed check(s).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta

# Make the `app` package importable when this is run as a bare script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _mint(sk: bytes, pk: bytes, did: str, *, score_mu: int, prove_threshold_mu: int,
          claim_threshold_mu: int | None = None) -> str:
    """Mint a real Phase-2 ATB ZKP credential, exactly as atb-zkp-service + the bench do.

    If ``claim_threshold_mu`` differs from ``prove_threshold_mu`` the payload lies about
    the threshold: the Falcon signature is still valid, but the Bulletproofs proof no
    longer verifies against the claimed threshold (the negative case).
    """
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
        "profile_set_hash": hashlib.sha256(b"acceptance-profile-set").hexdigest(),
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

    print("STEP 1 - two independent issuers (no shared trust root)")
    issuers = []
    for i in range(2):
        pk, sk = generate_keypair()
        issuers.append({"did": f"did:algovoi:acceptance:issuer-{i}", "pk": pk, "sk": sk})
    check("issuer A + issuer B generated", len(issuers) == 2)

    # Bring the service up WITHOUT a pre-supplied secret (exercise the bootstrap),
    # with the two issuers registered. Importing app.main runs _load_config().
    os.environ["FEDERATION_DATA_DIR"] = tempfile.mkdtemp()
    os.environ.pop("FEDERATION_VALIDATOR_SECRET", None)
    os.environ["FEDERATION_ISSUER_PKS"] = json.dumps({i["did"]: _b64(i["pk"]) for i in issuers})
    os.environ["FEDERATION_MIN_CREDENTIALS"] = "2"

    print("STEP 2 - bootstrap (no secret supplied -> auto-generated, issuers loaded)")
    import app.main as m
    from algovoi_federation_validator import verify_federation_token
    check("app booted without a supplied secret", isinstance(m._secret, bytes) and len(m._secret) >= 32)
    check("validator secret persisted to the data dir",
          os.path.exists(os.path.join(os.environ["FEDERATION_DATA_DIR"], "validator_secret.hex")))
    check("two issuers loaded into the trust set", len(m._issuer_pks) == 2)

    print("STEP 3 - mint a real Phase-2 credential per issuer (Falcon + Bulletproofs)")
    creds = [_mint(i["sk"], i["pk"], i["did"], score_mu=820, prove_threshold_mu=700) for i in issuers]
    check("two real credentials minted", len(creds) == 2)

    print("STEP 4 - compose -> federation token")
    res = m._validator.compose(creds)
    check("composition valid", bool(res.valid))
    check("federation token issued", bool(res.token and res.token.raw))
    check("token binds both issuers", bool(res.token) and len(res.token.issuers) == 2)

    print("STEP 5 - verify the federation token")
    payload = verify_federation_token(res.token.raw, m._secret) if res.token else None
    check("token verifies (HMAC + expiry)", payload is not None)
    check("verified token binds 2 issuers", bool(payload) and len(payload.get("issuers", [])) == 2)
    check("threshold_met asserted", bool(payload) and payload.get("threshold_met") is True)

    print("STEP 6 - fail-closed: a credential that lies about its threshold is rejected")
    liar = _mint(issuers[0]["sk"], issuers[0]["pk"], issuers[0]["did"],
                 score_mu=820, prove_threshold_mu=700, claim_threshold_mu=950)
    good = _mint(issuers[1]["sk"], issuers[1]["pk"], issuers[1]["did"],
                 score_mu=820, prove_threshold_mu=700)
    neg = m._validator.compose([liar, good])
    check("composition rejected", not neg.valid)
    check("rejected by real Bulletproofs verification (proof_invalid)",
          "proof_invalid" in (neg.failure_reason or ""))

    print()
    if _failures:
        print(f"RESULT: FAIL - {len(_failures)} check(s) failed: {', '.join(_failures)}")
        return 1
    print("RESULT: ALL GREEN - federation works out of the box: bootstrap + real "
          "cross-issuer compose/verify + fail-closed range-proof check.")
    return 0


def emit_e2e(out_dir: str) -> int:
    """Mint issuers + ready-to-POST request bodies for the HTTP e2e harness.

    Writes, into out_dir:
      issuer_pks.json   {"<did>": "<pk_b64>", ...}  (start the validator with this)
      compose.json      {"credentials": [<cert A>, <cert B>]}  (valid cross-issuer)
      compose_neg.json  {"credentials": [<threshold-lying cert>, <valid cert>]}
    """
    from pqcrypto.sign.falcon_1024 import generate_keypair

    os.makedirs(out_dir, exist_ok=True)
    issuers = []
    for i in range(2):
        pk, sk = generate_keypair()
        issuers.append({"did": f"did:algovoi:e2e:issuer-{i}", "pk": pk, "sk": sk})

    with open(os.path.join(out_dir, "issuer_pks.json"), "w") as fh:
        json.dump({i["did"]: _b64(i["pk"]) for i in issuers}, fh)

    good = [_mint(i["sk"], i["pk"], i["did"], score_mu=820, prove_threshold_mu=700) for i in issuers]
    with open(os.path.join(out_dir, "compose.json"), "w") as fh:
        json.dump({"credentials": good}, fh)

    liar = _mint(issuers[0]["sk"], issuers[0]["pk"], issuers[0]["did"],
                 score_mu=820, prove_threshold_mu=700, claim_threshold_mu=950)
    with open(os.path.join(out_dir, "compose_neg.json"), "w") as fh:
        json.dump({"credentials": [liar, good[1]]}, fh)

    print(f"emitted issuer_pks.json, compose.json, compose_neg.json to {out_dir}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--emit-e2e":
        sys.exit(emit_e2e(sys.argv[2]))
    sys.exit(main())
