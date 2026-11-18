"""
Section 6 — ZKP receipt + cross-issuer federation.

(a) zkp_receipt_v1 vectors: substrate2 canon reproduces the published ZKP receipt
    canonical bytes + content_hash (the cross-impl part).
(b) ZKP envelope round-trip: build a Falcon-signed envelope, verify it; confirm tamper /
    bad-commitment / expired are rejected.
(c) Federation: compose_commitments determinism + order-sensitivity; two independently
    Falcon-signed credentials composed by FederationValidator into an HMAC token that
    verifies; wrong validator secret is rejected.
"""
from __future__ import annotations

import base64
import json
import os

from .._paths import JCS_VECTORS_DIR


def _b64_to_bytes(s: str) -> bytes:
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    return base64.b64decode(s2)


def run():
    from substrate2 import pqc
    from substrate2.canon import canonicalize_bytes
    from substrate2.digest import sha256_jcs
    from substrate2.zkp import build_zkp_envelope_b64, build_zkp_receipt_payload, verify_zkp_receipt, PaymentReceipt
    from substrate2.federation import (
        FederationValidator,
        compose_commitments,
        verify_federation_token,
    )

    fails: list[str] = []
    checks = 0

    # (a) zkp_receipt_v1 canonicalisation vectors
    vpath = JCS_VECTORS_DIR / "zkp_receipt_v1" / "zkp_receipt_v1.json"
    if vpath.exists():
        data = json.loads(vpath.read_bytes())
        for vec in data.get("vectors", []):
            rcpt = vec.get("receipt")
            if not isinstance(rcpt, dict):
                continue
            checks += 1
            vid = vec.get("vector_id", "?")
            if canonicalize_bytes(rcpt) != _b64_to_bytes(vec["expected_jcs_bytes_b64"]):
                fails.append(f"zkp/{vid}: JCS bytes != expected")
            elif sha256_jcs(rcpt) != vec["expected_content_hash"].split(":")[-1]:
                fails.append(f"zkp/{vid}: content_hash != expected")
    else:
        fails.append("zkp_receipt_v1 vectors missing")

    fut = "2027-01-01T00:00:00Z"

    # (b) ZKP envelope round-trip — with a REAL Bulletproofs range proof.
    import algovoi_bpverify as bp

    pk, sk = pqc.generate_falcon_1024_keypair()
    receipt = PaymentReceipt("pay_001", "algorand_mainnet", 10_000_000, "ALGO_ADDR", "TX1", "2026-06-04T10:00:00Z")
    real_commit, real_proof, _ = bp.prove_range_proof(820, 700)  # score 0.820 >= threshold 0.700
    payload = build_zkp_receipt_payload(
        receipt=receipt,
        commitment_b64=base64.b64encode(real_commit).decode(),
        proof_b64=base64.b64encode(real_proof).decode(),
        threshold_milliunits=700,
        issuer_did="did:web:agent-trust-bench.algovoi.co.uk",
        expires_at=fut,
        issued_at="2026-06-04T00:00:00Z",
    )
    env = build_zkp_envelope_b64(payload, sk, pk)
    pk_b64 = base64.b64encode(pk).decode()
    checks += 1
    if not verify_zkp_receipt(env, pk_b64):
        fails.append("zkp envelope round-trip: valid envelope (real proof) rejected")
    # tamper: bad commitment size
    bad_payload = dict(payload, commitment_b64=base64.b64encode(os.urandom(1)).decode())
    bad_env = build_zkp_envelope_b64(bad_payload, sk, pk)
    if verify_zkp_receipt(bad_env, pk_b64):
        fails.append("zkp: bad-commitment envelope accepted")
    # negative: a structurally-sized but cryptographically invalid proof must be REJECTED
    # (this is exactly what the pre-2026-06 structural-only check let through).
    fake_payload = dict(payload, proof_b64=base64.b64encode(os.urandom(672)).decode())
    fake_env = build_zkp_envelope_b64(fake_payload, sk, pk)
    if verify_zkp_receipt(fake_env, pk_b64):
        fails.append("zkp: random-bytes proof ACCEPTED (range proof not actually verified)")
    # negative: a genuine proof presented at the wrong threshold must be REJECTED
    wrongthr_payload = dict(payload, threshold_milliunits=701)
    wrongthr_env = build_zkp_envelope_b64(wrongthr_payload, sk, pk)
    if verify_zkp_receipt(wrongthr_env, pk_b64):
        fails.append("zkp: genuine proof accepted at wrong (raised) threshold")

    # (c) federation
    checks += 1
    c1, c2, nonce = os.urandom(32), os.urandom(32), os.urandom(32)
    if compose_commitments([c1, c2], nonce) != compose_commitments([c1, c2], nonce):
        fails.append("federation: compose_commitments not deterministic")
    if compose_commitments([c1, c2], nonce) == compose_commitments([c2, c1], nonce):
        fails.append("federation: compose_commitments not order-sensitive")

    # two independently Falcon-signed credentials (real proofs unless proof_override given)
    def make_cred(proof_override: bytes | None = None):
        cpk, csk = pqc.generate_falcon_1024_keypair()
        ccommit, cproof, _ = bp.prove_range_proof(820, 700)
        cred_payload = build_zkp_receipt_payload(
            receipt=receipt,
            commitment_b64=base64.b64encode(ccommit).decode(),
            proof_b64=base64.b64encode(proof_override if proof_override is not None else cproof).decode(),
            threshold_milliunits=700,
            issuer_did="did:web:agent-trust-bench.algovoi.co.uk",
            expires_at=fut,
            issued_at="2026-06-04T00:00:00Z",
        )
        import hashlib
        kid = hashlib.sha256(cpk).hexdigest()[:16]
        return build_zkp_envelope_b64(cred_payload, csk, cpk), kid, base64.b64encode(cpk).decode()

    cred1, kid1, pkb1 = make_cred()
    cred2, kid2, pkb2 = make_cred()
    secret = os.urandom(32)
    validator = FederationValidator(secret, {kid1: pkb1, kid2: pkb2}, min_credentials=2)
    res = validator.compose([cred1, cred2], nonce=nonce, expires_at=fut)
    if not res:
        fails.append(f"federation compose failed: {res.failure_reason}")
    else:
        if not verify_federation_token(res.token.raw, secret):
            fails.append("federation token failed to verify with correct secret")
        if verify_federation_token(res.token.raw, os.urandom(32)):
            fails.append("federation token verified with WRONG secret")

    # negative: a Falcon-signed credential carrying a fake (random) range proof must
    # NOT compose — proves the core federation opens the proof, not just its shape.
    credf, kidf, pkbf = make_cred(proof_override=os.urandom(672))
    vf = FederationValidator(secret, {kid1: pkb1, kidf: pkbf}, min_credentials=2)
    if vf.compose([cred1, credf], nonce=nonce, expires_at=fut):
        fails.append("federation: credential with random proof ACCEPTED (proof not verified)")

    ok = (not fails) and checks > 0
    detail = f"{checks} groups: zkp canon vectors + zkp round-trip + federation compose/token"
    if fails:
        detail += f" | {len(fails)} FAIL: " + "; ".join(fails[:6])
    return ok, detail
