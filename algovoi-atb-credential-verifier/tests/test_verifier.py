"""
Tests for algovoi-atb-credential-verifier.

Uses a synthetic Falcon-1024 keypair (via pqcrypto if available, or mocks)
so the full verification path is exercised without hitting live endpoints.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
import rfc8785

from algovoi_atb_credential_verifier import ATBCredentialVerifier, ATBVerifyResult


# ── Helpers ───────────────────────────────────────────────────────────────────

ISSUER_DID = "did:web:test-bench.example.com"
FUTURE = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
PAST = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_verifier(pk_b64: str) -> ATBCredentialVerifier:
    return ATBCredentialVerifier(
        issuer_did=ISSUER_DID,
        public_key_b64=pk_b64,
    )


def _build_credential(payload: dict, pk_bytes: bytes, sk_bytes: bytes) -> str:
    """Build a base64url-encoded ATB credential envelope using pqcrypto."""
    canonical = rfc8785.dumps(payload)
    try:
        from pqcrypto.sign.falcon_1024 import sign
        sig_bytes = sign(sk_bytes, canonical)
    except ImportError:
        pytest.skip("pqcrypto not installed — skipping Falcon integration tests")
    kid = hashlib.sha256(pk_bytes).hexdigest()[:16]
    envelope = {
        "payload": payload,
        "alg": "Falcon-1024",
        "kid": kid,
        "sig": base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode(),
    }
    envelope_json = json.dumps(envelope, separators=(",", ":"))
    return base64.urlsafe_b64encode(envelope_json.encode()).rstrip(b"=").decode()


def _gen_keypair():
    try:
        from pqcrypto.sign.falcon_1024 import generate_keypair
        return generate_keypair()
    except ImportError:
        pytest.skip("pqcrypto not installed")


# ── Missing / malformed header ────────────────────────────────────────────────

def test_missing_header_returns_invalid():
    v = ATBCredentialVerifier(issuer_did=ISSUER_DID, public_key_b64="Cg==")
    result = v.verify(None)
    assert not result.valid
    assert result.failure_reason == "missing_header"


def test_empty_header_returns_invalid():
    v = ATBCredentialVerifier(issuer_did=ISSUER_DID, public_key_b64="Cg==")
    result = v.verify("   ")
    assert not result.valid
    assert result.failure_reason == "missing_header"


def test_garbage_header_returns_invalid():
    v = ATBCredentialVerifier(issuer_did=ISSUER_DID, public_key_b64="Cg==")
    result = v.verify("not-a-valid-credential")
    assert not result.valid
    assert result.failure_reason == "envelope_decode"


def test_no_public_key_returns_invalid():
    v = ATBCredentialVerifier(issuer_did=ISSUER_DID)
    # Build a syntactically valid but unsigned envelope
    payload = {"bench_issuer": ISSUER_DID, "expires_at": FUTURE, "passed": True}
    envelope = json.dumps({"payload": payload, "alg": "Falcon-1024", "kid": "abc", "sig": "AAAA"})
    header = base64.urlsafe_b64encode(envelope.encode()).rstrip(b"=").decode()
    result = v.verify(header)
    assert not result.valid
    assert result.failure_reason == "no_public_key"


# ── ATBVerifyResult properties ────────────────────────────────────────────────

def test_grants_discount_false_when_invalid():
    r = ATBVerifyResult(valid=False, passed=False, score=None, expires_at=None, kid=None, failure_reason="x")
    assert not r.grants_discount


def test_grants_discount_true_when_valid_and_passed():
    r = ATBVerifyResult(valid=True, passed=True, score=0.9, expires_at=None, kid="abc", failure_reason=None)
    assert r.grants_discount


def test_grants_discount_false_when_valid_but_not_passed():
    r = ATBVerifyResult(valid=True, passed=False, score=0.5, expires_at=None, kid="abc", failure_reason=None)
    assert not r.grants_discount


def test_has_zkp_true_when_zkp_fields_present():
    r = ATBVerifyResult(
        valid=True, passed=True, score=None, expires_at=None, kid="abc", failure_reason=None,
        commitment_b64="abc", proof_b64="def",
    )
    assert r.has_zkp


def test_has_zkp_false_when_no_zkp_fields():
    r = ATBVerifyResult(valid=True, passed=True, score=0.9, expires_at=None, kid="abc", failure_reason=None)
    assert not r.has_zkp


# ── Falcon-1024 integration tests (require pqcrypto) ─────────────────────────

def test_valid_phase1_credential_passes():
    pk, sk = _gen_keypair()
    pk_b64 = base64.b64encode(pk).decode()
    payload = {
        "atb_cert_version": "1",
        "bench_issuer": ISSUER_DID,
        "expires_at": FUTURE,
        "passed": True,
        "score": 0.87,
        "threshold": 0.70,
    }
    header = _build_credential(payload, pk, sk)
    v = _make_verifier(pk_b64)
    result = v.verify(header)
    assert result.valid
    assert result.passed
    assert result.score == pytest.approx(0.87)
    assert result.grants_discount


def test_expired_credential_fails():
    pk, sk = _gen_keypair()
    pk_b64 = base64.b64encode(pk).decode()
    payload = {
        "atb_cert_version": "1",
        "bench_issuer": ISSUER_DID,
        "expires_at": PAST,
        "passed": True,
        "score": 0.9,
    }
    header = _build_credential(payload, pk, sk)
    v = _make_verifier(pk_b64)
    result = v.verify(header)
    assert not result.valid
    assert result.failure_reason == "expired"


def test_tampered_payload_fails():
    pk, sk = _gen_keypair()
    pk_b64 = base64.b64encode(pk).decode()
    payload = {
        "bench_issuer": ISSUER_DID,
        "expires_at": FUTURE,
        "passed": False,   # Will be tampered to True
        "score": 0.3,
    }
    header = _build_credential(payload, pk, sk)
    # Tamper: decode, flip passed=True, re-encode without re-signing
    envelope = json.loads(base64.urlsafe_b64decode(header + "==="))
    envelope["payload"]["passed"] = True
    tampered = base64.urlsafe_b64encode(
        json.dumps(envelope, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    v = _make_verifier(pk_b64)
    result = v.verify(tampered)
    assert not result.valid
    assert result.failure_reason == "sig_invalid"


def test_wrong_issuer_fails():
    pk, sk = _gen_keypair()
    pk_b64 = base64.b64encode(pk).decode()
    payload = {
        "bench_issuer": "did:web:evil-bench.example.com",  # wrong issuer
        "expires_at": FUTURE,
        "passed": True,
        "score": 0.9,
    }
    header = _build_credential(payload, pk, sk)
    # Verifier is configured with ISSUER_DID only — evil-bench has no key
    # so the verifier returns no_public_key (key not found for that issuer)
    v = _make_verifier(pk_b64)
    result = v.verify(header)
    assert not result.valid
    # Either no_public_key (issuer unknown) or untrusted_issuer
    assert result.failure_reason in ("no_public_key", "untrusted_issuer", "kid_mismatch")


def test_caching_returns_same_result():
    pk, sk = _gen_keypair()
    pk_b64 = base64.b64encode(pk).decode()
    payload = {
        "bench_issuer": ISSUER_DID,
        "expires_at": FUTURE,
        "passed": True,
        "score": 0.8,
    }
    header = _build_credential(payload, pk, sk)
    v = _make_verifier(pk_b64)
    r1 = v.verify(header)
    r2 = v.verify(header)
    assert r1 is r2  # same object from cache


def test_phase2_non_phase2_cert_rejected():
    pk, sk = _gen_keypair()
    pk_b64 = base64.b64encode(pk).decode()
    payload = {
        "atb_cert_version": "1",  # Phase 1, not Phase 2
        "bench_issuer": ISSUER_DID,
        "expires_at": FUTURE,
        "passed": True,
        "score": 0.9,
    }
    header = _build_credential(payload, pk, sk)
    v = _make_verifier(pk_b64)

    import asyncio
    result = asyncio.get_event_loop().run_until_complete(
        v.verify_zkp_async(header, zkp_service_url="http://localhost:8091")
    )
    assert not result.valid
    assert result.failure_reason == "not_phase2_cert"


# ── Phase 2 OFFLINE verification (algovoi_bpverify; no ZKP service) ────────────

def _build_zk_credential(pk, sk, *, threshold=700, score=820, proof_override=None,
                         version="2", expires=FUTURE):
    bp = pytest.importorskip("algovoi_bpverify")
    commit, proof, _ = bp.prove_range_proof(score, threshold)
    payload = {
        "atb_cert_version": version,
        "bench_issuer": ISSUER_DID,
        "commitment_b64": base64.b64encode(commit).decode(),
        "proof_b64": proof_override if proof_override is not None else base64.b64encode(proof).decode(),
        "threshold_milliunits": threshold,
        "expires_at": expires,
        "passed": True,
    }
    return _build_credential(payload, pk, sk)


class TestOfflineZkp:
    def test_verify_zkp_sync_offline_valid(self):
        pytest.importorskip("pqcrypto")
        pytest.importorskip("algovoi_bpverify")
        pk, sk = _gen_keypair()
        header = _build_zk_credential(pk, sk)
        v = _make_verifier(base64.b64encode(pk).decode())
        r = v.verify_zkp(header)
        assert r.valid, r.failure_reason
        assert r.passed and r.score is None and r.has_zkp

    def test_verify_zkp_sync_random_proof_rejected(self):
        # The pre-existing structural-only era accepted random proof bytes here.
        pytest.importorskip("pqcrypto")
        pytest.importorskip("algovoi_bpverify")
        import os
        pk, sk = _gen_keypair()
        header = _build_zk_credential(pk, sk, proof_override=base64.b64encode(os.urandom(672)).decode())
        v = _make_verifier(base64.b64encode(pk).decode())
        r = v.verify_zkp(header)
        assert not r.valid
        assert (r.failure_reason or "").startswith("zkp_invalid")

    def test_verify_zkp_async_uses_offline_no_network(self):
        # With bpverify installed, the async path verifies offline — an unreachable
        # service URL must NOT matter (proves no network call is made).
        pytest.importorskip("pqcrypto")
        pytest.importorskip("algovoi_bpverify")
        import asyncio
        pk, sk = _gen_keypair()
        header = _build_zk_credential(pk, sk)
        v = _make_verifier(base64.b64encode(pk).decode())
        r = asyncio.run(v.verify_zkp_async(header, zkp_service_url="http://127.0.0.1:9/unreachable"))
        assert r.valid, r.failure_reason
        assert r.has_zkp
