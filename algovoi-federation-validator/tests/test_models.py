"""Tests for algovoi_federation_validator.models."""
import pytest
from datetime import datetime, timezone

from algovoi_federation_validator.models import (
    CredentialVerifyResult,
    FederationResult,
    FederationToken,
    IssuerEntry,
    PqcCredentialFields,
)


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class TestCredentialVerifyResult:
    def test_valid_true(self):
        r = CredentialVerifyResult(valid=True, issuer_did="did:algovoi:bench:prod", kid="abc123")
        assert r.valid is True
        assert r.failure_reason is None

    def test_valid_false_with_reason(self):
        r = CredentialVerifyResult(valid=False, failure_reason="sig_invalid")
        assert r.valid is False
        assert r.failure_reason == "sig_invalid"

    def test_defaults(self):
        r = CredentialVerifyResult(valid=False)
        assert r.issuer_did is None
        assert r.kid is None
        assert r.commitment_b64 is None
        assert r.proof_b64 is None
        assert r.threshold_milliunits is None
        assert r.expires_at is None


class TestIssuerEntry:
    def test_fields(self):
        e = IssuerEntry(did="did:algovoi:bench:prod", kid="abc123", alg="Falcon-1024")
        assert e.did == "did:algovoi:bench:prod"
        assert e.kid == "abc123"
        assert e.alg == "Falcon-1024"


class TestFederationToken:
    def test_fields(self):
        now = datetime.now(timezone.utc)
        exp = now.replace(hour=23, minute=59)
        token = FederationToken(
            raw="abc123",
            fed_commitment_hex="deadbeef" * 8,
            fed_nonce_hex="cafebabe" * 8,
            issuers=[IssuerEntry("did:a", "kid1", "Falcon-1024")],
            expires_at=exp,
            issued_at=now,
        )
        assert token.raw == "abc123"
        assert len(token.fed_commitment_hex) == 64
        assert len(token.issuers) == 1


class TestFederationResult:
    def test_valid_result(self):
        now = datetime.now(timezone.utc)
        token = FederationToken(
            raw="tok",
            fed_commitment_hex="a" * 64,
            fed_nonce_hex="b" * 64,
            issuers=[],
            expires_at=now,
            issued_at=now,
        )
        r = FederationResult(valid=True, token=token)
        assert r.valid is True
        assert r.token is token
        assert r.failure_reason is None

    def test_invalid_result(self):
        r = FederationResult(valid=False, failure_reason="envelope_shape")
        assert r.valid is False
        assert r.token is None
        assert r.credential_results == []


class TestPqcCredentialFields:
    def test_construction(self):
        now = datetime.now(timezone.utc)
        f = PqcCredentialFields(
            raw_b64url="abc",
            alg="Falcon-1024",
            kid="kid1",
            issuer_did="did:algovoi:bench:prod",
            commitment_b64="comm",
            proof_b64="proof",
            threshold_milliunits=700,
            expires_at=now,
        )
        assert f.cert_version == "2"
        assert f.issued_at is None
        assert f.methodology_version is None
