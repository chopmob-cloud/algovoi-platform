"""Tests for FederationValidator."""
import base64
import hashlib
import json
import os
import pytest
from datetime import datetime, timezone, timedelta

from algovoi_federation_validator._crypto import (
    _b64url_encode,
    _FALCON1024_PK_LEN,
    _COMMITMENT_BYTES,
    verify_federation_token,
)
from algovoi_federation_validator.validator import FederationValidator


# ── Fixture helpers ──────────────────────────────────────────────────────────

def _fake_credential(
    issuer_did: str,
    pk: bytes,
    *,
    expired: bool = False,
    wrong_version: bool = False,
    bad_commitment: bool = False,
) -> str:
    """Craft a structurally valid (but cryptographically fake) Phase 2 ATB cert."""
    kid = hashlib.sha256(pk).hexdigest()[:16]

    if expired:
        exp = "2020-01-01T00:00:00Z"
    else:
        exp = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    commitment = base64.b64encode(os.urandom(1 if bad_commitment else _COMMITMENT_BYTES)).decode()
    proof = base64.b64encode(os.urandom(672)).decode()

    payload = {
        "atb_cert_version": "1" if wrong_version else "2",
        "bench_issuer": issuer_did,
        "commitment_b64": commitment,
        "proof_b64": proof,
        "threshold_milliunits": 700,
        "expires_at": exp,
        "passed": True,
    }

    fake_sig = _b64url_encode(os.urandom(1280))
    envelope = {
        "alg": "Falcon-1024",
        "kid": kid,
        "payload": payload,
        "sig": fake_sig,
    }
    return _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())


def _make_validator(
    n_issuers: int = 2,
    min_credentials: int = 2,
) -> tuple[FederationValidator, dict[str, bytes]]:
    """Build a validator with N issuers, returning (validator, {did: pk_bytes})."""
    pks: dict[str, bytes] = {}
    issuer_pks: dict[str, str] = {}

    for i in range(n_issuers):
        did = f"did:algovoi:bench:issuer{i}"
        pk = os.urandom(_FALCON1024_PK_LEN)
        pks[did] = pk
        issuer_pks[did] = base64.b64encode(pk).decode()

    secret = os.urandom(32)
    validator = FederationValidator(
        validator_secret=secret,
        issuer_pks=issuer_pks,
        min_credentials=min_credentials,
    )
    return validator, pks


# ── Validator construction ────────────────────────────────────────────────────

class TestFederationValidatorInit:
    def test_secret_too_short(self):
        with pytest.raises(ValueError, match="at least 32 bytes"):
            FederationValidator(
                validator_secret=b"short",
                issuer_pks={},
            )

    def test_min_credentials_zero(self):
        with pytest.raises(ValueError, match="min_credentials must be >= 1"):
            FederationValidator(
                validator_secret=os.urandom(32),
                issuer_pks={},
                min_credentials=0,
            )

    def test_valid_construction(self):
        v = FederationValidator(
            validator_secret=os.urandom(32),
            issuer_pks={"did:test": "pk"},
        )
        assert v is not None


# ── Composition failure paths ─────────────────────────────────────────────────

class TestComposeFailures:
    def test_insufficient_credentials(self):
        validator, pks = _make_validator(n_issuers=2, min_credentials=2)
        did = list(pks.keys())[0]
        cred = _fake_credential(did, pks[did])
        result = validator.compose([cred])  # only 1, need 2
        assert not result.valid
        assert "insufficient_credentials" in (result.failure_reason or "")

    def test_replayed_credential_does_not_satisfy_min(self):
        """The same credential presented twice must NOT satisfy min_credentials=2 (security fix
        2026-08-19): it is one attestation, not two independent ones."""
        validator, pks = _make_validator(n_issuers=2, min_credentials=2)
        did = list(pks.keys())[0]
        cred = _fake_credential(did, pks[did])
        result = validator.compose([cred, cred])  # replay to try to reach the min
        assert not result.valid
        assert result.failure_reason == "duplicate_credential"

    def test_distinct_creds_same_issuer_not_flagged_as_duplicate(self):
        """Two genuinely distinct certs from the same issuer differ in their commitment, so they are NOT
        rejected as duplicates (they fail later on the fake signature, not on dedup)."""
        validator, pks = _make_validator(n_issuers=1, min_credentials=2)
        did = list(pks.keys())[0]
        cred_a = _fake_credential(did, pks[did])
        cred_b = _fake_credential(did, pks[did])  # fresh random commitment each call
        result = validator.compose([cred_a, cred_b])
        assert (result.failure_reason or "") != "duplicate_credential"

    def test_unknown_issuer(self):
        validator, pks = _make_validator()
        dids = list(pks.keys())
        cred_a = _fake_credential(dids[0], pks[dids[0]])
        # Use a DID not in the validator's registry
        unknown_pk = os.urandom(_FALCON1024_PK_LEN)
        cred_b = _fake_credential("did:unknown:issuer", unknown_pk)
        result = validator.compose([cred_a, cred_b])
        assert not result.valid
        assert "unknown_issuer" in (result.failure_reason or "")

    def test_expired_credential(self):
        validator, pks = _make_validator()
        dids = list(pks.keys())
        cred_a = _fake_credential(dids[0], pks[dids[0]])
        cred_b = _fake_credential(dids[1], pks[dids[1]], expired=True)
        result = validator.compose([cred_a, cred_b])
        assert not result.valid
        assert "expired" in (result.failure_reason or "")

    def test_wrong_cert_version(self):
        validator, pks = _make_validator()
        dids = list(pks.keys())
        cred_a = _fake_credential(dids[0], pks[dids[0]])
        cred_b = _fake_credential(dids[1], pks[dids[1]], wrong_version=True)
        result = validator.compose([cred_a, cred_b])
        assert not result.valid
        assert "not_phase2_cert" in (result.failure_reason or "")

    def test_bad_commitment_bytes(self):
        validator, pks = _make_validator()
        dids = list(pks.keys())
        cred_a = _fake_credential(dids[0], pks[dids[0]])
        cred_b = _fake_credential(dids[1], pks[dids[1]], bad_commitment=True)
        result = validator.compose([cred_a, cred_b])
        assert not result.valid
        assert "commitment_len" in (result.failure_reason or "")

    def test_garbled_envelope(self):
        validator, pks = _make_validator()
        dids = list(pks.keys())
        cred_a = _fake_credential(dids[0], pks[dids[0]])
        result = validator.compose([cred_a, "!!!not-base64!!!"])
        assert not result.valid

    def test_credential_results_populated_on_failure(self):
        validator, pks = _make_validator()
        dids = list(pks.keys())
        cred_a = _fake_credential(dids[0], pks[dids[0]])
        cred_b = _fake_credential(dids[1], pks[dids[1]], expired=True)
        result = validator.compose([cred_a, cred_b])
        assert not result.valid
        assert len(result.credential_results) == 2


# ── Composition success (falcon_unavailable or sig_invalid only) ──────────────

class TestComposeSuccessStructural:
    """With fake Falcon signatures, composition either:
      - Returns valid=False with reason 'falcon_unavailable' or 'sig_invalid'
        (depending on whether pqcrypto is installed), OR
      - Returns valid=True with a federation token (if signature check is
        bypassed in a test environment — not expected in normal runs).

    These tests confirm the composition pipeline runs to completion
    without crashing, and that the FederationResult shape is correct.
    """

    def test_compose_two_credentials_structural(self):
        validator, pks = _make_validator()
        dids = list(pks.keys())
        cred_a = _fake_credential(dids[0], pks[dids[0]])
        cred_b = _fake_credential(dids[1], pks[dids[1]])
        result = validator.compose([cred_a, cred_b])
        # Valid only if no [verify] extras installed and we skip sig check.
        # In either case, the result should be a proper FederationResult.
        assert isinstance(result.valid, bool)
        assert result.failure_reason is None or isinstance(result.failure_reason, str)

    def test_min_credentials_one_single_issuer(self):
        validator, pks = _make_validator(n_issuers=1, min_credentials=1)
        did = list(pks.keys())[0]
        cred = _fake_credential(did, pks[did])
        result = validator.compose([cred])
        assert isinstance(result.valid, bool)

    def test_three_credentials(self):
        validator, pks = _make_validator(n_issuers=3, min_credentials=2)
        dids = list(pks.keys())
        creds = [_fake_credential(dids[i], pks[dids[i]]) for i in range(3)]
        result = validator.compose(creds)
        assert isinstance(result.valid, bool)

    def test_duplicate_issuer_allowed(self):
        """Two creds from the same issuer are structurally valid."""
        validator, pks = _make_validator(n_issuers=1, min_credentials=2)
        did = list(pks.keys())[0]
        cred_a = _fake_credential(did, pks[did])
        cred_b = _fake_credential(did, pks[did])
        result = validator.compose([cred_a, cred_b])
        assert isinstance(result.valid, bool)


# ── Token verification ────────────────────────────────────────────────────────

class TestTokenVerification:
    def test_verify_wrong_secret(self):
        validator, pks = _make_validator(n_issuers=1, min_credentials=1)
        did = list(pks.keys())[0]
        cred = _fake_credential(did, pks[did])
        result = validator.compose([cred])
        if not result.valid or result.token is None:
            pytest.skip("composition did not succeed (Falcon sig required)")
        assert verify_federation_token(result.token.raw, os.urandom(32)) is None

    def test_verify_correct_secret(self):
        validator, pks = _make_validator(n_issuers=1, min_credentials=1)
        did = list(pks.keys())[0]
        cred = _fake_credential(did, pks[did])
        result = validator.compose([cred])
        if not result.valid or result.token is None:
            pytest.skip("composition did not succeed (Falcon sig required)")
        # Extract the validator secret from the validator's private attribute for testing.
        payload = verify_federation_token(result.token.raw, validator._secret)
        assert payload is not None
        assert payload["threshold_met"] is True


# ── Extract issuer DID ────────────────────────────────────────────────────────

class TestExtractIssuerDid:
    def test_valid_envelope(self):
        pk = os.urandom(_FALCON1024_PK_LEN)
        cred = _fake_credential("did:test:bench", pk)
        did = FederationValidator._extract_issuer_did(cred)
        assert did == "did:test:bench"

    def test_garbled_envelope(self):
        did = FederationValidator._extract_issuer_did("not-base64!")
        assert did is None

    def test_missing_issuer_in_payload(self):
        envelope = {
            "alg": "Falcon-1024",
            "kid": "abc",
            "payload": {"no_bench_issuer": True},
            "sig": "fake",
        }
        b = _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())
        did = FederationValidator._extract_issuer_did(b)
        assert did is None


# ── End-to-end: real Falcon signatures + real Bulletproofs proofs ──────────────
# Requires the [verify] extra (pqcrypto, rfc8785, algovoi-bpverify).

def _real_validator(n: int = 2, min_credentials: int = 2):
    from pqcrypto.sign.falcon_1024 import generate_keypair
    keys: dict = {}
    issuer_pks: dict[str, str] = {}
    for i in range(n):
        did = f"did:algovoi:bench:real{i}"
        pk, sk = generate_keypair()
        keys[did] = (pk, sk)
        issuer_pks[did] = base64.b64encode(pk).decode()
    v = FederationValidator(
        validator_secret=os.urandom(32), issuer_pks=issuer_pks, min_credentials=min_credentials
    )
    return v, keys


def _real_credential(issuer_did, pk, sk, *, score=820, threshold=700, proof_override=None):
    import rfc8785
    import algovoi_bpverify as bp
    from pqcrypto.sign.falcon_1024 import sign as _sign
    commit, proof, _ = bp.prove_range_proof(score, threshold)
    proof_b64 = proof_override if proof_override is not None else base64.b64encode(proof).decode()
    exp = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "atb_cert_version": "2",
        "bench_issuer": issuer_did,
        "commitment_b64": base64.b64encode(commit).decode(),
        "proof_b64": proof_b64,
        "threshold_milliunits": threshold,
        "expires_at": exp,
        "passed": True,
    }
    sig = _sign(sk, rfc8785.dumps(payload))
    kid = hashlib.sha256(pk).hexdigest()[:16]
    envelope = {"alg": "Falcon-1024", "kid": kid, "payload": payload, "sig": _b64url_encode(sig)}
    return _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())


class TestComposeEndToEnd:
    def _require(self):
        pytest.importorskip("rfc8785")
        pytest.importorskip("pqcrypto")
        pytest.importorskip("algovoi_bpverify")

    def test_compose_real_credentials_valid(self):
        self._require()
        v, keys = _real_validator(2)
        creds = [_real_credential(did, pk, sk) for did, (pk, sk) in keys.items()]
        result = v.compose(creds)
        assert result.valid, result.failure_reason
        assert result.token is not None
        assert verify_federation_token(result.token.raw, v._secret) is not None

    def test_compose_rejects_fake_proof(self):
        # Structural-only composition ACCEPTED random proof bytes; it must now be
        # rejected — this is the federation-side regression guard for the ZK hole.
        self._require()
        v, keys = _real_validator(2)
        items = list(keys.items())
        good = _real_credential(items[0][0], *items[0][1])
        bad = _real_credential(
            items[1][0], *items[1][1],
            proof_override=base64.b64encode(os.urandom(672)).decode(),
        )
        result = v.compose([good, bad])
        assert not result.valid
        assert "proof_invalid" in (result.failure_reason or "")

    def test_compose_rejects_wrong_threshold(self):
        # A genuine proof presented at a raised threshold must fail verification.
        self._require()
        import rfc8785
        import algovoi_bpverify as bp
        from pqcrypto.sign.falcon_1024 import sign as _sign
        v, keys = _real_validator(2)
        items = list(keys.items())
        good = _real_credential(items[0][0], *items[0][1])
        # Build a credential whose proof is for threshold 700 but claims 701.
        did, (pk, sk) = items[1]
        commit, proof, _ = bp.prove_range_proof(820, 700)
        exp = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {
            "atb_cert_version": "2", "bench_issuer": did,
            "commitment_b64": base64.b64encode(commit).decode(),
            "proof_b64": base64.b64encode(proof).decode(),
            "threshold_milliunits": 701, "expires_at": exp, "passed": True,
        }
        sig = _sign(sk, rfc8785.dumps(payload))
        kid = hashlib.sha256(pk).hexdigest()[:16]
        envelope = {"alg": "Falcon-1024", "kid": kid, "payload": payload, "sig": _b64url_encode(sig)}
        bad = _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())
        result = v.compose([good, bad])
        assert not result.valid
        assert "proof_invalid" in (result.failure_reason or "")
