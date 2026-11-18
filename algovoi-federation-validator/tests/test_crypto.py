"""Tests for algovoi_federation_validator._crypto."""
import base64
import hashlib
import hmac
import json
import os
import pytest
from datetime import datetime, timezone, timedelta

from algovoi_federation_validator._crypto import (
    _b64url_decode,
    _b64url_encode,
    _FED_TOKEN_LABEL,
    _jcs_canonical,
    _COMMITMENT_BYTES,
    _PROOF_MIN_BYTES,
    _PROOF_MAX_BYTES,
    _FALCON1024_PK_LEN,
    compose_commitments,
    issue_federation_token,
    verify_federation_token,
    verify_pqc_credential,
)
from algovoi_federation_validator.models import IssuerEntry


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_envelope(
    *,
    alg: str = "Falcon-1024",
    kid: str | None = None,
    payload_overrides: dict | None = None,
    pk_bytes: bytes | None = None,
    sig_override: str | None = None,
) -> tuple[str, bytes]:
    """Build a fake envelope without a real Falcon signature for structural tests."""
    pk = pk_bytes or os.urandom(_FALCON1024_PK_LEN)
    computed_kid = hashlib.sha256(pk).hexdigest()[:16]

    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    commitment = base64.b64encode(os.urandom(_COMMITMENT_BYTES)).decode()
    proof = base64.b64encode(os.urandom(672)).decode()

    payload: dict = {
        "atb_cert_version": "2",
        "bench_issuer": "did:algovoi:bench:prod",
        "commitment_b64": commitment,
        "proof_b64": proof,
        "threshold_milliunits": 700,
        "expires_at": exp,
        "passed": True,
        "methodology_version": "v1",
    }
    if payload_overrides:
        payload.update(payload_overrides)

    # Fake sig — just random bytes; real Falcon tests need [verify] extras
    sig = _b64url_encode(os.urandom(1280))

    envelope = {
        "alg": alg,
        "kid": kid or computed_kid,
        "payload": payload,
        "sig": sig_override or sig,
    }
    raw = _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())
    return raw, pk


class TestB64Helpers:
    def test_roundtrip_with_padding(self):
        for n in range(0, 40):
            b = os.urandom(n)
            encoded = _b64url_encode(b)
            assert _b64url_decode(encoded) == b

    def test_decode_padded_input(self):
        b = b"hello"
        padded = base64.urlsafe_b64encode(b).decode("ascii")
        assert _b64url_decode(padded) == b

    def test_decode_unpadded_input(self):
        b = b"hello"
        unpadded = base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
        assert _b64url_decode(unpadded) == b


class TestJcsFallback:
    def test_dict_sorted(self):
        val = {"b": 2, "a": 1}
        out = _jcs_canonical(val)
        assert out == b'{"a":1,"b":2}'

    def test_nested(self):
        val = {"z": {"y": 3, "x": 4}, "a": [1, 2]}
        out = _jcs_canonical(val)
        assert b'"a":[1,2]' in out
        assert b'"z":{"x":4,"y":3}' in out

    def test_string_escaping(self):
        val = {"msg": 'say "hi"'}
        out = _jcs_canonical(val)
        assert b'\\"hi\\"' in out


class TestComposeCommitments:
    def test_length(self):
        comms = [os.urandom(32) for _ in range(3)]
        nonce = os.urandom(32)
        result = compose_commitments(comms, nonce)
        assert len(result) == 32

    def test_deterministic(self):
        comms = [os.urandom(32) for _ in range(2)]
        nonce = os.urandom(32)
        assert compose_commitments(comms, nonce) == compose_commitments(comms, nonce)

    def test_different_nonce_produces_different_result(self):
        comms = [os.urandom(32) for _ in range(2)]
        r1 = compose_commitments(comms, os.urandom(32))
        r2 = compose_commitments(comms, os.urandom(32))
        assert r1 != r2

    def test_order_matters(self):
        c1, c2 = os.urandom(32), os.urandom(32)
        nonce = os.urandom(32)
        r1 = compose_commitments([c1, c2], nonce)
        r2 = compose_commitments([c2, c1], nonce)
        assert r1 != r2

    def test_single_commitment(self):
        comm = os.urandom(32)
        nonce = os.urandom(32)
        result = compose_commitments([comm], nonce)
        assert len(result) == 32

    def test_domain_separation(self):
        # Two identical inputs but different labels should differ from raw SHA-256.
        comms = [os.urandom(32)]
        nonce = os.urandom(32)
        h = hashlib.sha256()
        h.update(comms[0])
        h.update(nonce)
        raw_sha = h.digest()
        fed = compose_commitments(comms, nonce)
        assert fed != raw_sha


class TestIssueFederationToken:
    def _make_token(self, n_issuers: int = 2) -> tuple:
        secret = os.urandom(32)
        issuers = [
            IssuerEntry(did=f"did:algovoi:bench:{i}", kid=f"kid{i}", alg="Falcon-1024")
            for i in range(n_issuers)
        ]
        comms = [os.urandom(32) for _ in range(n_issuers)]
        nonce = os.urandom(32)
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        token = issue_federation_token(
            issuers=issuers,
            commitment_bytes_list=comms,
            nonce=nonce,
            expires_at=exp,
            validator_secret=secret,
        )
        return token, secret, comms, nonce, exp

    def test_raw_is_valid_base64url(self):
        token, _, _, _, _ = self._make_token()
        decoded = _b64url_decode(token.raw)
        assert len(decoded) > 0
        envelope = json.loads(decoded)
        assert envelope["alg"] == "HMAC-SHA256"
        assert envelope["type"] == "federation_token"

    def test_commitment_matches_compose(self):
        secret = os.urandom(32)
        comms = [os.urandom(32), os.urandom(32)]
        nonce = os.urandom(32)
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        token = issue_federation_token(
            issuers=[
                IssuerEntry("did:a", "k1", "Falcon-1024"),
                IssuerEntry("did:b", "k2", "Falcon-1024"),
            ],
            commitment_bytes_list=comms,
            nonce=nonce,
            expires_at=exp,
            validator_secret=secret,
        )
        expected_hex = compose_commitments(comms, nonce).hex()
        assert token.fed_commitment_hex == expected_hex

    def test_nonce_hex_in_payload(self):
        token, secret, comms, nonce, _ = self._make_token()
        payload = verify_federation_token(token.raw, secret)
        assert payload is not None
        assert payload["fed_nonce"] == nonce.hex()

    def test_issuers_in_payload(self):
        token, secret, _, _, _ = self._make_token(n_issuers=3)
        payload = verify_federation_token(token.raw, secret)
        assert payload is not None
        assert len(payload["issuers"]) == 3

    def test_threshold_met_true(self):
        token, secret, _, _, _ = self._make_token()
        payload = verify_federation_token(token.raw, secret)
        assert payload is not None
        assert payload["threshold_met"] is True

    def test_kid_from_validator_secret(self):
        secret = os.urandom(32)
        expected_kid = hashlib.sha256(secret).hexdigest()[:16]
        comms = [os.urandom(32)]
        nonce = os.urandom(32)
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        token = issue_federation_token(
            issuers=[IssuerEntry("did:a", "k1", "Falcon-1024")],
            commitment_bytes_list=comms,
            nonce=nonce,
            expires_at=exp,
            validator_secret=secret,
        )
        envelope = json.loads(_b64url_decode(token.raw))
        assert envelope["kid"] == expected_kid


class TestVerifyFederationToken:
    def _roundtrip(self) -> tuple:
        secret = os.urandom(32)
        comms = [os.urandom(32), os.urandom(32)]
        nonce = os.urandom(32)
        exp = datetime.now(timezone.utc) + timedelta(hours=2)
        token = issue_federation_token(
            issuers=[
                IssuerEntry("did:a", "k1", "Falcon-1024"),
                IssuerEntry("did:b", "k2", "Falcon-1024"),
            ],
            commitment_bytes_list=comms,
            nonce=nonce,
            expires_at=exp,
            validator_secret=secret,
        )
        return token, secret

    def test_valid_roundtrip(self):
        token, secret = self._roundtrip()
        payload = verify_federation_token(token.raw, secret)
        assert payload is not None
        assert payload["version"] == "1"
        assert payload["threshold_met"] is True

    def test_wrong_secret_rejected(self):
        token, _ = self._roundtrip()
        assert verify_federation_token(token.raw, os.urandom(32)) is None

    def test_tampered_payload_rejected(self):
        token, secret = self._roundtrip()
        envelope = json.loads(_b64url_decode(token.raw))
        envelope["payload"]["threshold_met"] = False
        tampered = _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())
        assert verify_federation_token(tampered, secret) is None

    def test_expired_token_rejected(self):
        secret = os.urandom(32)
        exp = datetime(2020, 1, 1, tzinfo=timezone.utc)  # in the past
        token = issue_federation_token(
            issuers=[IssuerEntry("did:a", "k1", "Falcon-1024")],
            commitment_bytes_list=[os.urandom(32)],
            nonce=os.urandom(32),
            expires_at=exp,
            validator_secret=secret,
        )
        assert verify_federation_token(token.raw, secret) is None

    def test_garbage_input(self):
        assert verify_federation_token("not-a-token", os.urandom(32)) is None


class TestVerifyPqcCredentialStructural:
    """Structural verification tests (no Falcon crypto — just shape and field checks)."""

    def test_invalid_base64url(self):
        result = verify_pqc_credential("!!!not-base64!!!", "pk")
        assert not result.valid
        assert "envelope_decode" in (result.failure_reason or "")

    def test_wrong_alg(self):
        raw, pk = _make_envelope(alg="Ed25519")
        result = verify_pqc_credential(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "envelope_shape" in (result.failure_reason or "")

    def test_not_phase2_cert(self):
        raw, pk = _make_envelope(payload_overrides={"atb_cert_version": "1"})
        result = verify_pqc_credential(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "not_phase2_cert" in (result.failure_reason or "")

    def test_expired_cert(self):
        raw, pk = _make_envelope(payload_overrides={
            "expires_at": "2020-01-01T00:00:00Z",
        })
        result = verify_pqc_credential(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "expired" in (result.failure_reason or "")

    def test_missing_commitment(self):
        raw, pk = _make_envelope(payload_overrides={"commitment_b64": ""})
        result = verify_pqc_credential(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "missing_zkp_fields" in (result.failure_reason or "")

    def test_wrong_commitment_length(self):
        bad_comm = base64.b64encode(os.urandom(16)).decode()  # 16 bytes, not 32
        raw, pk = _make_envelope(payload_overrides={"commitment_b64": bad_comm})
        result = verify_pqc_credential(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "commitment_len" in (result.failure_reason or "")

    def test_wrong_proof_length_too_small(self):
        tiny_proof = base64.b64encode(os.urandom(10)).decode()
        raw, pk = _make_envelope(payload_overrides={"proof_b64": tiny_proof})
        result = verify_pqc_credential(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "proof_len" in (result.failure_reason or "")

    def test_wrong_pk_length(self):
        raw, pk = _make_envelope()
        short_pk = base64.b64encode(os.urandom(100)).decode()  # not 1793 bytes
        result = verify_pqc_credential(raw, short_pk)
        assert not result.valid
        assert "pk_wrong_len" in (result.failure_reason or "")

    def test_kid_mismatch(self):
        raw, pk = _make_envelope()
        # Supply a different PK of the right length — kid won't match
        different_pk = base64.b64encode(os.urandom(_FALCON1024_PK_LEN)).decode()
        result = verify_pqc_credential(raw, different_pk)
        assert not result.valid
        assert "kid_mismatch" in (result.failure_reason or "")

    def test_threshold_out_of_range(self):
        raw, pk = _make_envelope(payload_overrides={"threshold_milliunits": 9999})
        result = verify_pqc_credential(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "threshold_out_of_range" in (result.failure_reason or "")

    def test_kid_matches_correct_pk(self):
        raw, pk = _make_envelope()
        pk_b64 = base64.b64encode(pk).decode()
        result = verify_pqc_credential(raw, pk_b64)
        # With no [verify] extras installed, we get falcon_unavailable — not a kid error.
        # The kid check passed; only signature is unverified.
        assert result.failure_reason in (
            "falcon_unavailable — install algovoi-federation-validator[verify]",
            "sig_invalid",  # if extras are installed but sig is fake
            None,           # valid (if extras + lucky fake sig)
        )
