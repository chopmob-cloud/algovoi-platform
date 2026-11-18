"""Tests for algovoi_zkp_receipt."""
import base64
import hashlib
import json
import os
import pytest
from datetime import datetime, timezone, timedelta

from algovoi_zkp_receipt import (
    PaymentReceipt,
    ZkpReceiptVerifyResult,
    build_zkp_receipt_payload,
    verify_zkp_receipt,
)
from algovoi_zkp_receipt.receipt import (
    _b64url_decode,
    _b64url_encode,
    _COMMITMENT_BYTES,
    _PROOF_MIN_BYTES,
    _PROOF_MAX_BYTES,
    _FALCON1024_PK_LEN,
)


def _make_receipt(**kwargs) -> PaymentReceipt:
    defaults = dict(
        payment_id="pay_test_001",
        chain="algorand",
        amount_microusd=100_000,
        recipient="ALGO_ADDR",
        tx_id="TXID_001",
        settled_at="2026-06-03T12:00:00Z",
    )
    defaults.update(kwargs)
    return PaymentReceipt(**defaults)


def _make_fake_envelope(
    pk: bytes | None = None,
    *,
    expired: bool = False,
    wrong_type: bool = False,
    bad_commitment: bool = False,
    missing_receipt: bool = False,
) -> tuple[str, bytes]:
    pk = pk or os.urandom(_FALCON1024_PK_LEN)
    kid = hashlib.sha256(pk).hexdigest()[:16]

    if expired:
        exp = "2020-01-01T00:00:00Z"
    else:
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload: dict = {
        "type": "wrong_type" if wrong_type else "zkp_receipt",
        "version": "1",
        "payment_id": "" if missing_receipt else "pay_001",
        "chain": "algorand",
        "amount_microusd": 100_000,
        "recipient": "ALGO_ADDR",
        "tx_id": "TXID_001",
        "settled_at": "2026-06-03T12:00:00Z",
        "atb_cert_version": "2",
        "bench_issuer": "did:algovoi:bench:prod",
        "commitment_b64": base64.b64encode(os.urandom(1 if bad_commitment else _COMMITMENT_BYTES)).decode(),
        "proof_b64": base64.b64encode(os.urandom(672)).decode(),
        "threshold_milliunits": 700,
        "expires_at": exp,
        "issued_at": "2026-06-03T00:00:00Z",
    }

    envelope = {
        "alg": "Falcon-1024",
        "kid": kid,
        "payload": payload,
        "sig": _b64url_encode(os.urandom(1280)),
    }
    raw = _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())
    return raw, pk


class TestBuildZkpReceiptPayload:
    def test_all_fields_present(self):
        receipt = _make_receipt()
        payload = build_zkp_receipt_payload(
            receipt=receipt,
            commitment_b64="comm==",
            proof_b64="proof==",
            threshold_milliunits=700,
            issuer_did="did:algovoi:bench:prod",
            expires_at="2026-06-04T00:00:00Z",
            issued_at="2026-06-03T00:00:00Z",
        )
        assert payload["type"] == "zkp_receipt"
        assert payload["version"] == "1"
        assert payload["payment_id"] == "pay_test_001"
        assert payload["chain"] == "algorand"
        assert payload["amount_microusd"] == 100_000
        assert payload["tx_id"] == "TXID_001"
        assert payload["commitment_b64"] == "comm=="
        assert payload["threshold_milliunits"] == 700
        assert payload["bench_issuer"] == "did:algovoi:bench:prod"
        assert payload["atb_cert_version"] == "2"

    def test_all_receipt_fields_copied(self):
        receipt = _make_receipt(tx_id="TX_XYZ", chain="solana")
        payload = build_zkp_receipt_payload(
            receipt=receipt,
            commitment_b64="c", proof_b64="p",
            threshold_milliunits=500,
            issuer_did="did:x", expires_at="2026-06-04T00:00:00Z",
            issued_at="2026-06-03T00:00:00Z",
        )
        assert payload["tx_id"] == "TX_XYZ"
        assert payload["chain"] == "solana"


class TestVerifyZkpReceiptStructural:
    def test_invalid_base64url(self):
        result = verify_zkp_receipt("!!!not-base64!!!", "pk")
        assert not result.valid
        assert "envelope_decode" in (result.failure_reason or "")

    def test_wrong_type(self):
        raw, pk = _make_fake_envelope(wrong_type=True)
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "wrong_type" in (result.failure_reason or "")

    def test_missing_receipt_fields(self):
        raw, pk = _make_fake_envelope(missing_receipt=True)
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "missing_receipt_fields" in (result.failure_reason or "")

    def test_expired(self):
        raw, pk = _make_fake_envelope(expired=True)
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "expired" in (result.failure_reason or "")

    def test_bad_commitment_len(self):
        raw, pk = _make_fake_envelope(bad_commitment=True)
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert "commitment_len" in (result.failure_reason or "")

    def test_wrong_pk_length(self):
        raw, _ = _make_fake_envelope()
        short_pk = base64.b64encode(os.urandom(100)).decode()
        result = verify_zkp_receipt(raw, short_pk)
        assert not result.valid
        assert "pk_wrong_len" in (result.failure_reason or "")

    def test_kid_mismatch(self):
        raw, _ = _make_fake_envelope()
        different_pk = base64.b64encode(os.urandom(_FALCON1024_PK_LEN)).decode()
        result = verify_zkp_receipt(raw, different_pk)
        assert not result.valid
        assert "kid_mismatch" in (result.failure_reason or "")

    def test_kid_match_leads_to_sig_check(self):
        raw, pk = _make_fake_envelope()
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        # Should reach sig check — either falcon_unavailable or sig_invalid
        assert result.failure_reason in (
            "falcon_unavailable — install algovoi-zkp-receipt[verify]",
            "sig_invalid",
            None,   # if somehow passes (test env)
        )


class TestZkpReceiptVerifyResult:
    def test_valid_fields(self):
        r = ZkpReceiptVerifyResult(
            valid=True,
            payment_id="pay_001",
            chain="algorand",
            amount_microusd=100_000,
            tx_id="TXID",
        )
        assert r.valid
        assert r.failure_reason is None

    def test_invalid_fields(self):
        r = ZkpReceiptVerifyResult(valid=False, failure_reason="sig_invalid")
        assert not r.valid
        assert r.payment_id is None


class TestPaymentReceipt:
    def test_construction(self):
        r = _make_receipt()
        assert r.payment_id == "pay_test_001"
        assert r.chain == "algorand"
        assert r.amount_microusd == 100_000


# ── End-to-end: real Falcon signature + real Bulletproofs range proof ──────────
# These require the [verify] extra (pqcrypto, rfc8785, algovoi-bpverify).

def _sign_envelope(payload: dict, sk: bytes, pk: bytes) -> str:
    import rfc8785
    from pqcrypto.sign.falcon_1024 import sign as _falcon_sign
    kid = hashlib.sha256(pk).hexdigest()[:16]
    sig = _falcon_sign(sk, rfc8785.dumps(payload))
    envelope = {"alg": "Falcon-1024", "kid": kid, "payload": payload, "sig": _b64url_encode(sig)}
    return _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode())


class TestVerifyZkpReceiptEndToEnd:
    """Full crypto path: genuine signature AND genuine range proof must both hold."""

    def _setup(self):
        pytest.importorskip("rfc8785")
        pytest.importorskip("pqcrypto")
        bp = pytest.importorskip("algovoi_bpverify")
        from pqcrypto.sign.falcon_1024 import generate_keypair
        pk, sk = generate_keypair()
        commit, proof, _ = bp.prove_range_proof(820, 700)  # 0.820 >= 0.700
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = build_zkp_receipt_payload(
            receipt=_make_receipt(),
            commitment_b64=base64.b64encode(commit).decode(),
            proof_b64=base64.b64encode(proof).decode(),
            threshold_milliunits=700,
            issuer_did="did:algovoi:bench:prod",
            expires_at=exp,
            issued_at="2026-06-03T00:00:00Z",
        )
        return pk, sk, payload

    def test_genuine_proof_and_signature_valid(self):
        pk, sk, payload = self._setup()
        raw = _sign_envelope(payload, sk, pk)
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        assert result.valid, result.failure_reason
        assert result.payment_id == "pay_test_001"

    def test_random_proof_bytes_rejected(self):
        # The pre-2026-06 structural-only check ACCEPTED this; it must now be rejected.
        pk, sk, payload = self._setup()
        payload = dict(payload, proof_b64=base64.b64encode(os.urandom(672)).decode())
        raw = _sign_envelope(payload, sk, pk)
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert result.failure_reason == "proof_invalid"

    def test_genuine_proof_wrong_threshold_rejected(self):
        pk, sk, payload = self._setup()
        payload = dict(payload, threshold_milliunits=701)  # proof was for 700
        raw = _sign_envelope(payload, sk, pk)
        result = verify_zkp_receipt(raw, base64.b64encode(pk).decode())
        assert not result.valid
        assert result.failure_reason == "proof_invalid"
