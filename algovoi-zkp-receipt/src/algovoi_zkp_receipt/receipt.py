"""ZKP-bound receipt envelope construction and verification.

A ZKP receipt binds an ATB Phase 2 ZKP credential to a specific on-chain
payment receipt. The Falcon-1024 signature covers the combined payload —
proving "the agent that made THIS payment has ATB score >= threshold."

v0.1 uses the standard ATB transcript (threshold-bound). v0.2 will extend
with payment_id domain separation in the Bulletproofs transcript, requiring
an update to the ATB ZKP service.

IETF anchors:
  draft-hopley-x402-pqc-credential-binding-00
  draft-hopley-x402-federation-zkp-00
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from algovoi_zkp_receipt.models import (
    PaymentReceipt,
    ZkpReceiptEnvelope,
    ZkpReceiptVerifyResult,
)

try:
    import rfc8785 as _rfc8785
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# Offline Bulletproofs range-proof verifier (native extension; reuses the exact
# dalek crates/generators/transcript as the ATB ZKP prover). Required to fully
# verify a ZKP receipt — without it, proof verification fails closed.
try:
    import algovoi_bpverify as _bpverify

    _HAS_BPVERIFY = True
except ImportError:
    _bpverify = None
    _HAS_BPVERIFY = False

# Pedersen commitment: 32 bytes (compressed Ristretto255 point)
_COMMITMENT_BYTES = 32
# Bulletproofs 64-bit range proof: 200–900 bytes
_PROOF_MIN_BYTES = 200
_PROOF_MAX_BYTES = 900
# Falcon-1024 PQClean public key: 1793 bytes
_FALCON1024_PK_LEN = 1793


def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad and pad < 4:
        s = s + "=" * pad
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _jcs_canonical(value: Any) -> bytes:
    if _HAS_CRYPTO:
        return _rfc8785.dumps(value)  # type: ignore[no-any-return]
    return _py_jcs(value)


def _py_jcs(value: Any) -> bytes:
    if isinstance(value, dict):
        inner = ",".join(
            json.dumps(k, ensure_ascii=False, separators=(",", ":"))
            + ":" + _py_jcs(v).decode("utf-8")
            for k, v in sorted(value.items())
        )
        return ("{" + inner + "}").encode("utf-8")
    if isinstance(value, list):
        inner = ",".join(_py_jcs(v).decode("utf-8") for v in value)
        return ("[" + inner + "]").encode("utf-8")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_zkp_receipt_payload(
    receipt: PaymentReceipt,
    commitment_b64: str,
    proof_b64: str,
    threshold_milliunits: int,
    issuer_did: str,
    expires_at: str,
    issued_at: str,
) -> dict[str, Any]:
    """Construct the unsigned ZKP receipt payload.

    The payload merges payment receipt fields with ATB ZKP credential fields.
    Pass this to an issuer's signing endpoint to produce the signed envelope.

    Args:
        receipt: The settled on-chain payment receipt.
        commitment_b64: Pedersen commitment from the ATB ZKP service (base64).
        proof_b64: Bulletproofs range proof from the ATB ZKP service (base64).
        threshold_milliunits: Score threshold used in the range proof (0–1000).
        issuer_did: Issuer DID (bench_issuer).
        expires_at: ISO 8601 UTC expiry.
        issued_at: ISO 8601 UTC issuance.

    Returns:
        Unsigned payload dict for inclusion in a Falcon-1024 signed envelope.
    """
    return {
        "type": "zkp_receipt",
        "version": "1",
        # Receipt fields
        "payment_id": receipt.payment_id,
        "chain": receipt.chain,
        "amount_microusd": receipt.amount_microusd,
        "recipient": receipt.recipient,
        "tx_id": receipt.tx_id,
        "settled_at": receipt.settled_at,
        # ZKP credential fields (ATB Phase 2 compatible)
        "atb_cert_version": "2",
        "bench_issuer": issuer_did,
        "commitment_b64": commitment_b64,
        "proof_b64": proof_b64,
        "threshold_milliunits": threshold_milliunits,
        # Timestamps
        "expires_at": expires_at,
        "issued_at": issued_at,
    }


def verify_zkp_receipt(
    envelope_b64url: str,
    pk_b64: str,
    *,
    verify_range: bool = True,
) -> ZkpReceiptVerifyResult:
    """Verify a ZKP receipt envelope.

    Checks:
      1. Base64url decode + JSON parse.
      2. Envelope shape (alg=Falcon-1024, kid, payload dict, sig).
      3. Payload type = "zkp_receipt", version = "1".
      4. Payment receipt fields present.
      5. ZKP field structural validity.
      6. Expiry.
      7. kid consistency with supplied public key.
      8. Falcon-1024 signature over JCS-canonical payload (requires [verify]).
      9. Bulletproofs range proof — cryptographic verification that the committed
         reputation score meets the threshold (requires [verify], i.e. the native
         ``algovoi_bpverify`` extension). Performed when ``verify_range`` is True.

    Args:
        envelope_b64url: Base64url ZKP receipt envelope.
        pk_b64: Issuer Falcon-1024 public key (base64 standard).
        verify_range: When True (default), fully verify the Bulletproofs range
            proof offline and fail closed if it is invalid or the verifier is
            unavailable. Set False only if the range proof is verified by another
            trusted means (e.g. an online check against the live ATB ZKP service).

    Returns:
        :class:`ZkpReceiptVerifyResult` — check ``.valid``.
    """
    # 1. Decode
    try:
        envelope: dict[str, Any] = json.loads(_b64url_decode(envelope_b64url))
    except Exception as exc:
        return ZkpReceiptVerifyResult(valid=False, failure_reason=f"envelope_decode:{exc}")

    # 2. Shape
    payload = envelope.get("payload")
    sig_b64url: str | None = envelope.get("sig")
    alg: str | None = envelope.get("alg")
    kid: str | None = envelope.get("kid")

    if (
        not isinstance(payload, dict)
        or not isinstance(sig_b64url, str)
        or alg != "Falcon-1024"
        or not isinstance(kid, str)
    ):
        return ZkpReceiptVerifyResult(valid=False, failure_reason="envelope_shape")

    # 3. Type check
    if payload.get("type") != "zkp_receipt" or str(payload.get("version", "")) != "1":
        return ZkpReceiptVerifyResult(valid=False, failure_reason="wrong_type_or_version")

    # 4. Payment receipt fields
    payment_id: str = payload.get("payment_id", "")
    chain: str = payload.get("chain", "")
    amount_microusd = payload.get("amount_microusd")
    tx_id: str = payload.get("tx_id", "")

    if not payment_id or not chain or amount_microusd is None or not tx_id:
        return ZkpReceiptVerifyResult(valid=False, failure_reason="missing_receipt_fields")

    # 5. ZKP fields
    commitment_b64: str = payload.get("commitment_b64", "")
    proof_b64: str = payload.get("proof_b64", "")
    threshold_milliunits = int(payload.get("threshold_milliunits", 0))

    if not commitment_b64 or not proof_b64:
        return ZkpReceiptVerifyResult(
            valid=False, failure_reason="missing_zkp_fields",
            payment_id=payment_id, chain=chain,
        )

    try:
        comm_bytes = base64.b64decode(commitment_b64)
        proof_bytes = base64.b64decode(proof_b64)
    except Exception:
        return ZkpReceiptVerifyResult(
            valid=False, failure_reason="zkp_b64_decode",
            payment_id=payment_id, chain=chain,
        )

    if len(comm_bytes) != _COMMITMENT_BYTES:
        return ZkpReceiptVerifyResult(
            valid=False,
            failure_reason=f"commitment_len:{len(comm_bytes)}",
            payment_id=payment_id, chain=chain,
        )
    if not (_PROOF_MIN_BYTES <= len(proof_bytes) <= _PROOF_MAX_BYTES):
        return ZkpReceiptVerifyResult(
            valid=False,
            failure_reason=f"proof_len:{len(proof_bytes)}",
            payment_id=payment_id, chain=chain,
        )
    if not (0 <= threshold_milliunits <= 1000):
        return ZkpReceiptVerifyResult(
            valid=False,
            failure_reason=f"threshold_out_of_range:{threshold_milliunits}",
            payment_id=payment_id, chain=chain,
        )

    # 6. Expiry
    expires_at_str: str = payload.get("expires_at", "")
    try:
        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
    except Exception:
        return ZkpReceiptVerifyResult(
            valid=False, failure_reason="expires_at_malformed",
            payment_id=payment_id, chain=chain,
        )
    if datetime.now(timezone.utc) > expires_at:
        return ZkpReceiptVerifyResult(
            valid=False, failure_reason="expired",
            payment_id=payment_id, chain=chain, expires_at=expires_at,
        )

    # 7. Kid check
    try:
        pk_bytes = base64.b64decode(pk_b64)
    except Exception:
        return ZkpReceiptVerifyResult(valid=False, failure_reason="pk_b64_decode")

    if len(pk_bytes) != _FALCON1024_PK_LEN:
        return ZkpReceiptVerifyResult(
            valid=False, failure_reason=f"pk_wrong_len:{len(pk_bytes)}"
        )

    expected_kid = hashlib.sha256(pk_bytes).hexdigest()[:16]
    if kid != expected_kid:
        return ZkpReceiptVerifyResult(
            valid=False,
            failure_reason=f"kid_mismatch:got={kid},expected={expected_kid}",
        )

    issuer_did: str = payload.get("bench_issuer", "")

    # 8. Falcon-1024 signature
    if not _HAS_CRYPTO:
        return ZkpReceiptVerifyResult(
            valid=False,
            payment_id=payment_id, chain=chain,
            amount_microusd=int(amount_microusd), tx_id=tx_id,
            issuer_did=issuer_did or None, kid=kid, expires_at=expires_at,
            failure_reason="falcon_unavailable — install algovoi-zkp-receipt[verify]",
        )

    try:
        sig_bytes = _b64url_decode(sig_b64url)
    except Exception:
        return ZkpReceiptVerifyResult(valid=False, failure_reason="sig_b64_decode")

    canonical = _jcs_canonical(payload)
    try:
        ok = bool(_falcon_verify(pk_bytes, canonical, sig_bytes))
    except Exception as exc:
        return ZkpReceiptVerifyResult(
            valid=False, failure_reason=f"sig_verify_error:{exc}"
        )

    if not ok:
        return ZkpReceiptVerifyResult(valid=False, failure_reason="sig_invalid")

    # 9. Bulletproofs range proof — cryptographically verify score >= threshold.
    #     Fail closed if the native verifier is unavailable.
    if verify_range:
        if not _HAS_BPVERIFY:
            return ZkpReceiptVerifyResult(
                valid=False,
                payment_id=payment_id, chain=chain,
                amount_microusd=int(amount_microusd), tx_id=tx_id,
                issuer_did=issuer_did or None, kid=kid, expires_at=expires_at,
                failure_reason="bpverify_unavailable — install algovoi-zkp-receipt[verify]",
            )
        if not _bpverify.verify_range_proof(comm_bytes, proof_bytes, threshold_milliunits):
            return ZkpReceiptVerifyResult(
                valid=False,
                payment_id=payment_id, chain=chain,
                amount_microusd=int(amount_microusd), tx_id=tx_id,
                issuer_did=issuer_did or None, kid=kid, expires_at=expires_at,
                failure_reason="proof_invalid",
            )

    return ZkpReceiptVerifyResult(
        valid=True,
        payment_id=payment_id,
        chain=chain,
        amount_microusd=int(amount_microusd),
        tx_id=tx_id,
        issuer_did=issuer_did or None,
        kid=kid,
        expires_at=expires_at,
    )
