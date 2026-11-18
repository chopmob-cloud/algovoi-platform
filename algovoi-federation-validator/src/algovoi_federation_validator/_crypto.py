"""PQC cryptographic primitives for federation token composition.

Full signature verification requires:  pip install algovoi-federation-validator[verify]
(installs pqcrypto>=0.4.0 and rfc8785>=0.1.2)

Without the extras:
  - Envelope structure, algorithm tag, expiry, and ZKP field shape are checked.
  - Falcon-1024 signature verification is skipped; failure_reason="falcon_unavailable".
  - Bulletproofs range-proof verification (algovoi_bpverify) fails closed;
    failure_reason="bpverify_unavailable".

Composition (compose_commitments, issue_federation_token) works without extras.

IETF anchors:
  draft-hopley-x402-pqc-credential-binding-00
  draft-hopley-x402-federation-zkp-00
  draft-hopley-x402-canonicalisation-jcs-v1-04
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from algovoi_federation_validator.models import (
    CredentialVerifyResult,
    FederationToken,
    IssuerEntry,
)

try:
    import rfc8785 as _rfc8785
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# Offline Bulletproofs range-proof verifier (native extension; reuses the exact
# dalek crates/generators/transcript as the ATB ZKP prover). Required to verify
# that each credential's committed score actually meets its threshold — without
# it, range verification fails closed.
try:
    import algovoi_bpverify as _bpverify

    _HAS_BPVERIFY = True
except ImportError:
    _bpverify = None
    _HAS_BPVERIFY = False

# Expected Falcon-1024 public key length in bytes (PQClean format).
_FALCON1024_PK_LEN = 1793

# Bulletproofs range proof approximate size bounds.
# A 64-bit range proof on Ristretto255 is ~672 bytes; allow 200–900 bytes.
_PROOF_MIN_BYTES = 200
_PROOF_MAX_BYTES = 900

# Pedersen commitment is a compressed Ristretto point — exactly 32 bytes.
_COMMITMENT_BYTES = 32

# Federation token HMAC tag label (domain separation).
_FED_TOKEN_LABEL = b"AlgoVoi-FederationToken-v1"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad and pad < 4:
        s = s + "=" * pad
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _jcs_canonical(value: Any) -> bytes:
    """JCS canonical JSON (RFC 8785).

    Uses rfc8785 if available; falls back to a pure-Python sort-then-dumps
    that is correct for non-unicode, non-float-edge-case payloads.
    """
    if _HAS_CRYPTO:
        return _rfc8785.dumps(value)  # type: ignore[no-any-return]
    # Pure-Python fallback — sufficient for federation token payloads.
    return _py_jcs(value)


def _py_jcs(value: Any) -> bytes:
    if isinstance(value, dict):
        pairs = sorted(value.items())
        inner = ",".join(
            json.dumps(k, ensure_ascii=False, separators=(",", ":"))
            + ":"
            + _py_jcs(v).decode("utf-8")
            for k, v in pairs
        )
        return ("{" + inner + "}").encode("utf-8")
    if isinstance(value, list):
        inner = ",".join(_py_jcs(v).decode("utf-8") for v in value)
        return ("[" + inner + "]").encode("utf-8")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ── Credential verification ──────────────────────────────────────────────────

def verify_pqc_credential(
    envelope_b64url: str,
    pk_b64: str,
    *,
    verify_range: bool = True,
) -> CredentialVerifyResult:
    """Verify a Falcon-1024-signed ATB ZKP Phase 2 credential envelope.

    Args:
        envelope_b64url: Base64url credential string (the value of
            X-ATB-ZK-Credential or the ``atb_zk_credential`` field).
        pk_b64: Issuer Falcon-1024 public key in base64 (standard, not URL-safe).
            Obtain from the issuer's ``/.well-known/atb-keys.json``
            (``keys[0].public_key_pqclean_b64``).

    Returns:
        :class:`CredentialVerifyResult` — check ``.valid``.

    Checks performed:
      1. Base64url decode + JSON parse.
      2. Envelope shape (alg=Falcon-1024, kid, payload dict, sig).
      3. Phase 2 cert version (``atb_cert_version == "2"``).
      4. Expiry.
      5. ZKP field presence and byte-length sanity.
      6. Kid consistency with the supplied public key.
      7. Falcon-1024 signature over JCS-canonical payload (requires extras).
      8. Bulletproofs range proof — cryptographic verification that the committed
         score meets the threshold (when ``verify_range`` is True; requires the
         native ``algovoi_bpverify`` extension). Fails closed if invalid/unavailable.
    """
    # 1. Decode
    try:
        envelope_bytes = _b64url_decode(envelope_b64url)
        envelope: dict[str, Any] = json.loads(envelope_bytes)
    except Exception as exc:
        return CredentialVerifyResult(valid=False, failure_reason=f"envelope_decode: {exc}")

    # 2. Shape
    payload = envelope.get("payload")
    sig_b64url: str | None = envelope.get("sig")
    alg: str | None = envelope.get("alg")
    kid: str | None = envelope.get("kid")

    if (
        not isinstance(payload, dict)
        or not isinstance(sig_b64url, str)
        or alg not in ("Falcon-1024",)
        or not isinstance(kid, str)
    ):
        return CredentialVerifyResult(valid=False, failure_reason="envelope_shape")

    # 3. Phase 2 only
    if str(payload.get("atb_cert_version", "")) != "2":
        return CredentialVerifyResult(valid=False, failure_reason="not_phase2_cert")

    # 4. Expiry
    expires_at_str: str = payload.get("expires_at", "")
    try:
        expires_at = datetime.fromisoformat(
            expires_at_str.replace("Z", "+00:00")
        )
    except Exception:
        return CredentialVerifyResult(valid=False, failure_reason="expires_at_malformed")

    if datetime.now(timezone.utc) > expires_at:
        return CredentialVerifyResult(
            valid=False, expires_at=expires_at, failure_reason="expired"
        )

    # 5. ZKP fields — structural size check (no Rust service needed)
    commitment_b64: str = payload.get("commitment_b64", "")
    proof_b64: str = payload.get("proof_b64", "")
    threshold_milliunits: int = int(payload.get("threshold_milliunits", 0))

    if not commitment_b64 or not proof_b64:
        return CredentialVerifyResult(valid=False, failure_reason="missing_zkp_fields")

    try:
        comm_bytes = base64.b64decode(commitment_b64)
        proof_bytes = base64.b64decode(proof_b64)
    except Exception:
        return CredentialVerifyResult(valid=False, failure_reason="zkp_b64_decode")

    if len(comm_bytes) != _COMMITMENT_BYTES:
        return CredentialVerifyResult(
            valid=False,
            failure_reason=f"commitment_len:{len(comm_bytes)} (expected {_COMMITMENT_BYTES})",
        )
    if not (_PROOF_MIN_BYTES <= len(proof_bytes) <= _PROOF_MAX_BYTES):
        return CredentialVerifyResult(
            valid=False,
            failure_reason=f"proof_len:{len(proof_bytes)} (expected {_PROOF_MIN_BYTES}–{_PROOF_MAX_BYTES})",
        )
    if not (0 <= threshold_milliunits <= 1000):
        return CredentialVerifyResult(
            valid=False, failure_reason=f"threshold_out_of_range:{threshold_milliunits}"
        )

    # 6. Kid check
    try:
        pk_bytes = base64.b64decode(pk_b64)
    except Exception:
        return CredentialVerifyResult(valid=False, failure_reason="pk_b64_decode")

    if len(pk_bytes) != _FALCON1024_PK_LEN:
        return CredentialVerifyResult(
            valid=False,
            failure_reason=f"pk_wrong_len:{len(pk_bytes)} (expected {_FALCON1024_PK_LEN})",
        )

    expected_kid = hashlib.sha256(pk_bytes).hexdigest()[:16]
    if kid != expected_kid:
        return CredentialVerifyResult(
            valid=False,
            failure_reason=f"kid_mismatch:got={kid},expected={expected_kid}",
        )

    # 7. Falcon-1024 signature
    issuer_did: str = payload.get("bench_issuer", "")

    if not _HAS_CRYPTO:
        # Structural checks all passed; signature cannot be verified without extras.
        return CredentialVerifyResult(
            valid=False,
            issuer_did=issuer_did or None,
            kid=kid,
            alg=alg,
            commitment_b64=commitment_b64,
            proof_b64=proof_b64,
            threshold_milliunits=threshold_milliunits,
            expires_at=expires_at,
            failure_reason="falcon_unavailable — install algovoi-federation-validator[verify]",
        )

    try:
        sig_bytes = _b64url_decode(sig_b64url)
    except Exception:
        return CredentialVerifyResult(valid=False, failure_reason="sig_b64_decode")

    canonical = _jcs_canonical(payload)
    try:
        ok = bool(_falcon_verify(pk_bytes, canonical, sig_bytes))
    except Exception as exc:
        return CredentialVerifyResult(valid=False, failure_reason=f"sig_verify_error:{exc}")

    if not ok:
        return CredentialVerifyResult(valid=False, failure_reason="sig_invalid")

    # 8. Bulletproofs range proof — cryptographically verify score >= threshold.
    #     Fail closed: a structurally-sized but invalid proof must NOT compose.
    if verify_range:
        if not _HAS_BPVERIFY:
            return CredentialVerifyResult(
                valid=False,
                issuer_did=issuer_did or None, kid=kid, alg=alg,
                commitment_b64=commitment_b64, proof_b64=proof_b64,
                threshold_milliunits=threshold_milliunits, expires_at=expires_at,
                failure_reason="bpverify_unavailable — install algovoi-federation-validator[verify]",
            )
        if not _bpverify.verify_range_proof(comm_bytes, proof_bytes, threshold_milliunits):
            return CredentialVerifyResult(
                valid=False,
                issuer_did=issuer_did or None, kid=kid, alg=alg,
                commitment_b64=commitment_b64, proof_b64=proof_b64,
                threshold_milliunits=threshold_milliunits, expires_at=expires_at,
                failure_reason="proof_invalid",
            )

    return CredentialVerifyResult(
        valid=True,
        issuer_did=issuer_did or None,
        kid=kid,
        alg=alg,
        commitment_b64=commitment_b64,
        proof_b64=proof_b64,
        threshold_milliunits=threshold_milliunits,
        expires_at=expires_at,
    )


# ── Commitment composition ────────────────────────────────────────────────────

def compose_commitments(commitment_bytes_list: list[bytes], nonce: bytes) -> bytes:
    """Compose multiple Pedersen commitments into a single federation commitment.

    Algorithm:
        fed_commitment = SHA-256(domain || comm_0 || comm_1 || … || nonce)

    The domain label provides separation from other SHA-256 uses.
    The nonce prevents a composite from being bound to a different credential set.

    Args:
        commitment_bytes_list: Raw 32-byte Pedersen commitment for each credential.
        nonce: Random 32-byte nonce generated per composition.

    Returns:
        32-byte federation commitment.

    IETF anchor: draft-hopley-x402-federation-zkp-00 §5.2
    """
    h = hashlib.sha256()
    h.update(_FED_TOKEN_LABEL)
    for comm in commitment_bytes_list:
        h.update(comm)
    h.update(nonce)
    return h.digest()


# ── Federation token issuance ─────────────────────────────────────────────────

def issue_federation_token(
    issuers: list[IssuerEntry],
    commitment_bytes_list: list[bytes],
    nonce: bytes,
    expires_at: datetime,
    validator_secret: bytes,
) -> FederationToken:
    """Issue a signed federation token from verified credential components.

    The token is an HMAC-SHA256-signed envelope whose payload contains the
    composite commitment, issuer list, and validity window. The validator
    signs with its own key — neither issuer is involved, so no shared trust
    root is required.

    Token envelope format (JCS-canonical payload, then HMAC over it):

        {
          "alg":  "HMAC-SHA256",
          "kid":  "<hex(sha256(validator_secret)[:16])>",
          "type": "federation_token",
          "payload": {
            "version":          "1",
            "fed_commitment":   "<hex>",
            "fed_nonce":        "<hex>",
            "issuers":          [{"did":…,"kid":…,"alg":…}, …],
            "threshold_met":    true,
            "issued_at":        "2026-06-03T00:00:00Z",
            "expires_at":       "2026-06-03T23:59:59Z"
          },
          "sig": "<base64url HMAC-SHA256(JCS(payload))>"
        }

    IETF anchor: draft-hopley-x402-federation-zkp-00 §6

    Args:
        issuers: Verified issuer entries (DID, kid, alg).
        commitment_bytes_list: Raw 32-byte commitments from verified credentials.
        nonce: Per-composition random nonce (32 bytes).
        expires_at: Earliest expiry across all input credentials.
        validator_secret: HMAC key held by the validator (not shared with issuers).

    Returns:
        :class:`FederationToken` with a signed ``raw`` envelope.
    """
    fed_commitment = compose_commitments(commitment_bytes_list, nonce)
    fed_commitment_hex = fed_commitment.hex()
    fed_nonce_hex = nonce.hex()

    kid = hashlib.sha256(validator_secret).hexdigest()[:16]
    issued_at = datetime.now(timezone.utc)

    payload: dict[str, Any] = {
        "version": "1",
        "fed_commitment": fed_commitment_hex,
        "fed_nonce": fed_nonce_hex,
        "issuers": [
            {"did": e.did, "kid": e.kid, "alg": e.alg}
            for e in issuers
        ],
        "threshold_met": True,
        "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    canonical = _jcs_canonical(payload)
    sig = hmac.new(validator_secret, _FED_TOKEN_LABEL + canonical, hashlib.sha256).digest()
    sig_b64url = _b64url_encode(sig)

    envelope: dict[str, Any] = {
        "alg": "HMAC-SHA256",
        "kid": kid,
        "type": "federation_token",
        "payload": payload,
        "sig": sig_b64url,
    }
    raw = _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))

    return FederationToken(
        raw=raw,
        fed_commitment_hex=fed_commitment_hex,
        fed_nonce_hex=fed_nonce_hex,
        issuers=issuers,
        expires_at=expires_at,
        issued_at=issued_at,
    )


def verify_federation_token(
    token_b64url: str,
    validator_secret: bytes,
) -> dict[str, Any] | None:
    """Verify a federation token's HMAC signature and return its payload.

    Args:
        token_b64url: The ``raw`` field from a :class:`FederationToken`.
        validator_secret: The same secret used during issuance.

    Returns:
        The payload dict if the token is valid and unexpired, else ``None``.
    """
    try:
        envelope: dict[str, Any] = json.loads(_b64url_decode(token_b64url))
    except Exception:
        return None

    if envelope.get("type") != "federation_token" or envelope.get("alg") != "HMAC-SHA256":
        return None

    payload = envelope.get("payload")
    sig_b64url: str | None = envelope.get("sig")
    if not isinstance(payload, dict) or not isinstance(sig_b64url, str):
        return None

    # Verify HMAC
    canonical = _jcs_canonical(payload)
    expected = hmac.new(validator_secret, _FED_TOKEN_LABEL + canonical, hashlib.sha256).digest()
    try:
        received = _b64url_decode(sig_b64url)
    except Exception:
        return None
    if not hmac.compare_digest(expected, received):
        return None

    # Expiry
    expires_at_str: str = payload.get("expires_at", "")
    try:
        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
    except Exception:
        return None
    if datetime.now(timezone.utc) > expires_at:
        return None

    return payload
