"""
substrate2.jws — compact EdDSA/Ed25519 JWS over receipts, JWKS, did:key, receipt verify.

From draft-hopley-x402-compliance-receipt-02 (JWS section). The header/payload are signed
as sorted-key COMPACT JSON (this is distinct from the JCS used for content hashes — the two
serialisations are deliberately never mixed). kid = sha256(pk_raw)[:32];
did:key = "did:key:z" + base58btc(0xED01 || pk_raw).

Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

import rfc8785

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _base58btc(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


# Valid machine-readable failure categories (the receipt-verification threat surface).
ERROR_CODES = frozenset({
    "INVALID_JWS_FORMAT",         # not 3-part base64url, or bad JSON header
    "UNSUPPORTED_ALG",            # alg not supported by this verifier
    "UNSUPPORTED_CANON_VERSION",  # canon_version not in the supported registry
    "TAMPERED_SIGNATURE",         # signature verify failed / no resolvable key
    "PAYMENT_HASH_MISMATCH",      # payment_hash doesn't match the expected tx
    "MISSING_ENVELOPE",           # no JWS present
    "NON_CANONICAL_PAYLOAD",      # payload doesn't re-canonicalise to the signed bytes
    "INVALID_PAYLOAD",            # payload bytes are not a JSON object post-decode
    "MISSING_FIELD",              # required receipt field absent/invalid in payload
})

# This verifier implements EdDSA/Ed25519. (The wider receipt contract also names ES256K/RS256;
# substrate2 platform receipts are EdDSA — other algs fail closed with UNSUPPORTED_ALG.)
SUPPORTED_ALGS = frozenset({"EdDSA"})
SUPPORTED_CANON_VERSIONS = frozenset({"jcs-rfc8785-v1"})
_SCREEN_RESULTS = frozenset({"ALLOW", "REFER", "DENY"})


class ReceiptVerificationError(Exception):
    """Raised when a compliance receipt fails any verification step.

    Keyword-only (code, message, field); code is validated against ERROR_CODES. Carries
    .code / .message / .field and .to_dict(). The gateway's receipt_verify.py reads
    exc.code, exc.message and exc.field, so this contract must be kept stable.
    """

    def __init__(self, *, code: str, message: str, field: str | None = None) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"Unknown error code {code!r}. Valid: {sorted(ERROR_CODES)}")
        self.code = code
        self.message = message
        self.field = field
        super().__init__(f"[{code}] {message}")

    def to_dict(self) -> dict:
        d: dict = {"code": self.code, "message": self.message}
        if self.field is not None:
            d["field"] = self.field
        return d


@dataclass
class VerifiedReceipt:
    """Successful verification result. Verification *failures* raise ReceiptVerificationError;
    a returned VerifiedReceipt always represents a valid receipt (bool(result) is True)."""

    raw_payload: dict
    alg: str
    kid: str | None = None
    canon_version: str | None = None
    screen_result: str | None = None
    screen_provider_did: str | None = None
    payer_ref: str | None = None

    def __bool__(self) -> bool:
        return True


def _seed_to_sk(private_key: Any) -> Ed25519PrivateKey:
    if isinstance(private_key, Ed25519PrivateKey):
        return private_key
    if isinstance(private_key, (bytes, bytearray)) and len(private_key) == 32:
        return Ed25519PrivateKey.from_private_bytes(bytes(private_key))
    raise ValueError("private_key must be an Ed25519PrivateKey or 32-byte seed")


def kid_for(public_key_raw: bytes) -> str:
    return hashlib.sha256(public_key_raw).hexdigest()[:32]


def did_key_for(public_key_raw: bytes) -> str:
    return "did:key:z" + _base58btc(b"\xed\x01" + public_key_raw)


def jwk_for(public_key_raw: bytes) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(public_key_raw), "kid": kid_for(public_key_raw)}


def sign_receipt(payload: dict, *, private_key: Any, kid: str | None = None) -> str:
    """Compact JWS (EdDSA) over a receipt payload. Header/payload are sorted-key compact JSON."""
    sk = _seed_to_sk(private_key)
    pk_raw = sk.public_key().public_bytes_raw()
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid or kid_for(pk_raw)}
    h = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h}.{p}".encode()
    return f"{h}.{p}." + _b64u(sk.sign(signing_input))


def _find_jwk(jwks: dict, kid: str | None):
    for jwk in (jwks or {}).get("keys", []):
        if jwk.get("kid") == kid:
            return jwk
    return None


def public_key_from_jwk(jwk: dict) -> Ed25519PublicKey:
    """Build an Ed25519 public key from an OKP/Ed25519 JWK ({kty,crv,x})."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ReceiptVerificationError(
            code="UNSUPPORTED_ALG",
            message=f"unsupported JWK key type {jwk.get('kty')!r}/{jwk.get('crv')!r}",
        )
    return Ed25519PublicKey.from_public_bytes(_b64u_dec(jwk["x"]))


def decode_jws(token: str):
    """Split + decode a compact JWS into (header dict, raw payload bytes, signature bytes).

    Raises ReceiptVerificationError(INVALID_JWS_FORMAT) for anything that is not three
    base64url segments with a JSON-object header.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT",
            message="JWS must have exactly three dot-separated segments",
        )
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(_b64u_dec(h_b64))
    except Exception as exc:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT", message=f"invalid JWS header: {exc}"
        ) from exc
    if not isinstance(header, dict):
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT", message="JWS header is not a JSON object"
        )
    try:
        raw_payload = _b64u_dec(p_b64)
        sig = _b64u_dec(s_b64)
    except Exception as exc:
        raise ReceiptVerificationError(
            code="INVALID_JWS_FORMAT", message=f"invalid base64url segment: {exc}"
        ) from exc
    return header, raw_payload, sig


def _verify_signature(public_key: Ed25519PublicKey, token: str, sig: bytes) -> None:
    h_b64, p_b64 = token.split(".")[:2]
    try:
        public_key.verify(sig, f"{h_b64}.{p_b64}".encode())
    except Exception as exc:
        raise ReceiptVerificationError(
            code="TAMPERED_SIGNATURE", message="signature verification failed"
        ) from exc


def _decode_payload(raw_payload: bytes) -> dict:
    try:
        payload = json.loads(raw_payload)
    except Exception as exc:
        raise ReceiptVerificationError(
            code="INVALID_PAYLOAD", message=f"payload is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ReceiptVerificationError(
            code="INVALID_PAYLOAD", message="payload is not a JSON object"
        )
    return payload


def verify_jws(token: str, *, public_key: Ed25519PublicKey):
    """Decode, enforce a supported alg, verify the signature; return (header, payload dict)."""
    header, raw_payload, sig = decode_jws(token)
    alg = header.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise ReceiptVerificationError(code="UNSUPPORTED_ALG", message=f"unsupported alg {alg!r}")
    _verify_signature(public_key, token, sig)
    return header, _decode_payload(raw_payload)


def verify_compliance_receipt(
    jws_token: str | None,
    *,
    public_key: Ed25519PublicKey | None = None,
    jwks: dict | None = None,
    expected_payment_hash: str | None = None,
    receipt_required: bool = False,
) -> VerifiedReceipt:
    """Verify a JWS-signed compliance receipt.

    Returns a VerifiedReceipt on success; raises ReceiptVerificationError (with a code from
    ERROR_CODES) on any failure. Key resolution: an explicit ``public_key`` takes precedence,
    otherwise the header ``kid`` selects a key from ``jwks``.
    """
    if not jws_token:
        raise ReceiptVerificationError(code="MISSING_ENVELOPE", message="no JWS receipt present")

    header, raw_payload, sig = decode_jws(jws_token)

    alg = header.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise ReceiptVerificationError(code="UNSUPPORTED_ALG", message=f"unsupported alg {alg!r}")

    kid = header.get("kid")
    key = public_key
    if key is None:
        jwk = _find_jwk(jwks or {}, kid)
        if jwk is None:
            raise ReceiptVerificationError(
                code="TAMPERED_SIGNATURE",
                message=f"no verification key available for kid {kid!r}",
            )
        key = public_key_from_jwk(jwk)

    _verify_signature(key, jws_token, sig)

    payload = _decode_payload(raw_payload)

    canon_version = payload.get("canon_version")
    if canon_version not in SUPPORTED_CANON_VERSIONS:
        raise ReceiptVerificationError(
            code="UNSUPPORTED_CANON_VERSION",
            message=f"unsupported canon_version {canon_version!r}",
            field="canon_version",
        )

    if rfc8785.dumps(payload) != raw_payload:
        raise ReceiptVerificationError(
            code="NON_CANONICAL_PAYLOAD",
            message="payload does not re-canonicalise (RFC 8785) to the signed bytes",
            field="payload",
        )

    screen_result = payload.get("screen_result")
    if screen_result not in _SCREEN_RESULTS:
        raise ReceiptVerificationError(
            code="MISSING_FIELD",
            message="screen_result is missing or not one of ALLOW/REFER/DENY",
            field="screen_result",
        )

    if expected_payment_hash is not None and payload.get("payment_hash") != expected_payment_hash:
        raise ReceiptVerificationError(
            code="PAYMENT_HASH_MISMATCH",
            message="payment_hash does not match the expected transaction",
            field="payment_hash",
        )

    return VerifiedReceipt(
        raw_payload=payload,
        alg=alg,
        kid=kid,
        canon_version=canon_version,
        screen_result=screen_result,
        screen_provider_did=payload.get("screen_provider_did"),
        payer_ref=payload.get("payer_ref"),
    )


__all__ = [
    "ERROR_CODES", "ReceiptVerificationError", "VerifiedReceipt",
    "kid_for", "did_key_for", "jwk_for", "sign_receipt", "public_key_from_jwk",
    "decode_jws", "verify_jws", "verify_compliance_receipt",
]
