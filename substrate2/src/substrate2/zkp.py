"""
substrate2.zkp — ZKP payment receipt (Falcon-1024 envelope binding an opaque
Pedersen commitment + Bulletproofs range proof to a settled payment).

From draft-hopley-x402-federation-zkp-00 + draft-hopley-x402-pqc-credential-binding-00 +
zkp_receipt_v1 vectors. substrate2 Falcon-verifies the envelope over JCS canonical bytes,
structurally validates the commitment/proof (commitment 32 bytes; proof 200-900 bytes),
and — when verify_range is set (the default) — *cryptographically* verifies the
Bulletproofs range proof offline via the native ``algovoi_bpverify`` extension, which
reuses the exact dalek crates / generators / Fiat-Shamir transcript as the ATB ZKP prover.
Verification therefore opens the proof and confirms score >= threshold; it does not merely
bind an opaque blob. Fails closed when the proof is invalid or the verifier is unavailable.

Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .canon import canonicalize_bytes
from . import pqc

# Real Bulletproofs range-proof verification (offline native extension; reuses the
# exact dalek crates/generators/transcript as the ATB ZKP prover). Optional import:
# if unavailable the receipt cannot be proof-verified and verification fails closed.
try:
    import algovoi_bpverify as _bpverify
    _HAS_BPVERIFY = True
except ImportError:  # pragma: no cover
    _bpverify = None
    _HAS_BPVERIFY = False

_COMMITMENT_BYTES = 32
_PROOF_MIN_BYTES = 200
_PROOF_MAX_BYTES = 900
_FALCON1024_PK_LEN = 1793
_ALG = "Falcon-1024"

_RECEIPT_FIELDS = ("payment_id", "chain", "amount_microusd", "recipient", "tx_id", "settled_at")
# Optional chain-agnostic identifiers, emitted ONLY when supplied so that a receipt built
# without them is byte-identical to one built before they existed.
_CAIP_FIELDS = ("chain_caip2", "recipient_caip10")


def _caip_fields(chain_caip2, recipient_caip10) -> dict:
    """Validate and return the optional CAIP keys, or {} when none are supplied.

    Under SUBSTRATE2_CAIP_STRICT both become mandatory. The gates run BEFORE the payload is
    assembled, so a malformed identifier can never reach the signature.
    """
    from .caip import CaipError, require_caip2, require_caip10
    from .receipts._common import caip_strict

    if chain_caip2 is None and recipient_caip10 is None:
        if caip_strict():
            raise ValueError(
                "chain_caip2 and recipient_caip10 are required when SUBSTRATE2_CAIP_STRICT is set"
            )
        return {}
    if caip_strict() and (chain_caip2 is None or recipient_caip10 is None):
        raise ValueError(
            "chain_caip2 and recipient_caip10 are both required when SUBSTRATE2_CAIP_STRICT is set"
        )
    out = {}
    try:
        if chain_caip2 is not None:
            out["chain_caip2"] = require_caip2(chain_caip2)
        if recipient_caip10 is not None:
            out["recipient_caip10"] = require_caip10(recipient_caip10)
    except CaipError as exc:
        raise ValueError(f"zkp receipt: {exc}") from exc
    return out


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


@dataclass
class PaymentReceipt:
    """A payment receipt bound into a ZK receipt envelope.

    ``chain`` and ``recipient`` are free-form for backwards compatibility: they are part of
    the preimage of every ZK envelope already issued, so their meaning cannot change without
    those envelopes ceasing to verify.

    ``chain_caip2`` and ``recipient_caip10`` are the chain-agnostic answers, added additively
    in 2.0.0. Supply them and they are gated and emitted as their own keys; omit them and the
    payload serialises byte-for-byte as it did before they existed. Under
    ``SUBSTRATE2_CAIP_STRICT=1`` they are mandatory.

    Why this matters more here than elsewhere: a ZK receipt deliberately withholds the
    cleartext amount, so the identifiers are most of what a verifier can actually read. A
    bare ``"solana"`` names a chain by convention rather than by identity, and two parties
    can agree on the string while meaning different networks.
    """

    payment_id: str
    chain: str
    amount_microusd: int
    recipient: str
    tx_id: str
    settled_at: str
    chain_caip2: str | None = None
    recipient_caip10: str | None = None

    def as_dict(self) -> dict:
        out = {f: getattr(self, f) for f in _RECEIPT_FIELDS}
        out.update(_caip_fields(self.chain_caip2, self.recipient_caip10))
        return out


@dataclass
class ZkpReceiptEnvelope:
    raw_b64url: str
    alg: str
    kid: str
    payload: dict
    sig_b64url: str


@dataclass
class ZkpReceiptVerifyResult:
    valid: bool
    payment_id: str | None = None
    chain: str | None = None
    amount_microusd: int | None = None
    tx_id: str | None = None
    issuer_did: str | None = None
    kid: str | None = None
    expires_at: str | None = None
    failure_reason: str | None = None
    keystone_ref: str | None = None
    mandate_ref: str | None = None

    def __bool__(self) -> bool:
        return self.valid


import re as _re

# \A...\Z, never ^...$: `$` also matches before a trailing newline. See execution.py.
_SHA256_REF = _re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_KEYSTONE_TYPE = "zkp_keystone_receipt"
_PREDICATE_OPS = ("le", "lt", "ge", "gt", "in_range")


def build_zkp_receipt_payload(receipt, commitment_b64, proof_b64, threshold_milliunits, issuer_did, expires_at, issued_at) -> dict:
    """Assemble the ZKP receipt envelope payload (cleartext-free; binds the opaque proof)."""
    if isinstance(receipt, PaymentReceipt):
        base = receipt.as_dict()
    else:
        base = {f: receipt[f] for f in _RECEIPT_FIELDS}
        # a mapping may carry the optional CAIP keys too; same gates, same additive rule
        base.update(_caip_fields(receipt.get("chain_caip2"), receipt.get("recipient_caip10")))
    return {
        "type": "zkp_receipt",
        "version": "1",
        **base,
        "atb_cert_version": "2",
        "bench_issuer": issuer_did,
        "commitment_b64": commitment_b64,
        "proof_b64": proof_b64,
        "threshold_milliunits": threshold_milliunits,
        "expires_at": expires_at,
        "issued_at": issued_at,
    }


def prove_range_b64(score_milliunits: int, threshold_milliunits: int) -> tuple[str, str]:
    """Generate a REAL Bulletproofs range proof (committed score >= threshold) via the bundled
    algovoi-bpverify prover, returning (commitment_b64, proof_b64) ready for a zkp_keystone
    receipt. score/threshold are 0..1000 milliunits. Raises if algovoi-bpverify is not installed
    (it travels in the bundle) or if score < threshold (the proof would not verify)."""
    if not _HAS_BPVERIFY:
        raise RuntimeError("algovoi-bpverify not installed; cannot generate a ZK range proof")
    commitment, proof, _blinding = _bpverify.prove_range_proof(int(score_milliunits), int(threshold_milliunits))
    return base64.b64encode(commitment).decode(), base64.b64encode(proof).decode()


def build_zkp_keystone_payload(*, keystone_ref, mandate_ref, commitment_b64, proof_b64,
                               threshold_milliunits, issuer_did, expires_at, issued_at,
                               predicate=None) -> dict:
    """Assemble a zkp_keystone_v1 payload (SPEC-private-keystone-zkp-bind-v1): a ZK predicate
    bound to a keystone ref. The committed value is never in cleartext; the proof proves the
    predicate over it, the issuer (bench_issuer) attests the commitment opens to the value
    behind keystone_ref (v1 issuer-attested binding), and the Falcon envelope + content address
    make keystone_ref/mandate_ref tamper-evident."""
    if not (isinstance(keystone_ref, str) and _SHA256_REF.match(keystone_ref)):
        raise ValueError("keystone_ref must be a sha256: ref")
    if not (isinstance(mandate_ref, str) and _SHA256_REF.match(mandate_ref)):
        raise ValueError("mandate_ref must be a sha256: ref")
    pred = predicate or {"op": "ge", "subject": "committed_value", "bound_source": "mandate_ref"}
    if pred.get("op") not in _PREDICATE_OPS:
        raise ValueError(f"predicate.op must be one of {_PREDICATE_OPS}")
    return {
        "type": _KEYSTONE_TYPE,
        "version": "1",
        "canon_version": "jcs-rfc8785-v1",
        "keystone_ref": keystone_ref,
        "mandate_ref": mandate_ref,
        "predicate": pred,
        "atb_cert_version": "2",
        "bench_issuer": issuer_did,
        "commitment_b64": commitment_b64,
        "proof_b64": proof_b64,
        "threshold_milliunits": threshold_milliunits,
        "expires_at": expires_at,
        "issued_at": issued_at,
    }


def zkp_from_keystone(bundle, *, commitment_b64, proof_b64, threshold_milliunits, issuer_did,
                      secret_key, public_key, expires_at, issued_at, predicate=None,
                      keystone_ref_field="execution_ref") -> str:
    """Emit a Falcon-signed zkp_keystone envelope bound to a keystone bundle: keystone_ref from
    bundle[keystone_ref_field] (execution_ref by default), mandate_ref from bundle["mandate_ref"]."""
    payload = build_zkp_keystone_payload(
        keystone_ref=bundle[keystone_ref_field], mandate_ref=bundle["mandate_ref"],
        commitment_b64=commitment_b64, proof_b64=proof_b64,
        threshold_milliunits=threshold_milliunits, issuer_did=issuer_did,
        expires_at=expires_at, issued_at=issued_at, predicate=predicate)
    return build_zkp_envelope_b64(payload, secret_key, public_key)


def build_zkp_envelope_b64(payload: dict, secret_key: bytes, public_key: bytes) -> str:
    import hashlib
    kid = hashlib.sha256(public_key).hexdigest()[:16]
    sig = pqc.sign_falcon_1024(secret_key, canonicalize_bytes(payload))
    envelope = {"alg": _ALG, "kid": kid, "payload": payload, "sig": _b64url_encode(sig)}
    return _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))


def verify_zkp_receipt(envelope_b64url: str, pk_b64: str, *, verify_range: bool = True) -> ZkpReceiptVerifyResult:
    """Verify a ZKP receipt envelope: Falcon sig + structural bounds + type + expiry,
    and (when ``verify_range`` is True, the default) the Bulletproofs range proof itself.

    ``verify_range=True`` performs full offline cryptographic verification of the
    range proof via the native ``algovoi_bpverify`` extension and fails closed if
    the proof is invalid or the extension is unavailable. Pass ``verify_range=False``
    only when the caller verifies the range proof by another trusted means (e.g. the
    gateway's online check against the live ATB ZKP service)."""
    import hashlib
    try:
        pk = base64.b64decode(pk_b64) if isinstance(pk_b64, str) else pk_b64
    except Exception:
        return ZkpReceiptVerifyResult(False, failure_reason="pk_decode")
    if len(pk) != _FALCON1024_PK_LEN:
        return ZkpReceiptVerifyResult(False, failure_reason="pk_length")
    try:
        envelope = json.loads(_b64url_decode(envelope_b64url))
        payload = envelope["payload"]
        sig = _b64url_decode(envelope["sig"])
    except Exception as exc:
        return ZkpReceiptVerifyResult(False, failure_reason=f"decode:{exc}")
    if envelope.get("alg") != _ALG:
        return ZkpReceiptVerifyResult(False, failure_reason="alg")
    if envelope.get("kid") != hashlib.sha256(pk).hexdigest()[:16]:
        return ZkpReceiptVerifyResult(False, failure_reason="kid")
    if not pqc.verify_falcon_1024(pk, canonicalize_bytes(payload), sig):
        return ZkpReceiptVerifyResult(False, failure_reason="sig")
    if payload.get("type") != "zkp_receipt":
        return ZkpReceiptVerifyResult(False, failure_reason="type")
    if not payload.get("payment_id"):
        return ZkpReceiptVerifyResult(False, failure_reason="missing_receipt")
    try:
        commitment_bytes = base64.b64decode(payload["commitment_b64"])
        proof_bytes = base64.b64decode(payload["proof_b64"])
    except Exception:
        return ZkpReceiptVerifyResult(False, failure_reason="blob_decode")
    if len(commitment_bytes) != _COMMITMENT_BYTES:
        return ZkpReceiptVerifyResult(False, failure_reason="commitment_size")
    if not (_PROOF_MIN_BYTES <= len(proof_bytes) <= _PROOF_MAX_BYTES):
        return ZkpReceiptVerifyResult(False, failure_reason="proof_size")
    # Cryptographically verify the range proof (score >= threshold) — fail closed.
    if verify_range:
        try:
            threshold_mu = int(payload.get("threshold_milliunits"))
        except (TypeError, ValueError):
            return ZkpReceiptVerifyResult(False, failure_reason="threshold_malformed")
        if not (0 <= threshold_mu <= 1000):
            return ZkpReceiptVerifyResult(False, failure_reason="threshold_range")
        if not _HAS_BPVERIFY:
            return ZkpReceiptVerifyResult(
                False,
                failure_reason="bpverify_unavailable — install algovoi-bpverify for ZK proof verification",
            )
        if not _bpverify.verify_range_proof(commitment_bytes, proof_bytes, threshold_mu):
            return ZkpReceiptVerifyResult(False, failure_reason="proof_invalid")
    try:
        exp = datetime.strptime(payload.get("expires_at", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return ZkpReceiptVerifyResult(False, failure_reason="expires_malformed")
    if exp < datetime.now(timezone.utc):
        return ZkpReceiptVerifyResult(False, failure_reason="expired")
    return ZkpReceiptVerifyResult(
        True,
        payment_id=payload.get("payment_id"),
        chain=payload.get("chain"),
        amount_microusd=payload.get("amount_microusd"),
        tx_id=payload.get("tx_id"),
        issuer_did=payload.get("bench_issuer"),
        kid=envelope.get("kid"),
        expires_at=payload.get("expires_at"),
    )


def verify_zkp_keystone(envelope_b64url: str, pk_b64: str, *, verify_range: bool = True,
                        keystone_ref: str | None = None) -> ZkpReceiptVerifyResult:
    """Verify a zkp_keystone envelope: Falcon sig + structural bounds + keystone binding + expiry,
    and (when verify_range, the default) the Bulletproofs range proof itself via algovoi_bpverify.

    If keystone_ref is given, the receipt's keystone_ref must equal it (binds the proof to THIS
    lifecycle point; a proof for decision X is rejected against decision Y). Fails closed."""
    import hashlib
    try:
        pk = base64.b64decode(pk_b64) if isinstance(pk_b64, str) else pk_b64
    except Exception:
        return ZkpReceiptVerifyResult(False, failure_reason="pk_decode")
    if len(pk) != _FALCON1024_PK_LEN:
        return ZkpReceiptVerifyResult(False, failure_reason="pk_length")
    try:
        envelope = json.loads(_b64url_decode(envelope_b64url))
        payload = envelope["payload"]
        sig = _b64url_decode(envelope["sig"])
    except Exception as exc:
        return ZkpReceiptVerifyResult(False, failure_reason=f"decode:{exc}")
    if envelope.get("alg") != _ALG:
        return ZkpReceiptVerifyResult(False, failure_reason="alg")
    if envelope.get("kid") != hashlib.sha256(pk).hexdigest()[:16]:
        return ZkpReceiptVerifyResult(False, failure_reason="kid")
    if not pqc.verify_falcon_1024(pk, canonicalize_bytes(payload), sig):
        return ZkpReceiptVerifyResult(False, failure_reason="sig")
    if payload.get("type") != _KEYSTONE_TYPE:
        return ZkpReceiptVerifyResult(False, failure_reason="type")
    kref = payload.get("keystone_ref")
    mref = payload.get("mandate_ref")
    if not (isinstance(kref, str) and _SHA256_REF.match(kref)):
        return ZkpReceiptVerifyResult(False, failure_reason="keystone_ref_malformed")
    if not (isinstance(mref, str) and _SHA256_REF.match(mref)):
        return ZkpReceiptVerifyResult(False, failure_reason="mandate_ref_malformed")
    if keystone_ref is not None and kref != keystone_ref:
        return ZkpReceiptVerifyResult(False, failure_reason="keystone_ref_mismatch")
    pred = payload.get("predicate")
    if not (isinstance(pred, dict) and pred.get("op") in _PREDICATE_OPS):
        return ZkpReceiptVerifyResult(False, failure_reason="predicate_malformed")
    try:
        commitment_bytes = base64.b64decode(payload["commitment_b64"])
        proof_bytes = base64.b64decode(payload["proof_b64"])
    except Exception:
        return ZkpReceiptVerifyResult(False, failure_reason="blob_decode")
    if len(commitment_bytes) != _COMMITMENT_BYTES:
        return ZkpReceiptVerifyResult(False, failure_reason="commitment_size")
    if not (_PROOF_MIN_BYTES <= len(proof_bytes) <= _PROOF_MAX_BYTES):
        return ZkpReceiptVerifyResult(False, failure_reason="proof_size")
    if verify_range:
        try:
            threshold_mu = int(payload.get("threshold_milliunits"))
        except (TypeError, ValueError):
            return ZkpReceiptVerifyResult(False, failure_reason="threshold_malformed")
        if not (0 <= threshold_mu <= 1000):
            return ZkpReceiptVerifyResult(False, failure_reason="threshold_range")
        if not _HAS_BPVERIFY:
            return ZkpReceiptVerifyResult(
                False, failure_reason="bpverify_unavailable — install algovoi-bpverify for ZK proof verification")
        if not _bpverify.verify_range_proof(commitment_bytes, proof_bytes, threshold_mu):
            return ZkpReceiptVerifyResult(False, failure_reason="proof_invalid")
    try:
        exp = datetime.strptime(payload.get("expires_at", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return ZkpReceiptVerifyResult(False, failure_reason="expires_malformed")
    if exp < datetime.now(timezone.utc):
        return ZkpReceiptVerifyResult(False, failure_reason="expired")
    return ZkpReceiptVerifyResult(
        True, issuer_did=payload.get("bench_issuer"), kid=envelope.get("kid"),
        expires_at=payload.get("expires_at"), keystone_ref=kref, mandate_ref=mref)


__all__ = [
    "PaymentReceipt", "ZkpReceiptEnvelope", "ZkpReceiptVerifyResult",
    "build_zkp_receipt_payload", "build_zkp_envelope_b64", "verify_zkp_receipt",
    "build_zkp_keystone_payload", "zkp_from_keystone", "verify_zkp_keystone", "prove_range_b64",
]
