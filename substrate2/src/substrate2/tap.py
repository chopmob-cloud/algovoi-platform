"""AlgoVoi TAP receipt profile — render a keystone fact as a Visa Trusted Agent Protocol
post-authentication transaction receipt (interop profile, not a reimplementation).

External spec: visa/trusted-agent-protocol Issue #16 (transaction receipt signing for a
post-authentication audit trail). That issue describes a receipt that carries: the original TAP
signature binding it to the authenticated request, a hash of the processed transaction, a merchant
signature over both, and a timestamp + sequence, a "two-sided audit trail". JCS (RFC 8785) is the
canonicalization in its reference. This is exactly our keystone shape, so we map it natively:

    authorization_ref  <- decision_ref   (passport->mandate->policy->decision: the agent was authorized)
    transaction_hash   <- execution_ref  (decision-bound execution evidence: what was processed)
    settlement_ref     <- the real on-chain settlement that closed it (optional)

We keep TAP's JCS canonicalization and two-sided semantics, sign Ed25519 (so a TAP-native verifier
checks it) AND Falcon-1024 (post-quantum durability), and credit the spec in-band. Same pattern as
our .epi profile (which adapts microsoft/agent-governance-toolkit's format). The open verifier is
algovoi-tap-verifier (PyPI + npm); this module is the commercial emitter, one renderer on the
shared keystone evidence-export surface (native / JWS / PEF / TAP / EPI / ZK).
"""
from __future__ import annotations
import base64
import hashlib

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CANON_VERSION = "jcs-rfc8785-v1"
PROFILE = "tap-receipt-v1"
TAP_SPEC = "visa/trusted-agent-protocol#16"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def tap_receipt_preimage(*, authorization_ref: str, transaction_hash: str, outcome: str,
                         timestamp_ms: int, sequence: int, settlement_ref: str | None = None) -> dict:
    """The signed core of a TAP receipt: the two-sided audit fact, in JCS-canonical form.

    authorization_ref = the keystone decision_ref (agent proved authorized);
    transaction_hash   = the keystone execution_ref (what was processed)."""
    pre = {
        "canon_version": CANON_VERSION,
        "profile": PROFILE,
        "tap_spec": TAP_SPEC,
        "authorization_ref": authorization_ref,
        "transaction_hash": transaction_hash,
        "outcome": outcome,
        "timestamp_ms": int(timestamp_ms),     # integer epoch-ms (collision-stable; our distinctive form)
        "sequence": int(sequence),
    }
    if settlement_ref:
        pre["settlement_ref"] = settlement_ref
    return pre


def sign_tap_receipt(preimage: dict, *, ed25519_sk: Ed25519PrivateKey,
                     falcon_sk: bytes | None = None, falcon_pk: bytes | None = None) -> dict:
    """Sign a TAP receipt: Ed25519 (TAP-native verifiers) plus optional Falcon-1024 (post-quantum)."""
    msg = rfc8785.dumps(preimage)
    env = {
        "preimage": preimage,
        "receipt_id": "sha256:" + hashlib.sha256(msg).hexdigest(),
        "alg": "Ed25519",
        "sig": _b64(ed25519_sk.sign(msg)),
    }
    if falcon_sk is not None and falcon_pk is not None:
        from substrate2 import pqc
        env["alg2"] = "Falcon-1024"
        env["kid2"] = pqc.falcon_kid(falcon_pk)
        env["sig2"] = _b64(pqc.sign_falcon_1024(falcon_sk, msg))
    return env


def verify_tap_receipt(env: dict, *, ed25519_pk: Ed25519PublicKey, falcon_pk: bytes | None = None) -> bool:
    """Verify a TAP receipt offline: receipt_id binds the preimage, Ed25519 (and Falcon if present)."""
    pre = env.get("preimage")
    if not isinstance(pre, dict):
        return False
    msg = rfc8785.dumps(pre)
    if env.get("receipt_id") != "sha256:" + hashlib.sha256(msg).hexdigest():
        return False
    try:
        ed25519_pk.verify(_b64d(env["sig"]), msg)
    except Exception:
        return False
    if falcon_pk is not None:
        # Supplying a Falcon key means the caller requires the post-quantum layer. A stripped/absent
        # sig2 is then a downgrade attack and must fail, not silently pass on Ed25519 alone.
        sig2 = env.get("sig2")
        if not sig2:
            return False
        from substrate2 import pqc
        if not pqc.verify_falcon_1024(falcon_pk, msg, _b64d(sig2)):
            return False
    return True


def tap_from_keystone(bundle: dict, *, ed25519_sk: Ed25519PrivateKey, sequence: int = 1,
                      falcon_sk: bytes | None = None, falcon_pk: bytes | None = None) -> dict:
    """Emit a TAP receipt directly from a keystone bundle, keystone-bound by construction.

    authorization_ref <- bundle["decision_ref"], transaction_hash <- bundle["execution_ref"],
    outcome + timestamp from the execution stage. Optional settlement_ref carried through.
    Raises KeyError if the bundle is missing a load-bearing keystone field."""
    pre = tap_receipt_preimage(
        authorization_ref=bundle["decision_ref"],
        transaction_hash=bundle["execution_ref"],
        outcome=bundle["outcome"],
        timestamp_ms=bundle["executed_at_ms"],
        sequence=sequence,
        settlement_ref=bundle.get("settlement_ref"),
    )
    return sign_tap_receipt(pre, ed25519_sk=ed25519_sk, falcon_sk=falcon_sk, falcon_pk=falcon_pk)


__all__ = ["CANON_VERSION", "PROFILE", "TAP_SPEC",
           "tap_receipt_preimage", "sign_tap_receipt", "verify_tap_receipt", "tap_from_keystone"]
