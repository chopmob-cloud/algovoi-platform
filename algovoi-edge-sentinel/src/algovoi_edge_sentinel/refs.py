"""Content-addressed references for the edge layer.

  policy_ref         = "sha256:" + SHA-256(JCS(policy))                         (the rules in force)
  subject_ref        = "sha256:" + SHA-256(JCS(no_pii_descriptor))             (who/where, no PII)
  edge_decision_ref  = "sha256:" + SHA-256(JCS({policy_ref, verdict, check, reason_code, subject_ref}))

The subject descriptor is **no-PII**: the client IP, agent DID, key id and wallet are hash-folded
(``ip_ref``/``did_ref``/``key_ref``/``wallet_ref``), while non-PII signals (country, ASN) stay in the
clear for audit value. So an edge decision proves WHICH policy blocked WHICH (hashed) subject for WHICH
reason, without the record carrying an identity. ``_prefixed`` is byte-identical to
``algovoi_substrate.sha256_jcs``.
"""
from __future__ import annotations

import hashlib

import rfc8785

__all__ = ["_prefixed", "policy_ref", "subject_ref", "edge_decision_ref", "build_descriptor"]


def _prefixed(value) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def policy_ref(policy_snapshot: dict) -> str:
    """Content address of the policy in force (pinnable, rotation-detectable)."""
    return _prefixed(policy_snapshot)


def build_descriptor(*, ip: str | None = None, country: str | None = None, asn: int | None = None,
                     agent_did: str | None = None, key_id: str | None = None,
                     wallet: str | None = None) -> dict:
    """A no-PII subject descriptor: identities hash-folded, geo signals in the clear."""
    d: dict = {}
    if ip:
        d["ip_ref"] = _prefixed(ip)
    if country:
        d["country"] = country
    if asn is not None:
        d["asn"] = asn
    if agent_did:
        d["did_ref"] = _prefixed(agent_did)
    if key_id:
        d["key_ref"] = _prefixed(key_id)
    if wallet:
        d["wallet_ref"] = _prefixed(wallet)
    return d


def subject_ref(descriptor: dict) -> str:
    return _prefixed(descriptor)


def edge_decision_ref(*, policy_ref_: str, decision: str, check: str,
                      reason_code: str, subject_ref_: str) -> str:
    return _prefixed({"policy_ref": policy_ref_, "verdict": decision, "check": check,
                      "reason_code": reason_code, "subject_ref": subject_ref_})
