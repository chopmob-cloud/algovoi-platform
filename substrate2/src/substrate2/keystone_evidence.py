"""
substrate2.keystone_evidence — the WHOLE keystone lifecycle as one signed, hash-linked,
Compliance Command Center ingestable chain, plus a Records Vault custody batch binding.

Where ``execution_evidence`` renders the single execution tier, this renders the full lifecycle
(execution -> settlement binding -> refund -> capping trust verdict), each stage carrying its
recomputable keystone references, signed with Falcon-1024 (+ optional ML-DSA-65) and linked by
``prev_entry_hash``. Same envelope shape as the rest of the suite, entry type ``keystone_evidence``,
so one CCC instance verifies it with the same code path and folds it under the
"Keystone · full lifecycle" posture.

The open tier (algovoi-execution-ref / algovoi-pef-keystone / algovoi-keystone-verifier) produces
and verifies the content-addressed references; this commercial tier signs them for CCC + Vault.
"""
from __future__ import annotations

import base64
import json
import os

import rfc8785

from .digest import sha256_jcs
from . import pqc

ENTRY_TYPE = "keystone_evidence"
CHAIN_FILE = "keystone_evidence_chain.json"
CANON_VERSION = "jcs-rfc8785-v1"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _kid(public_key: bytes) -> str:
    return "sha256:" + sha256_jcs(_b64u(public_key))[:16]


def _prefixed(payload: dict) -> str:
    return "sha256:" + sha256_jcs(payload)


def _make_envelope(payload, falcon_sk, falcon_pk, mldsa_sk, mldsa_pk) -> str:
    msg = rfc8785.dumps(payload)
    env = {
        "payload": payload,
        "alg": pqc.SIGNATURE_ALGORITHM_IDENTIFIER,
        "kid": pqc.falcon_kid(falcon_pk),
        "sig": _b64u(pqc.sign_falcon_1024(falcon_sk, msg)),
    }
    if mldsa_sk is not None and mldsa_pk is not None:
        env["alg2"] = pqc.ML_DSA_65_ALGORITHM_IDENTIFIER
        env["kid2"] = _kid(mldsa_pk)
        env["sig2"] = _b64u(pqc.sign_ml_dsa_65(mldsa_sk, msg))
    return _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())


def keystone_evidence_cores(bundle: dict) -> list[dict]:
    """Build the ordered lifecycle entry bodies from a keystone bundle.

    bundle keys: execution_ref, decision_ref, action_type, scope, outcome, executed_at_ms,
    settlement_ref, retention_chain_ref, binding_ref, refund_ref, trust_query_ref, audit_cap,
    screen_ref, screen_binding_ref.
    Stages with no data are skipped, so a bare keystone (execution + cap) is valid too. When a
    compliance screen is present (screen_ref = the Compliance Receipt ref issued by the
    compliance tier), it leads the chain (screening precedes the decision) and binds to the
    decision via screen_binding_ref.
    """
    b = bundle
    cores: list[dict] = []
    if b.get("screen_ref"):
        cores.append({
            "stage": "compliance", "screen_ref": b["screen_ref"],
            "screen_binding_ref": b.get("screen_binding_ref"), "decision_ref": b["decision_ref"],
        })
    cores.append({
        "stage": "execution", "execution_ref": b["execution_ref"], "decision_ref": b["decision_ref"],
        "action_type": b["action_type"], "scope": b["scope"], "outcome": b["outcome"],
        "executed_at_ms": b["executed_at_ms"],
    })
    if b.get("settlement_ref") and b.get("binding_ref"):
        cores.append({"stage": "settlement", "binding_ref": b["binding_ref"], "execution_ref": b["execution_ref"],
                      "settlement_ref": b["settlement_ref"], "retention_chain_ref": b.get("retention_chain_ref")})
    if b.get("refund_ref"):
        cores.append({"stage": "refund", "refund_ref": b["refund_ref"], "subject_ref": b["execution_ref"]})
    cores.append({"stage": "cap", "trust_query_ref": b["trust_query_ref"], "audit_cap": b.get("audit_cap")})
    return cores


def build_keystone_evidence_chain(cores, falcon_secret_key, falcon_public_key,
                                  mldsa_secret_key=None, mldsa_public_key=None) -> list[str]:
    envelopes: list[str] = []
    prev = None
    for seq, core in enumerate(cores):
        payload = {"canon_version": CANON_VERSION, "type": ENTRY_TYPE, "seq": seq, "prev_entry_hash": prev, **core}
        envelopes.append(_make_envelope(payload, falcon_secret_key, falcon_public_key, mldsa_secret_key, mldsa_public_key))
        prev = _prefixed(payload)
    return envelopes


def export_keystone_evidence_pack(cores, out_dir, falcon_secret_key, falcon_public_key,
                                  mldsa_secret_key=None, mldsa_public_key=None) -> str:
    """Write a CCC-ingestable pack: keystone_evidence_chain.json + public_key.b64."""
    envelopes = build_keystone_evidence_chain(cores, falcon_secret_key, falcon_public_key, mldsa_secret_key, mldsa_public_key)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
        json.dump(envelopes, fh)
    with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(falcon_public_key).decode())
    return out_dir


def keystone_custody_binding(envelopes: list[str]) -> dict:
    """Records Vault custody batch binding over a keystone evidence chain: a stable batch_hash + range
    ready for CustodyLog.attest_batch / make_custody_attestation."""
    return {
        "batch_range": {"type": ENTRY_TYPE, "from": 0, "to": max(0, len(envelopes) - 1), "count": len(envelopes)},
        "batch_hash": "sha256:" + sha256_jcs({"chain": envelopes}),
    }


__all__ = [
    "ENTRY_TYPE", "CHAIN_FILE",
    "keystone_evidence_cores", "build_keystone_evidence_chain",
    "export_keystone_evidence_pack", "keystone_custody_binding",
]
