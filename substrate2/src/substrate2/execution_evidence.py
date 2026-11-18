"""
substrate2.execution_evidence — signed, hash-linked execution-evidence chain.

The post-decision tier of the keystone, rendered as a Compliance Command Center
ingestable chain. Same envelope + hashing shape as the rest of the suite
(``{"payload","alg":"Falcon-1024","kid","sig"}``, optional ML-DSA-65 co-signature,
``prev_entry_hash = "sha256:"+SHA-256(JCS(payload))``), entry type
``execution_evidence``, so one CCC instance verifies it with the same code path
as edge/guard/decision/settlement chains.

Each entry carries the execution_ref and the exact decision_ref it was executed
under, so the chain proves every executed action is consistent with the decision
that authorized it. Altering or dropping one entry breaks the chain from that
point on. No raw agent_id appears (it is bound inside decision_ref) -> no-PII.
"""
from __future__ import annotations

import base64
import json
import os

import rfc8785

from .digest import sha256_jcs
from .execution import execution_ref, execution_ref_object
from . import pqc

ENTRY_TYPE = "execution_evidence"
CHAIN_FILE = "execution_evidence_chain.json"
CANON_VERSION = "jcs-rfc8785-v1"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _kid(public_key: bytes) -> str:
    return "sha256:" + sha256_jcs(_b64u(public_key))[:16]


def _prefixed(payload: dict) -> str:
    return "sha256:" + sha256_jcs(payload)


def _make_envelope(payload: dict, falcon_sk: bytes, falcon_pk: bytes,
                   mldsa_sk: bytes | None, mldsa_pk: bytes | None) -> str:
    msg = rfc8785.dumps(payload)
    env = {
        "payload": payload,
        "alg": pqc.SIGNATURE_ALGORITHM_IDENTIFIER,           # "Falcon-1024"
        "kid": pqc.falcon_kid(falcon_pk),
        "sig": _b64u(pqc.sign_falcon_1024(falcon_sk, msg)),
    }
    if mldsa_sk is not None and mldsa_pk is not None:
        env["alg2"] = pqc.ML_DSA_65_ALGORITHM_IDENTIFIER     # "ML-DSA-65"
        env["kid2"] = _kid(mldsa_pk)
        env["sig2"] = _b64u(pqc.sign_ml_dsa_65(mldsa_sk, msg))
    return _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())


def execution_evidence_core(decision_ref: str, action_type: str, scope: str,
                            outcome: str, executed_at_ms: int) -> dict:
    """Build one execution-evidence entry body (carries the recomputable execution_ref)."""
    obj = execution_ref_object(decision_ref, action_type, scope, outcome, executed_at_ms)
    return {
        **obj,
        "execution_ref": execution_ref(decision_ref, action_type, scope, outcome, executed_at_ms),
    }


def build_execution_evidence_chain(
    cores: list[dict],
    falcon_secret_key: bytes,
    falcon_public_key: bytes,
    mldsa_secret_key: bytes | None = None,
    mldsa_public_key: bytes | None = None,
) -> list[str]:
    """Return the list of signed, hash-linked CCC envelopes for the given cores."""
    envelopes: list[str] = []
    prev: str | None = None
    for seq, core in enumerate(cores):
        payload = {
            "canon_version": CANON_VERSION,
            "type": ENTRY_TYPE,
            "seq": seq,
            "prev_entry_hash": prev,
            **core,
        }
        envelopes.append(_make_envelope(
            payload, falcon_secret_key, falcon_public_key,
            mldsa_secret_key, mldsa_public_key,
        ))
        prev = _prefixed(payload)
    return envelopes


def export_execution_evidence_pack(
    cores: list[dict],
    out_dir: str,
    falcon_secret_key: bytes,
    falcon_public_key: bytes,
    mldsa_secret_key: bytes | None = None,
    mldsa_public_key: bytes | None = None,
) -> str:
    """Write a CCC-ingestable pack: execution_evidence_chain.json + public_key.b64."""
    envelopes = build_execution_evidence_chain(
        cores, falcon_secret_key, falcon_public_key,
        mldsa_secret_key, mldsa_public_key,
    )
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
        json.dump(envelopes, fh)
    with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(falcon_public_key).decode())
    return out_dir


__all__ = [
    "ENTRY_TYPE",
    "CHAIN_FILE",
    "execution_evidence_core",
    "build_execution_evidence_chain",
    "export_execution_evidence_pack",
]
