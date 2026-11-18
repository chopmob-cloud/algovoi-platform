"""Compliance Gate → Compliance Command Center evidence export (bolt-in adapter).

Writes the gate's append-only decision ledger as a Falcon-1024 signed, hash-linked chain
in the common evidence-pack format the Command Center ingests offline (entry_type
``compliance_gate_verdict``). Drop it into the console's watched ingest dir, or hand it to
an auditor with the bundled standalone verifier — whose trust base is only ``pqcrypto`` +
``rfc8785`` and the published key (no AlgoVoi code required).

Pack layout (a directory):
    public_key.b64                 standard-base64 Falcon-1024 public key
    public_key_mldsa.b64           (only if the gate dual-signs) ML-DSA-65 public key
    compliance_gate_chain.json     JSON array of envelope strings (one per verdict)
    verify_compliance_gate_pack.py standalone offline verifier (pqcrypto + rfc8785)
"""
from __future__ import annotations

import base64
import json
import os

CHAIN_FILE = "compliance_gate_chain.json"


def export_evidence_pack(gate, out_dir: str) -> str:
    """Write a Command Center ingestable evidence pack from a gate's decision ledger
    (every :meth:`ComplianceGate.decide` call appends one verdict). Returns the pack dir."""
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
        json.dump(gate.envelopes, fh)
    with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(gate.pk).decode())
    if getattr(gate, "dual_sign", False) and gate.mldsa_pk is not None:
        with open(os.path.join(out_dir, "public_key_mldsa.b64"), "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(gate.mldsa_pk).decode())
    with open(os.path.join(out_dir, "verify_compliance_gate_pack.py"), "w", encoding="utf-8") as fh:
        fh.write(_VERIFIER_SRC)
    return out_dir


def verify_evidence_pack(pack_dir: str, *, policy_document: dict | None = None) -> dict:
    """In-process re-verification: Falcon signatures + the envelope chain + each verdict's
    internal ``policy_bound_ref`` consistency, and (if ``policy_document`` is supplied) that
    every ``policy_ref`` matches that policy. Returns a summary dict; ``verified`` is the gate."""
    import hashlib

    import substrate2
    from substrate2.pqc import verify_falcon_1024

    with open(os.path.join(pack_dir, "public_key.b64"), encoding="utf-8") as fh:
        pk = base64.b64decode(fh.read().strip())
    with open(os.path.join(pack_dir, CHAIN_FILE), encoding="utf-8") as fh:
        envelopes = json.load(fh)

    def b64u(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))

    want_policy_ref = substrate2.policy_ref(policy_document) if policy_document is not None else None
    prev = None
    n = 0
    for i, e in enumerate(envelopes):
        try:
            env = json.loads(b64u(e))
            payload, sig = env["payload"], b64u(env["sig"])
        except Exception:  # noqa: BLE001
            return {"verified": False, "reason": f"malformed_entry@{i}", "entries": i}
        if not verify_falcon_1024(pk, substrate2.canonicalize_bytes(payload), sig):
            return {"verified": False, "reason": f"bad_signature@{i}", "entries": i}
        if payload.get("type") != "compliance_gate_verdict" or payload.get("seq") != i:
            return {"verified": False, "reason": f"shape@{i}", "entries": i}
        if payload.get("prev_entry_hash") != prev:
            return {"verified": False, "reason": f"chain_break@{i}", "entries": i}
        recomputed = substrate2.policy_bound_ref(payload["subject_ref"], payload["policy_ref"])
        if recomputed != payload.get("policy_bound_ref"):
            return {"verified": False, "reason": f"policy_bound_mismatch@{i}", "entries": i}
        if want_policy_ref is not None and payload.get("policy_ref") != want_policy_ref:
            return {"verified": False, "reason": f"policy_rotated@{i}", "entries": i}
        prev = "sha256:" + hashlib.sha256(substrate2.canonicalize_bytes(payload)).hexdigest()
        n += 1
    return {"verified": True, "reason": "ok", "entries": n}


# Standalone verifier bundled into every pack. Trust base: pqcrypto + rfc8785 only — no
# AlgoVoi/substrate2 code, so an auditor needs nothing of ours to verify.
_VERIFIER_SRC = '''#!/usr/bin/env python3
"""Offline verifier for an AlgoVoi Compliance Gate evidence pack.
Trust base: pqcrypto + rfc8785 + a JSON parser. No AlgoVoi software required.

    pip install pqcrypto rfc8785
    python verify_compliance_gate_pack.py <pack_dir>

Checks, per verdict: Falcon-1024 signature valid · seq == index · hash-linked chain intact
· policy_bound_ref == SHA-256(JCS({policy_ref, subject_ref})) (rotation-detectable binding).
Exit 0 = all pass.
"""
import base64, hashlib, json, os, sys

import rfc8785
from pqcrypto.sign.falcon_1024 import verify as falcon_verify


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def sha256_jcs_prefixed(obj):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def main(pack):
    pk = base64.b64decode(open(os.path.join(pack, "public_key.b64")).read().strip())
    envelopes = json.load(open(os.path.join(pack, "compliance_gate_chain.json")))
    prev = None
    for i, e in enumerate(envelopes):
        env = json.loads(b64u(e))
        p, sig = env["payload"], b64u(env["sig"])
        assert falcon_verify(pk, rfc8785.dumps(p), sig), f"bad signature @{i}"
        assert p.get("seq") == i, f"seq mismatch @{i}"
        assert p.get("prev_entry_hash") == prev, f"chain break @{i}"
        assert sha256_jcs_prefixed({"policy_ref": p["policy_ref"], "subject_ref": p["subject_ref"]}) \\
            == p.get("policy_bound_ref"), f"policy_bound_ref mismatch @{i}"
        prev = sha256_jcs_prefixed(p)
    print(f"OK: {len(envelopes)} compliance-gate verdicts verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
'''


__all__ = ["export_evidence_pack", "verify_evidence_pack"]
