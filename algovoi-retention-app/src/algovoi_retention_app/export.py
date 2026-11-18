"""Retention evidence pack export.

Emits a Falcon-1024 signed, hash-linked evidence pack that is simultaneously:
  * the regulator pack (a signed, offline-verifiable record of the retention
    chains, with a bundled standalone verifier), and
  * a Compliance Command Center ingestable pack (entry_type
    ``retention_chain_link``), so the same artefact lights up the CCC console
    posture with no CCC change beyond a one-line type label.

Pack layout (a directory):
    public_key.b64        standard-base64 Falcon-1024 public key
    retention_chain.json  JSON array of envelope strings (one per record)
    verify_retention_pack.py  standalone offline verifier (pqcrypto + rfc8785)

Each envelope payload carries the CCC integrity fields (``type``, ``seq``,
``prev_entry_hash``) plus the retention data under non-colliding keys, so CCC's
generic chain verifier and a deep retention re-verifier both work:

    {
      "type": "retention_chain_link",
      "seq": <int>,                       # envelope index in this pack chain
      "prev_entry_hash": <"sha256:..."|null>,  # links the envelope chain
      "issuer_id": <str>,
      "chain_seq": <int>,                 # retention chain position (per issuer)
      "receipt_hash": "sha256:...",
      "retention_prev_receipt_hash": "sha256:..."|"",
      "retention_chain_ref": "sha256:...",
      "reg_basis": ["MiCA-80","DORA-14","AMLR-56"],
      "attested_at": "<iso8601Z>"
    }
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from algovoi_retention_app import ENTRY_TYPE, REG_BASIS
from algovoi_retention_app.signing import LocalSigner, payload_hash


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_payloads(records: list, *, attested_at: str | None = None) -> list[dict]:
    """Build the ordered envelope payloads (pre-signing) for the given records.

    ``records`` are RetentionRecord (or dicts with the same fields), in the order
    they should appear in the pack chain. ``seq`` is the envelope index and
    ``prev_entry_hash`` links each payload to the prior payload's hash.
    """
    at = attested_at or _now()
    payloads: list[dict] = []
    prev_entry_hash: str | None = None
    for i, r in enumerate(records):
        d = r.as_dict() if hasattr(r, "as_dict") else dict(r)
        payload = {
            "type": ENTRY_TYPE,
            "seq": i,
            "prev_entry_hash": prev_entry_hash,
            "issuer_id": d["issuer_id"],
            "chain_seq": d["chain_seq"],
            "receipt_hash": d["receipt_hash"],
            "retention_prev_receipt_hash": d["prev_receipt_hash"],
            "retention_chain_ref": d["chain_ref"],
            "reg_basis": REG_BASIS,
            "attested_at": at,
        }
        payloads.append(payload)
        prev_entry_hash = payload_hash(payload)
    return payloads


def build_retention_pack(records: list, signer: LocalSigner, out_dir: str,
                         *, attested_at: str | None = None) -> str:
    """Write a signed retention evidence pack to ``out_dir``. Returns out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    payloads = build_payloads(records, attested_at=attested_at)
    envelopes = [signer.envelope(p) for p in payloads]

    with open(os.path.join(out_dir, "retention_chain.json"), "w", encoding="utf-8") as fh:
        json.dump(envelopes, fh, indent=2)
    with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(signer.public_key_b64())
    with open(os.path.join(out_dir, "verify_retention_pack.py"), "w", encoding="utf-8") as fh:
        fh.write(_VERIFIER_SRC)
    return out_dir


def verify_retention_pack(pack_dir: str) -> dict:
    """In-process re-verification of a pack (signatures + envelope chain + each
    retention_chain_ref). Returns a summary dict; ``verified`` is the gate."""
    import base64

    import substrate2
    from substrate2.pqc import verify_falcon_1024 as falcon_verify

    from algovoi_retention_chain import retention_chain_ref

    with open(os.path.join(pack_dir, "public_key.b64"), encoding="utf-8") as fh:
        pk = base64.b64decode(fh.read().strip())
    with open(os.path.join(pack_dir, "retention_chain.json"), encoding="utf-8") as fh:
        envelopes = json.load(fh)

    def b64u(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))

    import hashlib

    prev: str | None = None
    n = 0
    issuers: set[str] = set()
    for i, e in enumerate(envelopes):
        try:
            env = json.loads(b64u(e))
            payload, sig = env["payload"], b64u(env["sig"])
        except Exception:  # noqa: BLE001 -- a malformed entry is "not verified", not a crash
            return {"verified": False, "reason": f"malformed_entry@{i}", "entries": i}
        if not falcon_verify(pk, substrate2.canonicalize_bytes(payload), sig):
            return {"verified": False, "reason": f"bad_signature@{i}", "entries": i}
        if payload.get("seq") != i:
            return {"verified": False, "reason": f"seq_mismatch@{i}", "entries": i}
        if payload.get("prev_entry_hash") != prev:
            return {"verified": False, "reason": f"chain_break@{i}", "entries": i}
        recomputed = retention_chain_ref(
            prev_receipt_hash=payload["retention_prev_receipt_hash"],
            receipt_hash=payload["receipt_hash"],
            chain_seq=payload["chain_seq"],
            issuer_id=payload["issuer_id"],
        )
        if recomputed != payload["retention_chain_ref"]:
            return {"verified": False, "reason": f"retention_ref_mismatch@{i}", "entries": i}
        prev = substrate2.sha256_jcs_prefixed(payload)
        issuers.add(payload["issuer_id"])
        n += 1
    return {"verified": True, "reason": "ok", "entries": n, "issuers": sorted(issuers)}


# Standalone verifier bundled into every pack. Trust base: pqcrypto + rfc8785
# + algovoi-retention-chain only. No AlgoVoi service, no network.
_VERIFIER_SRC = '''#!/usr/bin/env python3
"""Offline verifier for an AlgoVoi retention evidence pack.

    pip install pqcrypto rfc8785 algovoi-retention-chain
    python verify_retention_pack.py [pack_dir]

Exit 0 iff every signature, envelope link and retention_chain_ref reproduces.
"""
import base64, hashlib, json, os, sys

import rfc8785
from pqcrypto.sign.falcon_1024 import verify as falcon_verify
from algovoi_retention_chain import retention_chain_ref


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def main(d):
    with open(os.path.join(d, "public_key.b64")) as fh:
        pk = base64.b64decode(fh.read().strip())
    with open(os.path.join(d, "retention_chain.json")) as fh:
        envelopes = json.load(fh)
    prev = None
    for i, e in enumerate(envelopes):
        env = json.loads(b64u(e))
        p, sig = env["payload"], b64u(env["sig"])
        assert falcon_verify(pk, rfc8785.dumps(p), sig), f"bad signature @{i}"
        assert p["seq"] == i, f"seq mismatch @{i}"
        assert p.get("prev_entry_hash") == prev, f"chain break @{i}"
        assert retention_chain_ref(
            prev_receipt_hash=p["retention_prev_receipt_hash"],
            receipt_hash=p["receipt_hash"], chain_seq=p["chain_seq"],
            issuer_id=p["issuer_id"]) == p["retention_chain_ref"], f"chain_ref @{i}"
        prev = "sha256:" + hashlib.sha256(rfc8785.dumps(p)).hexdigest()
    print(f"VERIFIED {len(envelopes)} entries OFFLINE")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
'''
