"""Sanctions Monitor to Compliance Command Center evidence export (bolt-in adapter).

Wraps the monitor's signed screening deltas into a hash-linked chain in the common
evidence-pack format the Compliance Command Center ingests offline. This is the
bolt-in: Sanctions Monitor becomes one more verified stream in the hub, alongside
Records Vault and Recovery Vault, with no change to the console.

Each delta the monitor signs (a counterparty's verdict change: newly_hit, cleared,
escalated, de-escalated) becomes one entry in a Falcon-1024 signed, hash-linked
chain. Each entry carries the no-PII ``subject_ref`` and the transition, and links
to the underlying signed delta receipt by ``receipt_hash`` so a verifier can cross
check it against the monitor's own receipt. The chain is tamper-evident and
verifiable offline with only ``pqcrypto`` and ``rfc8785`` and the published key.

The output is a directory with ``sanctions_screening_chain.json`` and
``public_key.b64``. Drop it into the console's watched ingest directory, or hand
it to an auditor with the standalone verifier.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone

import substrate2

from algovoi_doc_archive import signing

ENTRY_TYPE = "sanctions_screening_delta"
CHAIN_FILE = "sanctions_screening_chain.json"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _payload_hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(substrate2.canonicalize_bytes(payload)).hexdigest()


def _envelope(payload: dict, secret_key: bytes, kid: str) -> str:
    sig = signing.sign_bytes(secret_key, substrate2.canonicalize_bytes(payload))
    return _b64u(json.dumps({"payload": payload, "sig": _b64u(sig), "kid": kid}).encode())


def export_evidence_pack(deltas: list[dict], out_dir: str, *, public_key: bytes | None = None,
                         secret_key: bytes | None = None, attested_at: str | None = None) -> str:
    """Write a Command Center ingestable evidence pack from the monitor's signed
    deltas (the ``list[dict]`` returned by ``SanctionsMonitor.sweep``). Returns the
    pack directory.

    Pass a stable ``public_key``/``secret_key`` to keep the published evidence key
    constant across exports, or omit to mint a fresh pair (useful for tests).
    """
    if public_key is None or secret_key is None:
        public_key, secret_key = signing.generate_keypair()
        if len(public_key) != signing.PUBLIC_KEY_BYTES:
            public_key, secret_key = secret_key, public_key
    kid = signing.kid_for(public_key)
    attested_at = attested_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # oldest-first so seq increases with screening time
    ordered = sorted(deltas, key=lambda d: d.get("receipt", {}).get("screen_timestamp_ms", 0))

    os.makedirs(out_dir, exist_ok=True)
    chain: list[str] = []
    prev: str | None = None
    for i, dlt in enumerate(ordered):
        r = dlt.get("receipt", {})
        payload = {
            "type": ENTRY_TYPE, "seq": i, "prev_entry_hash": prev,
            "subject_ref": dlt.get("subject_ref"),
            "transition": dlt.get("transition"),
            "prior_result": r.get("prior_result"),
            "new_result": r.get("new_result"),
            "receipt_hash": dlt.get("receipt_hash"),
            "screen_timestamp_ms": r.get("screen_timestamp_ms"),
            "monitor_run_id": r.get("monitor_run_id"),
            "attested_at": attested_at,
        }
        chain.append(_envelope(payload, secret_key, kid))
        prev = _payload_hash(payload)

    with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
        json.dump(chain, fh)
    with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(public_key).decode())
    return out_dir
