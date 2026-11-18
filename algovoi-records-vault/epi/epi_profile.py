"""AlgoVoi `.epi` PQC profile — emit a Records Vault evidence pack as a portable `.epi` artifact.

This is a *profile/adapter* for the `.epi` portable-compliance-evidence format
(microsoft/agent-governance-toolkit Discussion #806; epilabs.org). It keeps `.epi`'s structure and
semantics — ``manifest.json`` (``sha256`` / ``files`` / ``signature``), a hash-linked ``steps.jsonl``
(``← prev``), DID:WEB identity, SHA-256 hashing, RFC 8785 (JCS) canonicalization, and the five
verification checks — and adds ONE thing: an **optional post-quantum signature suite**, ``falcon1024``,
alongside the spec's classical ``ed25519``. Records kept for the decades-long audit windows ``.epi``
targets outlive Ed25519's safety margin; Falcon-1024 (NIST FN-DSA) + a key-lineage block keep them
verifiable past the PQC migration.

Signature string format mirrors the spec: ``<suite>:<kid>:<b64url-sig>`` (e.g. ``falcon1024:6edb…:AbC…``).
The signature covers the JCS bytes of the manifest with its own ``signature`` field removed.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

import rfc8785

from algovoi_doc_archive import signing

SCHEMA = "algovoi-epi-pqc/0.1"
SUITE = "falcon1024"


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _step_hash(step: dict) -> str:
    return "sha256:" + _sha256_hex(rfc8785.dumps(step))


def build_steps(streams: dict[str, list[str]]) -> list[dict]:
    """Flatten the vault's signed streams into one hash-linked `.epi` ``steps.jsonl`` timeline.

    Each step references the underlying signed vault receipt by ``evidence_hash`` (so a verifier can
    cross-check it against the original) and links to the prior step via ``prev`` (the spec's ``← prev``).
    """
    steps: list[dict] = []
    prev: str | None = None
    seq = 0
    for stream_name in sorted(streams):
        for env in streams[stream_name]:
            payload, _sig, _kid = signing.open_envelope(env)
            step = {
                "seq": seq,
                "stream": stream_name,
                "type": payload.get("type"),
                "evidence_hash": signing.payload_hash(payload),  # links to the signed vault receipt
                "recorded_at": payload.get("recorded_at") or payload.get("archived_at"),
                "prev": prev,
            }
            prev = _step_hash(step)
            steps.append(step)
            seq += 1
    return steps


def export_epi(*, streams: dict[str, list[str]], public_key: bytes, secret_key: bytes,
               out_dir: str, control_mapping: dict | None = None,
               issuer_did: str = "did:web:issuer.example.com",
               artifact_id: str = "urn:algovoi:epi:demo",
               created_at: str | None = None,
               generator: str = "algovoi-records-vault") -> dict:
    """Write a `.epi`-profile artifact directory and return its manifest. Signs with Falcon-1024."""
    os.makedirs(out_dir, exist_ok=True)
    created_at = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # steps.jsonl (hash-linked)
    steps = build_steps(streams)
    steps_path = os.path.join(out_dir, "steps.jsonl")
    with open(steps_path, "w", encoding="utf-8") as fh:
        for s in steps:
            fh.write(json.dumps(s, separators=(",", ":"), sort_keys=True) + "\n")

    # control_mapping.json (framework → requirement → coverage), default = empty
    cm_path = os.path.join(out_dir, "control_mapping.json")
    with open(cm_path, "w", encoding="utf-8") as fh:
        json.dump(control_mapping or {"mappings": []}, fh, separators=(",", ":"), sort_keys=True)

    # public_key.b64 + verification.md
    pk_path = os.path.join(out_dir, "public_key.b64")
    with open(pk_path, "w", encoding="utf-8") as fh:
        fh.write(signing.public_key_b64(public_key))
    _write_verification_md(out_dir)

    # manifest.json — files + steps head + Falcon-1024 signature over the JCS(manifest sans signature)
    files = []
    for name in ("steps.jsonl", "control_mapping.json", "public_key.b64", "verification.md"):
        files.append({"name": name, "sha256": _sha256_file(os.path.join(out_dir, name))})
    kid = signing.kid_for(public_key)
    manifest = {
        "schema_version": SCHEMA,
        "artifact_id": artifact_id,
        "generator": generator,
        "created_at": created_at,
        "issuer_did": issuer_did,
        "canonicalization": "RFC 8785 (JCS)",
        "signature_suite": SUITE,
        "hash_alg": "SHA-256",
        "kid": kid,
        "files": files,
        "steps_count": len(steps),
        "steps_head": (steps[-1] and _step_hash(steps[-1])) if steps else None,
        "control_mapping_ref": "control_mapping.json",
    }
    sig = signing.sign_bytes(secret_key, rfc8785.dumps(manifest))
    manifest["signature"] = f"{SUITE}:{kid}:{signing.b64u_encode(sig)}"
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    return manifest


def _write_verification_md(out_dir: str) -> None:
    txt = """# Verify this .epi artifact (AlgoVoi PQC profile)

No AlgoVoi software required. Trust base = two public libraries:

    pip install pqcrypto rfc8785
    python algovoi_verify.py epi <this_directory>

Five checks (per the .epi model): Structure valid · Hashes match · Signature valid (Falcon-1024) ·
Chain intact (steps.jsonl) · SCITT anchored (optional). Exit 0 = all pass.
"""
    with open(os.path.join(out_dir, "verification.md"), "w", encoding="utf-8") as fh:
        fh.write(txt)


def control_mapping_for(streams: dict, edition: str | None = None) -> dict:
    """A starter control_mapping: which regulatory requirement each present stream evidences."""
    catalog = {
        "access": ("HIPAA", "164.312(b)", "audit controls — record/examine access"),
        "consent": ("HIPAA/GDPR", "164.508 / Art.6", "authorization / lawful basis"),
        "holds": ("FRCP/GDPR", "37(e) / Art.17(3)(e)", "litigation hold overrides erasure"),
        "tsa": ("eIDAS", "Art.42", "qualified electronic time stamp (evidence)"),
        "custody": ("FRCP", "chain-of-custody", "unbroken custody for admissibility"),
        "keyring": ("ETSI/NIST", "key lifecycle", "long-horizon key validity + rotation"),
        "redaction": ("GDPR/HIPAA", "Art.5(1)(c) / minimum-necessary", "data minimisation on disclosure"),
        "acl": ("ISO 27001", "A.9", "access control to records"),
    }
    mappings = []
    for name in sorted(streams):
        if name in catalog:
            fw, req, cov = catalog[name]
            mappings.append({"stream": name, "framework": fw, "requirement_id": req, "coverage": cov})
    return {"mappings": mappings, "edition": edition}
