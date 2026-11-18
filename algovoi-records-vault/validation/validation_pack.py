"""AlgoVoi System Validation Evidence Pack, collector.

Emits a signed, offline-verifiable IQ/OQ/PQ validation evidence pack using the
same format as the Records Vault ``.epi`` evidence packs: a ``manifest.json``
whose per-file SHA-256 hashes are committed by a Falcon-1024 signature over the
JCS bytes of the manifest (its own ``signature`` field removed). The pack is
self-describing and ships its own standalone verifier.

The pack answers three questions, the IQ/OQ/PQ of computerised-system
validation:

  IQ  installation qualification, the system is installed as specified
      (component versions, optional CycloneDX SBOM, configuration fingerprint).
  OQ  operational qualification, the system operates to specification
      (conformance and test-suite results, captured and signed).
  PQ  performance qualification, the system performs in production
      (the head of the tamper-evident integrity-attestation chain).

This is the free, control-plane-standard answer to FDA 21 CFR Part 11
section 11.10(a) system validation and to ALCOA+ data integrity: validation
evidence generated and signed by the system itself, kept current, and checkable
by anyone offline with two public libraries and the published public key.

It carries no AlgoVoi business logic of its own. It is a thin assembler over
``algovoi_doc_archive.signing`` and the data its callers gather. See
``adapters.py`` for the standalone Records Vault and control-plane collectors.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone

import rfc8785

from algovoi_doc_archive import signing

SCHEMA = "algovoi-validation-pack/0.1"
SUITE = "falcon1024"
SECTIONS = ("iq.json", "oq.json", "pq.json")
VERIFIER = "verify_validation_pack.py"


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)


def default_control_mapping() -> dict:
    """Starter mapping: which control each IQ/OQ/PQ section evidences. Override
    per vertical (this default is tuned to pharma 21 CFR Part 11 and ALCOA+)."""
    return {
        "mappings": [
            {"section": "IQ", "framework": "FDA 21 CFR Part 11", "requirement_id": "11.10(a)",
             "coverage": "Installation Qualification: component versions, SBOM and configuration fingerprint, signed"},
            {"section": "OQ", "framework": "FDA 21 CFR Part 11", "requirement_id": "11.10(a)",
             "coverage": "Operational Qualification: conformance and test-suite results, captured and signed"},
            {"section": "PQ", "framework": "FDA 21 CFR Part 11", "requirement_id": "11.10(a)",
             "coverage": "Performance Qualification: production integrity-attestation chain head"},
            {"section": "ALL", "framework": "ALCOA+", "requirement_id": "Original/Accurate/Enduring",
             "coverage": "Falcon-1024 signed, JCS-canonical, offline-verifiable evidence"},
            {"section": "PQ", "framework": "SOC 2", "requirement_id": "CC7",
             "coverage": "continuous integrity attestation of the system of record"},
        ]
    }


def build_validation_pack(
    *,
    iq: dict,
    oq: dict,
    pq: dict,
    out_dir: str,
    signer=None,
    public_key: bytes | None = None,
    secret_key: bytes | None = None,
    control_mapping: dict | None = None,
    artifact_id: str = "urn:algovoi:validation:demo",
    generator: str = "algovoi-records-vault",
    created_at: str | None = None,
    include_verifier: bool = True,
) -> dict:
    """Write a System Validation Evidence Pack directory and return its manifest.

    The three section dicts are stamped with their ``section`` marker, written
    out, hashed, and committed by a Falcon-1024 signature on the manifest. The
    standalone verifier and a VERIFY.md are bundled by default so the directory
    is a self-contained, auditor-ready artifact.

    Signing accepts either a ``signer`` with ``sign(bytes) -> bytes``,
    ``public_key() -> bytes`` and ``kid() -> str`` (the Command Center ``Signer``
    protocol, which also covers the HSM/KMS/Vault path), or a raw
    ``public_key`` plus ``secret_key`` pair.
    """
    os.makedirs(out_dir, exist_ok=True)
    created_at = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if signer is not None:
        public_key = signer.public_key()
        kid = signer.kid()
        _sign = signer.sign
    else:
        if public_key is None or secret_key is None:
            raise ValueError("provide signer=, or both public_key= and secret_key=")
        kid = signing.kid_for(public_key)

        def _sign(msg: bytes) -> bytes:
            return signing.sign_bytes(secret_key, msg)

    sections = {
        "iq.json": {"section": "IQ", **iq},
        "oq.json": {"section": "OQ", **oq},
        "pq.json": {"section": "PQ", **pq},
    }
    for name, obj in sections.items():
        _write_json(os.path.join(out_dir, name), obj)
    _write_json(os.path.join(out_dir, "control_mapping.json"),
                control_mapping or default_control_mapping())

    with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(signing.public_key_b64(public_key))

    file_names = ["iq.json", "oq.json", "pq.json", "control_mapping.json", "public_key.b64"]
    if include_verifier:
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), VERIFIER)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(out_dir, VERIFIER))
            _write_verify_md(out_dir)
            file_names += [VERIFIER, "VERIFY.md"]

    files = [{"name": n, "sha256": _sha256_file(os.path.join(out_dir, n))}
             for n in file_names if os.path.exists(os.path.join(out_dir, n))]
    manifest = {
        "schema_version": SCHEMA,
        "artifact_id": artifact_id,
        "generator": generator,
        "created_at": created_at,
        "canonicalization": "RFC 8785 (JCS)",
        "signature_suite": SUITE,
        "hash_alg": "SHA-256",
        "kid": kid,
        "sections": list(SECTIONS),
        "files": files,
        "control_mapping_ref": "control_mapping.json",
    }
    sig = _sign(rfc8785.dumps(manifest))
    manifest["signature"] = f"{SUITE}:{kid}:{signing.b64u_encode(sig)}"
    _write_json(os.path.join(out_dir, "manifest.json"), manifest)
    return manifest


def _write_verify_md(out_dir: str) -> None:
    txt = """# Verify this System Validation Evidence Pack

No AlgoVoi software is required. The trust base is two public libraries and the
published public key in this directory.

    pip install pqcrypto rfc8785
    python verify_validation_pack.py .

Three checks: the manifest carries a valid Falcon-1024 signature over the
canonical (RFC 8785) manifest; every file's SHA-256 matches what that signature
commits to; the IQ, OQ and PQ sections are well formed. Exit code 0 means every
check passed and the validation evidence is genuine and unaltered.
"""
    with open(os.path.join(out_dir, "VERIFY.md"), "w", encoding="utf-8") as fh:
        fh.write(txt)
