"""System Validation Evidence Pack for the console itself.

Builds a signed, offline-verifiable IQ/OQ/PQ validation evidence pack for the
Compliance Command Center, served at ``GET /validation/pack``. The pack proves
the console is installed correctly (IQ), operates to specification (OQ, the live
self-checks: the console audit chain verifies and every ingested evidence chain
re-verifies) and performs in production (PQ, the head of the console's
tamper-evident audit chain and the verified posture heads).

Same format and standalone verifier as the rest of the suite, signed with the
console's own ``Signer`` (local key today, HSM/KMS/Vault under phase f). It is
built fresh on every request, so the validation evidence is never stale, and it
adds no new trust model: it reuses machinery already proven on VM2.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import zipfile
from datetime import datetime, timezone

import rfc8785

SCHEMA = "algovoi-validation-pack/0.1"
SUITE = "falcon1024"
_VERIFIER = "verify_validation_pack.py"

_VERIFY_MD = """# Verify this System Validation Evidence Pack

No AlgoVoi software is required. The trust base is two public libraries and the
published public key in this archive.

    pip install pqcrypto rfc8785
    python verify_validation_pack.py .

Three checks: the manifest carries a valid Falcon-1024 signature over the
canonical (RFC 8785) manifest; every file's SHA-256 matches what that signature
commits to; the IQ, OQ and PQ sections are well formed. Exit code 0 means every
check passed and the validation evidence is genuine and unaltered.
"""


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _control_mapping() -> dict:
    return {"mappings": [
        {"section": "IQ", "framework": "FDA 21 CFR Part 11", "requirement_id": "11.10(a)",
         "coverage": "Installation Qualification: console component versions, signed"},
        {"section": "OQ", "framework": "FDA 21 CFR Part 11", "requirement_id": "11.10(a)",
         "coverage": "Operational Qualification: live self-checks (audit-chain integrity + evidence re-verification)"},
        {"section": "PQ", "framework": "FDA 21 CFR Part 11", "requirement_id": "11.10(a)",
         "coverage": "Performance Qualification: console audit-chain head + verified posture heads"},
        {"section": "ALL", "framework": "ALCOA+", "requirement_id": "Original/Accurate/Enduring",
         "coverage": "Falcon-1024 signed, JCS-canonical, offline-verifiable"},
        {"section": "PQ", "framework": "SOC 2", "requirement_id": "CC7",
         "coverage": "continuous integrity attestation of the console of record"},
    ]}


def build_pack_bytes(iq: dict, oq: dict, pq: dict, signer, control_mapping: dict | None = None) -> bytes:
    """Build the validation pack in memory and return a zip blob ready to serve.

    ``signer`` is the console ``Signer`` (``sign``/``public_key``/``kid``).
    """
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verifier_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), _VERIFIER)
    with open(verifier_path, "rb") as fh:
        verifier_src = fh.read()

    files: dict[str, bytes] = {
        "iq.json": json.dumps({"section": "IQ", **iq}, indent=2, sort_keys=True).encode(),
        "oq.json": json.dumps({"section": "OQ", **oq}, indent=2, sort_keys=True).encode(),
        "pq.json": json.dumps({"section": "PQ", **pq}, indent=2, sort_keys=True).encode(),
        "control_mapping.json": json.dumps(control_mapping or _control_mapping(), indent=2, sort_keys=True).encode(),
        "public_key.b64": base64.b64encode(signer.public_key()),
        _VERIFIER: verifier_src,
        "VERIFY.md": _VERIFY_MD.encode(),
    }
    file_list = [{"name": n, "sha256": hashlib.sha256(b).hexdigest()} for n, b in files.items()]

    manifest = {
        "schema_version": SCHEMA, "artifact_id": "urn:algovoi:validation:command-center",
        "generator": "algovoi-command-center", "created_at": created_at,
        "canonicalization": "RFC 8785 (JCS)", "signature_suite": SUITE, "hash_alg": "SHA-256",
        "kid": signer.kid(), "sections": ["iq.json", "oq.json", "pq.json"],
        "files": file_list, "control_mapping_ref": "control_mapping.json",
    }
    sig = signer.sign(rfc8785.dumps(manifest))
    manifest["signature"] = f"{SUITE}:{signer.kid()}:{_b64u(sig)}"
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            z.writestr(name, files[name])
    return buf.getvalue()


def build_ccc_validation_pack(signer, audit, posture) -> bytes:
    """Gather the console's live IQ/OQ/PQ and return a served validation-pack zip.

    IQ from component versions, OQ from live self-checks (the console audit chain
    re-verifies, every ingested evidence chain re-verifies), PQ from the audit
    chain head and the verified posture heads. Built fresh, so never stale.
    """
    from algovoi_command_center import __version__
    from algovoi_command_center.engine import verify_chain

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    audit_res = verify_chain(audit.chain(), signer.public_key())
    verified_chains = sum(1 for c in posture.chains if c.verified)

    iq = {"component_versions": {"algovoi-command-center": __version__}, "installed_at": now}
    oq = {"suites": [
        {"name": "console_audit_chain_integrity", "total": 1,
         "passed": 1 if audit_res.verified else 0, "failed": 0 if audit_res.verified else 1,
         "run_at": now, "result_digest": "head:" + str(audit_res.head)},
        {"name": "evidence_posture_verification", "total": len(posture.chains),
         "passed": verified_chains, "failed": len(posture.chains) - verified_chains,
         "run_at": now, "result_digest": "estate:" + str(posture.estate)},
    ]}
    pq = {"integrity_attestation": {"chain": "command_center_console_audit",
                                    "head": audit_res.head, "rows": audit_res.entries,
                                    "attested_at": now},
          "posture_chains": [{"name": c.name, "head": c.head, "verified": c.verified}
                             for c in posture.chains]}
    return build_pack_bytes(iq, oq, pq, signer)
