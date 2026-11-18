"""Self-test for the System Validation Evidence Pack.

Builds a pack from synthetic IQ/OQ/PQ evidence, verifies it with the bundled
standalone verifier (in a subprocess, exactly as an auditor would), then proves
the verifier rejects two kinds of tamper: an edited section file and an edited
manifest. Exit 0 iff the honest pack verifies and both tampers are caught.

Run:  python selftest.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

from algovoi_doc_archive import signing

from validation_pack import build_validation_pack


def _keypair():
    a, b = signing.generate_keypair()
    # Normalise (public_key, secret_key) regardless of the wrapper's order.
    return (a, b) if len(a) == signing.PUBLIC_KEY_BYTES else (b, a)


def _sample_evidence():
    iq = {
        "component_versions": {"records_vault": "0.4.1", "algovoi_doc_archive": "0.1.1"},
        "sbom_ref": "artifacts/sbom.cdx.json",
        "config_fingerprint": "sha256:7f3a...e91",
        "installed_at": "2026-06-15T00:00:00Z",
    }
    oq = {
        "suites": [
            {"name": "records_vault", "total": 283, "passed": 283, "failed": 0,
             "run_at": "2026-06-15T01:00:00Z", "result_digest": "sha256:aa11...22bb"},
            {"name": "jcs_conformance_vectors", "total": 77, "passed": 77, "failed": 0,
             "run_at": "2026-06-15T01:05:00Z", "result_digest": "sha256:cc33...44dd"},
        ],
    }
    pq = {
        "integrity_attestation": {
            "chain": "control_plane_audit",
            "head": "sha256:deadbeefcafef00d1234567890abcdef",
            "rows": 10421,
            "attested_at": "2026-06-15T02:00:00Z",
        },
        "health": {"status": "ok"},
    }
    return iq, oq, pq


def _verify(pack_dir: str) -> int:
    verifier = os.path.join(pack_dir, "verify_validation_pack.py")
    return subprocess.run([sys.executable, verifier, pack_dir]).returncode


def main() -> int:
    pk, sk = _keypair()
    iq, oq, pq = _sample_evidence()
    failures = 0

    with tempfile.TemporaryDirectory() as root:
        pack = os.path.join(root, "validation-pack")
        build_validation_pack(iq=iq, oq=oq, pq=pq, public_key=pk, secret_key=sk,
                              out_dir=pack, artifact_id="urn:algovoi:validation:selftest")

        print("\n--- 1. honest pack should verify ---")
        if _verify(pack) != 0:
            print("UNEXPECTED: honest pack failed verification"); failures += 1

        print("\n--- 2. edited OQ section should be caught ---")
        oq_path = os.path.join(pack, "oq.json")
        data = json.load(open(oq_path, encoding="utf-8"))
        data["suites"][0]["failed"] = 0
        data["suites"][0]["passed"] = 999  # forge a better result
        json.dump(data, open(oq_path, "w", encoding="utf-8"), indent=2, sort_keys=True)
        if _verify(pack) == 0:
            print("UNEXPECTED: edited section passed verification"); failures += 1
        else:
            print("(correctly rejected)")

        print("\n--- 3. edited manifest should be caught ---")
        # Rebuild a clean pack, then tamper the manifest signature payload.
        build_validation_pack(iq=iq, oq=oq, pq=pq, public_key=pk, secret_key=sk, out_dir=pack)
        man_path = os.path.join(pack, "manifest.json")
        man = json.load(open(man_path, encoding="utf-8"))
        man["generator"] = "forged-generator"  # changes signed bytes, signature now stale
        json.dump(man, open(man_path, "w", encoding="utf-8"), indent=2, sort_keys=True)
        if _verify(pack) == 0:
            print("UNEXPECTED: edited manifest passed verification"); failures += 1
        else:
            print("(correctly rejected)")

    print("\n" + "=" * 50)
    print("SELFTEST:", "PASS" if failures == 0 else f"FAIL ({failures} unexpected)")
    print("=" * 50)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
