"""algovoi-records-vault-epi: .epi export + offline-verify (standalone, runnable).

Builds signed vault-style streams, exports a `.epi` PQC-profile artifact, then proves the bundled
redistributable offline verifier accepts a good artifact and rejects a tampered one. Fully offline;
the runtime licence gate is bypassed for the test the same way the rest of the suite does.

Run: python algovoi-records-vault-epi/tests/test_epi_export.py   (needs pqcrypto + rfc8785 + substrate2)
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault-epi/src")

from algovoi_records_vault_epi import licensing as epi_licensing  # noqa: E402
epi_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_records_vault_epi import (  # noqa: E402
    SCHEMA, SUITE, build_steps, control_mapping_for, export_epi,
)
from algovoi_records_vault_epi.verifier.epi_verify import verify_epi, _kid  # noqa: E402

PASS = 0
FAIL = 0


def check(label, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


def _streams(pk, sk):
    """Two signed vault-style streams (access + consent), each a list of signed envelopes."""
    def env(stream_type, seq):
        payload = {
            "type": stream_type,
            "seq": seq,
            "recorded_at": f"2026-01-0{seq + 1}T00:00:00Z",
            "detail": f"{stream_type}-{seq}",
        }
        return signing.make_envelope(payload, sk, pk)
    return {
        "access": [env("vault_access_event", 0), env("vault_access_event", 1)],
        "consent": [env("vault_consent_receipt", 0)],
    }


def main() -> int:
    pk, sk = signing.generate_keypair()
    streams = _streams(pk, sk)
    tmp = tempfile.mkdtemp(prefix="epi-")

    # build_steps: hash-linked timeline across all envelopes
    steps = build_steps(streams)
    check("build_steps flattens every envelope into one timeline", len(steps) == 3)
    check("first step prev is None (chain root)", steps[0]["prev"] is None)
    check("later steps link to a prior step hash",
          bool(steps[1]["prev"]) and steps[1]["prev"].startswith("sha256:"))
    check("each step carries evidence_hash back to its signed receipt",
          all("evidence_hash" in s for s in steps))

    # control_mapping_for: maps present streams to regulatory requirements
    cm = control_mapping_for(streams, edition="health")
    mapped = {m["stream"] for m in cm["mappings"]}
    check("control_mapping covers the access + consent streams", {"access", "consent"} <= mapped)

    # export_epi: writes the .epi artifact directory + a Falcon-1024-signed manifest
    manifest = export_epi(streams=streams, public_key=pk, secret_key=sk, out_dir=tmp,
                          control_mapping=cm, issuer_did="did:web:test.example.com")
    check("manifest declares the .epi PQC profile schema", manifest["schema_version"] == SCHEMA)
    check("manifest signature suite is falcon1024", manifest["signature_suite"] == SUITE)
    check("manifest steps_count matches the timeline", manifest["steps_count"] == 3)
    check("all artifact files were written", all(
        os.path.exists(os.path.join(tmp, n))
        for n in ("manifest.json", "steps.jsonl", "control_mapping.json", "public_key.b64", "verification.md")))

    # the bundled redistributable verifier confirms a good artifact is cryptographically
    # intact. With no kid pinned out-of-band it returns 3 (INTACT, key self-asserted); when
    # the artifact's kid is pinned it returns 0 (VERIFIED AND ANCHORED). Both are "good".
    check("offline verifier confirms the good .epi artifact is intact (self-asserted key)",
          verify_epi(tmp) == 3)
    check("offline verifier ANCHORS the good .epi artifact when the kid is pinned",
          verify_epi(tmp, expected_kid=_kid(pk)) == 0)

    # tamper: flip bytes in steps.jsonl -> the file hash (and chain) no longer match -> reject
    steps_path = os.path.join(tmp, "steps.jsonl")
    data = open(steps_path, "rb").read()
    open(steps_path, "wb").write(data.replace(b"access", b"acce55", 1))
    check("offline verifier REJECTS a tampered artifact", verify_epi(tmp) != 0)

    print(f"\n=== EPI-EXPORT RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
