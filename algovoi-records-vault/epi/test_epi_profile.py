"""`.epi` PQC-profile test (standalone, runnable): vault -> .epi export -> 5-check verify -> tamper.

Run: python algovoi-records-vault/epi/test_epi_profile.py
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # platform dir
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")
sys.path.insert(0, HERE)
VERIFIER = f"{ROOT}/algovoi-records-vault/free-verifier/algovoi_verify.py"

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda: {"test": True}

from algovoi_records_vault import Principal, RecordsVault  # noqa: E402
from algovoi_records_vault.vault import (  # noqa: E402
    ACCESS_PREFIX, ACCESS_TYPE, CONSENT_PREFIX, CONSENT_TYPE, HOLD_PREFIX, HOLD_TYPE,
    TSA_PREFIX, TSA_TYPE, _VaultStream,
)

from epi_profile import build_steps, control_mapping_for, export_epi  # noqa: E402

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


def run_verifier(d):
    return subprocess.run([sys.executable, VERIFIER, "epi", d], capture_output=True, text=True)


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-epi-")
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    storage = LocalFsBackend(os.path.join(tmp, "archive"))
    archive = Archive(public_key=pk, secret_key=sk, storage=storage,
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk),
                      issuer_did="did:web:vault.algovoi.example")
    os.environ.pop("VAULT_TSA_URL", None)
    vault = RecordsVault(archive=archive)

    # populate several evidence streams
    out = await vault.notarize(data=b"patient-1 record", title="rec-1", metadata={"subject_ref": "patient-1"})
    await vault.retrieve(doc_hash=out["archive"]["doc_hash"], principal=Principal(did="did:web:clinic/dr"))
    await vault.holds(retention_days=365).place_hold(matter_id="M-1", reason="litigation",
                                                     query={"subject_ref": "patient-1"})
    await vault.consent().grant(subject_ref="patient-1", terms="HIPAA auth", authorized_uses=["treatment"])

    async def ents(etype, prefix):
        return await _VaultStream(storage=storage, public_key=pk, secret_key=None,
                                  entry_type=etype, prefix=prefix).list_entries()

    streams = {
        "archive": await archive.list_entries(),
        "tsa": await ents(TSA_TYPE, TSA_PREFIX),
        "access": await ents(ACCESS_TYPE, ACCESS_PREFIX),
        "holds": await ents(HOLD_TYPE, HOLD_PREFIX),
        "consent": await ents(CONSENT_TYPE, CONSENT_PREFIX),
    }

    # steps cross-link to the underlying signed vault receipts
    steps = build_steps(streams)
    arch_payload = signing.open_envelope(streams["archive"][0])[0]
    check("steps.jsonl links each step to the signed vault receipt (evidence_hash)",
          any(s["evidence_hash"] == signing.payload_hash(arch_payload) for s in steps))
    check("steps form a hash-linked timeline (first prev is null)", steps[0]["prev"] is None)

    epi_dir = os.path.join(tmp, "artifact.epi")
    manifest = export_epi(streams=streams, public_key=pk, secret_key=sk, out_dir=epi_dir,
                          control_mapping=control_mapping_for(streams, edition="health"),
                          issuer_did="did:web:vault.algovoi.example")
    check("manifest signature uses the falcon1024 PQC suite", manifest["signature"].startswith("falcon1024:"))
    check("manifest maps streams to controls",
          any(m["framework"] == "HIPAA" for m in json.load(open(os.path.join(epi_dir, "control_mapping.json")))["mappings"]))

    # the standalone free verifier passes all 5 checks
    r = run_verifier(epi_dir)
    check("free verifier passes all 5 .epi checks (exit 0)", r.returncode == 0 and ".epi VERIFIED" in r.stdout)
    for ck in ("Structure valid", "Hashes match", "Signature valid", "Chain intact"):
        check(f"  check present + PASS: {ck}", f"[PASS] {ck}" in r.stdout)

    # tamper 1: edit a step -> hashes + chain fail
    sp = os.path.join(epi_dir, "steps.jsonl")
    lines = open(sp, encoding="utf-8").read().splitlines()
    obj = json.loads(lines[1]); obj["type"] = "FORGED"
    lines[1] = json.dumps(obj, separators=(",", ":"), sort_keys=True)
    open(sp, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    r2 = run_verifier(epi_dir)
    check("tampered steps.jsonl fails verification", r2.returncode != 0 and ".epi VERIFICATION FAILED" in r2.stdout)

    # tamper 2: forge the manifest signature -> signature check fails
    export_epi(streams=streams, public_key=pk, secret_key=sk, out_dir=epi_dir,
               control_mapping=control_mapping_for(streams), issuer_did="did:web:vault.algovoi.example")
    mpath = os.path.join(epi_dir, "manifest.json")
    m = json.load(open(mpath))
    suite, kid, _ = m["signature"].split(":", 2)
    m["signature"] = f"{suite}:{kid}:{signing.b64u_encode(b'0' * 64)}"
    json.dump(m, open(mpath, "w"), indent=2, sort_keys=True)
    r3 = run_verifier(epi_dir)
    check("forged manifest signature fails the Signature check",
          r3.returncode != 0 and "[FAIL] Signature valid" in r3.stdout)

    print(f"\n=== EPI-PROFILE RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
