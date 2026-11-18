"""Phase-1 worked end-to-end (standalone, runnable): the credible-launch flow, all-offline.

HEALTH/LEGAL composite: consent-less minimal path —
  notarize encrypted record (TSA-sealed) -> clinician retrieve (access logged) -> legal hold on the
  patient matter -> disposal blocked by the hold -> HIPAA access report -> offline-verify EVERY chain
with no service running and only the published public key.

Run: python algovoi-records-vault/tests/test_phase1_e2e.py
"""
import asyncio
import os
import sys
import tempfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda: {"test": True}

from algovoi_records_vault import Principal, RecordsVault, verify_stream  # noqa: E402
from algovoi_records_vault.timestamp import verify_timestamp_binding  # noqa: E402
from algovoi_records_vault.vault import (  # noqa: E402
    ACCESS_TYPE, HOLD_TYPE, TSA_TYPE,
)

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


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-e2e-")
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    storage = LocalFsBackend(os.path.join(tmp, "archive"))
    archive = Archive(public_key=pk, secret_key=sk, storage=storage,
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    os.environ.pop("VAULT_TSA_URL", None)        # air-gap
    vault = RecordsVault(archive=archive, signing_secret_key=sk, signing_public_key=pk)

    clinician = Principal(did="did:web:clinic.example/dr-jones", kid="k1", scopes=("records:read",))

    # 1) notarize an encrypted record, TSA-sealed
    out = await vault.notarize(data=b"patient-42 imaging report", title="patient-42/img",
                               content_type="text/plain",
                               metadata={"subject_ref": "patient-42"})
    receipt = out["archive"]["receipt"]
    doc_hash = out["archive"]["doc_hash"]
    check("record notarized + timestamp-sealed in tsa/ stream", out["tsa"]["seq"] == 0)
    check("timestamp binds to the receipt",
          verify_timestamp_binding(out["tsa"]["payload"], receipt))

    # 2) clinician retrieves -> access event logged, plaintext recovered
    data = await vault.retrieve(doc_hash=doc_hash, principal=clinician, reason="treatment")
    check("clinician recovers the decrypted record", data == b"patient-42 imaging report")

    # 3) legal hold on the patient matter
    holds = vault.holds(retention_days=365 * 7)   # 7-year health-records floor
    await holds.place_hold(matter_id="MATTER-A", reason="malpractice claim; preserve patient-42",
                           principal=Principal(did="did:web:law.example/counsel", scopes=("legal:hold",)),
                           query={"subject_ref": "patient-42"})
    held_record = {"subject_ref": "patient-42", "archived_at": out["archive"]["archived_at"]}
    check("the patient's record is under hold", (await holds.is_held(held_record)) is True)

    # 4) disposal blocked by the hold even far past retention
    check("disposal blocked by the active hold",
          (await holds.is_disposable(held_record, now=datetime(2099, 1, 1, tzinfo=timezone.utc))) is False)

    # 5) HIPAA access report (JSONL)
    report = await vault.access_log().export_jsonl()
    check("access report contains the clinician's read",
          "did:web:clinic.example/dr-jones" in report and "granted" in report)

    # 6) offline-verify EVERY chain with only the published public key (no service, no secret key)
    results = await vault.verify_all_chains()
    check("archive chain verifies offline", results["archive"].valid)
    check("tsa chain verifies offline", results["tsa"].valid)
    check("access chain verifies offline", results["access"].valid)
    check("holds chain verifies offline", results["holds"].valid)

    # 6b) prove the standalone verifier works from EXPORTED envelopes alone (pubkey only)
    async def export(prefix):
        keys = sorted(await storage.list_prefix(f"{prefix}/"))
        keys = [k for k in keys if not k.endswith("head.json")]
        return [(await storage.get(k)).decode() for k in keys]

    check("standalone verify_stream(tsa) valid from exported JSON only",
          verify_stream(await export("tsa"), pk, TSA_TYPE).valid)
    check("standalone verify_stream(access) valid from exported JSON only",
          verify_stream(await export("access"), pk, ACCESS_TYPE).valid)
    check("standalone verify_stream(holds) valid from exported JSON only",
          verify_stream(await export("holds"), pk, HOLD_TYPE).valid)

    print(f"\n=== PHASE-1 E2E RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
