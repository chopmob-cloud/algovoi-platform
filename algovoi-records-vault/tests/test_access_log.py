"""F3 read-access audit log test (standalone, runnable): granted/denied events + tamper-evidence.

Run: python algovoi-records-vault/tests/test_access_log.py
"""
import asyncio
import json
import os
import sys
import tempfile

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

from algovoi_records_vault import Principal, RecordsVault  # noqa: E402

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


def tamper(path):
    with open(path, "rb") as fh:
        outer = json.loads(signing.b64u_decode(fh.read().decode()))
    outer["payload"]["decision"] = "granted"   # try to flip a denial into a grant
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(
            json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-access-")
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    archive = Archive(public_key=pk, secret_key=sk,
                      storage=LocalFsBackend(os.path.join(tmp, "archive")),
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    vault = RecordsVault(archive=archive)

    out = await vault.notarize(data=b"PHI: patient chart", title="chart-1", time_stamp=False)
    doc_hash = out["archive"]["doc_hash"]

    clinician = Principal(did="did:web:clinic.example/dr-jones", kid="key-7",
                          scopes=("records:read",))

    data = await vault.retrieve(doc_hash=doc_hash, principal=clinician, reason="treatment")
    check("retrieve returns the document bytes", data == b"PHI: patient chart")

    alog = vault.access_log()
    events = await alog.events()
    check("one granted access event recorded", len(events) == 1 and events[0]["decision"] == "granted")
    check("access event records who + why",
          events[0]["principal_did"] == "did:web:clinic.example/dr-jones"
          and events[0]["principal_kid"] == "key-7" and events[0]["reason"] == "treatment")
    check("access event records the doc_hash", events[0]["doc_hash"] == doc_hash)

    # denied path: unknown hash -> denied event + the underlying error re-raises
    raised = False
    try:
        await vault.retrieve(doc_hash="sha256:" + "00" * 32, principal=clinician, reason="fishing")
    except Exception:  # noqa: BLE001
        raised = True
    check("retrieve of an unknown doc re-raises", raised)
    events = await alog.events()
    check("denied access event recorded with error class",
          len(events) == 2 and events[1]["decision"] == "denied" and events[1]["error"])

    # anonymous principal -> null who-fields, still logged
    await vault.retrieve(doc_hash=doc_hash, reason="audit")
    events = await alog.events()
    check("anonymous retrieve logs null principal", events[2]["principal_did"] is None)

    # JSONL export
    jsonl = await alog.export_jsonl()
    check("export_jsonl yields one line per event", len(jsonl.splitlines()) == 3)

    # chain integrity
    vr = await alog.verify_chain()
    check("access log chain verifies valid", vr.valid and vr.length == 3)

    # tamper-evidence: flipping a denied event to granted breaks the signature
    tamper(os.path.join(tmp, "archive", "access", "000000000001.json"))
    vr = await alog.verify_chain()
    check("tampered access event detected (chain invalid at index 1)",
          (not vr.valid) and vr.broken_at == 1)

    print(f"\n=== ACCESS-LOG RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
