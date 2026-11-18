"""End-to-end migration test (standalone, runnable): build -> validate -> test.

Bypasses runtime licence enforcement the same way the vendor unit tests do (test-tree only).
Run: python algovoi-records-vault/tests/test_migrate_e2e.py
"""
import asyncio
import os
import sys
import tempfile

# platform dir resolved from this file's location: <ROOT>/algovoi-records-vault/tests/
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing  # noqa: E402
licensing.require_license = lambda: {"test": True}  # vendor-test bypass (never shipped)

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault import (  # noqa: E402
    FsSource, migrate, reconcile, sign_manifest, verify_manifest, detect_drift,
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


def make_source_dir(n=5):
    d = tempfile.mkdtemp(prefix="legacy_records_")
    os.makedirs(os.path.join(d, "sub"), exist_ok=True)
    for i in range(n):
        sub = "sub/" if i % 2 else ""
        with open(os.path.join(d, f"{sub}record_{i}.txt"), "wb") as f:
            f.write(f"patient/contract record {i} -- sensitive payload".encode())
    return d


async def main():
    print("=== 1. set up a legacy filesystem store (5 records) + a PQC archive ===")
    src_dir = make_source_dir(5)
    src = FsSource(src_dir, content_type="text/plain")
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    arc_dir = tempfile.mkdtemp(prefix="pqc_archive_")
    arc = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(arc_dir),
                  encryptor=HybridPqcEncryptor(kem_pk, kem_sk))

    print("=== 2. BRIDGE migrate (hash-only, no bytes moved) ===")
    res = await migrate(arc, src, mode="bridge")
    check("notarized all 5 records", res.notarized == 5 and res.total == 5)
    check("nothing skipped on first run", res.skipped == 0)
    check("no blob/ written in bridge mode (no bytes stored)",
          not os.path.isdir(os.path.join(arc_dir, "blob")))

    print("=== 3. chain verifies offline (public key only) ===")
    vr = await arc.verify_chain()
    check("verify_chain().valid", getattr(vr, "valid", False))

    print("=== 4. reconcile -> signed migration manifest -> offline verify ===")
    manifest = await reconcile(arc, src)
    check("manifest complete (every source record in chain)", manifest["complete"] is True)
    check("manifest in_chain == 5, missing == []", manifest["in_chain"] == 5 and manifest["missing"] == [])
    env = sign_manifest(manifest, sk, pk)
    check("signed manifest verifies with correct public key", verify_manifest(env, pk) is True)
    wrong_pk, _ = signing.generate_keypair()
    check("signed manifest REJECTS a wrong public key", verify_manifest(env, wrong_pk) is False)

    print("=== 5. idempotent re-run (content-addressed) ===")
    res2 = await migrate(arc, src, mode="bridge")
    check("re-run skips all 5, notarizes 0", res2.skipped == 5 and res2.notarized == 0)

    print("=== 6. drift detection: tamper a source record after notarisation ===")
    tampered = os.path.join(src_dir, "record_0.txt")
    with open(tampered, "wb") as f:
        f.write(b"ALTERED after notarisation")
    drift = await detect_drift(arc, src)
    check("drift detected on the altered record", any(d["ref"] == "record_0.txt" for d in drift))
    check("exactly one drifted record", len(drift) == 1)

    print("=== 7. STORE migrate (encrypt + store) into a fresh archive, retrieve checks integrity ===")
    src2_dir = make_source_dir(3)
    src2 = FsSource(src2_dir, content_type="text/plain")
    arc2_dir = tempfile.mkdtemp(prefix="pqc_archive2_")
    arc2 = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(arc2_dir),
                   encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    res3 = await migrate(arc2, src2, mode="store")
    check("store mode notarized all 3", res3.notarized == 3)
    check("blob/ written (bytes stored encrypted)", os.path.isdir(os.path.join(arc2_dir, "blob")))
    # retrieve one and confirm decrypt + integrity matches the original source bytes
    a_hash = next(iter(res3.entries))
    got = await arc2.retrieve(doc_hash=a_hash)
    src_bytes = {r.sha256: r.data for r in src2.records()}
    check("retrieve() decrypts + integrity-checks back to original bytes", got == src_bytes[a_hash])

    print(f"\n=== RESULT: {PASS} passed, {FAIL} failed ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
