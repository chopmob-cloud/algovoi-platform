"""RecordsVault facade test (standalone, runnable): licensing fail-closed + full composed flow.

Run: python algovoi-records-vault/tests/test_vault_facade.py
"""
import asyncio
import os
import sys
import tempfile

# platform dir resolved from this file's location: <ROOT>/algovoi-records-vault/tests/
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}  # vendor-test bypass (never shipped)

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
from algovoi_records_vault import FsSource, RecordsVault  # noqa: E402

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


def make_archive(tmp, SUB="archive"):
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    archive = Archive(public_key=pk, secret_key=sk,
                      storage=LocalFsBackend(os.path.join(tmp, SUB)),
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    return archive, pk, sk



async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-facade-")

    # --- 1. fail-closed: no licence in env -> constructing the vault must raise -------------
    saved = {k: os.environ.pop(k, None) for k in ("ALGOVOI_LICENSE_KEY", "ALGOVOI_LICENSE_FILE")}
    archive, pk, sk = make_archive(tmp)
    try:
        RecordsVault(archive=archive)
        check("RecordsVault without licence raises (fail-closed)", False)
    except Exception as exc:  # LicenseError
        check("RecordsVault without licence raises (fail-closed)",
              type(exc).__name__ == "LicenseError")
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v

    # --- 2. with the vendor-test bypass the facade composes the whole flow ------------------
    rv_licensing.require_license = lambda: {"test": True}  # test-tree only
    vault = RecordsVault(archive=archive, signing_secret_key=sk, signing_public_key=pk)
    check("facade constructs under test bypass", isinstance(vault, RecordsVault))

    srcdir = os.path.join(tmp, "legacy")
    os.makedirs(srcdir)
    for i in range(3):
        with open(os.path.join(srcdir, f"rec{i}.txt"), "wb") as fh:
            fh.write(f"facade record {i}".encode())
    src = FsSource(srcdir, content_type="text/plain")

    res = await vault.migrate(src, mode="store")
    check("facade migrate(store): 3 notarized", res.notarized == 3 and res.total == 3)

    res2 = await vault.migrate(src, mode="store")
    check("facade migrate is idempotent (3 skipped)", res2.skipped == 3 and res2.notarized == 0)

    manifest = await vault.reconcile(src)
    check("facade reconcile: complete + no missing",
          manifest["complete"] is True and manifest["missing"] == [])

    envelope = vault.sign_manifest(manifest)
    check("facade sign_manifest -> verify_manifest (offline, pubkey only)",
          RecordsVault.verify_manifest(envelope, pk) is True)
    bad = envelope.replace("complete", "Complete", 1)
    check("tampered manifest fails verification",
          RecordsVault.verify_manifest(bad, pk) is False if bad != envelope else True)

    drift = await vault.detect_drift(src)
    check("facade detect_drift: none on unchanged source", drift == [])

    vr = await vault.verify_chain()
    n_entries = len(await vault.archive.list_entries())
    check("facade verify_chain: valid over migrated entries",
          getattr(vr, "valid", False) and n_entries >= 3)

    # sign_manifest without keys must refuse
    vault_nokeys = RecordsVault(archive=archive)
    try:
        vault_nokeys.sign_manifest(manifest)
        check("sign_manifest without keys raises", False)
    except RuntimeError:
        check("sign_manifest without keys raises", True)

    print(f"\n=== FACADE RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
