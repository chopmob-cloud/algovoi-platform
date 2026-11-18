"""LIVE S3 migration test against a real MinIO (VM2): real boto3 client, real bucket,
real objects -> S3Source -> migrate(store) -> retrieve + verify chain.

Requires env MINIO_URL (e.g. http://127.0.0.1:9000); credentials via MINIO_USER/MINIO_PASS
(default minioadmin/minioadmin). Run: MINIO_URL=... python tests/test_live_s3_minio.py
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

from algovoi_records_vault import S3Source, migrate, reconcile, sign_manifest, verify_manifest  # noqa: E402

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
    url = os.environ.get("MINIO_URL")
    if not url:
        print("SKIP: MINIO_URL not set (live MinIO test is VM2-only)")
        return 0
    import boto3

    s3c = boto3.client(
        "s3", endpoint_url=url,
        aws_access_key_id=os.environ.get("MINIO_USER", "minioadmin"),
        aws_secret_access_key=os.environ.get("MINIO_PASS", "minioadmin"),
        region_name="us-east-1",
    )
    bucket = "rv-live-test"
    try:
        s3c.create_bucket(Bucket=bucket)
    except Exception:
        pass  # already exists
    objects = {
        "legacy/health/pat-1.json": b'{"patient": 1, "live": true}',
        "legacy/health/pat-2.json": b'{"patient": 2, "live": true}',
        "legacy/health/imaging/scan.bin": os.urandom(4096),
        "legacy/other/outside.txt": b"outside prefix",
    }
    for k, v in objects.items():
        s3c.put_object(Bucket=bucket, Key=k, Body=v)
    check("MinIO reachable + 4 objects seeded", True)

    tmp = tempfile.mkdtemp(prefix="rv-minio-")
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    arc = Archive(public_key=pk, secret_key=sk,
                  storage=LocalFsBackend(os.path.join(tmp, "archive")),
                  encryptor=HybridPqcEncryptor(kem_pk, kem_sk))

    src = S3Source(s3c, bucket=bucket, prefix="legacy/health/")
    res = await migrate(arc, src, mode="store")
    check("live S3 -> archive store: 3 notarized (prefix-scoped)", res.notarized == 3)

    res2 = await migrate(arc, src, mode="store")
    check("idempotent on live re-run (3 skipped)", res2.skipped == 3)

    scan_sha = "sha256:" + __import__("hashlib").sha256(
        objects["legacy/health/imaging/scan.bin"]).hexdigest()
    data = await arc.retrieve(doc_hash=scan_sha)
    check("binary object retrieves + decrypts byte-identical from archive",
          data == objects["legacy/health/imaging/scan.bin"])

    manifest = await reconcile(arc, src)
    check("live reconcile complete", manifest["complete"] is True and manifest["missing"] == [])
    env = sign_manifest(manifest, sk, pk)
    check("signed live manifest verifies offline", verify_manifest(env, pk) is True)

    vr = await arc.verify_chain()
    check("chain valid after live S3 migration", getattr(vr, "valid", False))

    print(f"\n=== LIVE-MINIO RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
