"""Source-adapter tests (standalone, runnable): SqliteBlobSource (real sqlite) + S3Source
(fake boto3-shaped client) — each migrated end-to-end into a real archive.

Run: python algovoi-records-vault/tests/test_sources.py
On VM2 a live MinIO pass reuses S3Source with a real boto3 client (see test_live_s3_minio.py).
"""
import asyncio
import os
import sqlite3
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

from algovoi_records_vault import SqliteBlobSource, S3Source, migrate, reconcile  # noqa: E402

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


def make_archive(tmp, SUB):
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    archive = Archive(public_key=pk, secret_key=sk,
                      storage=LocalFsBackend(os.path.join(tmp, SUB)),
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    return archive



class FakeS3Client:
    """Minimal boto3-S3-shaped fake: list_objects_v2 paginator + get_object."""

    def __init__(self, objects: dict[str, bytes], page_size: int = 2) -> None:
        self._objects = dict(objects)
        self._page = page_size

    def get_paginator(self, op):
        assert op == "list_objects_v2"
        outer = self

        class _P:
            def paginate(self, *, Bucket, Prefix=""):
                keys = sorted(k for k in outer._objects if k.startswith(Prefix))
                for i in range(0, len(keys), outer._page):
                    yield {"Contents": [{"Key": k} for k in keys[i:i + outer._page]]}
        return _P()

    def get_object(self, *, Bucket, Key):
        import io
        return {"Body": io.BytesIO(self._objects[Key])}


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-sources-")

    # --- SqliteBlobSource ---------------------------------------------------------------
    db = os.path.join(tmp, "legacy.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE docs (doc_id TEXT PRIMARY KEY, body BLOB, archived INT)")
    rows = [("case-001", b"legal record one", 0), ("case-002", b"legal record two", 0),
            ("case-003", b"already archived", 1), ("case-004", None, 0)]
    conn.executemany("INSERT INTO docs VALUES (?,?,?)", rows)
    conn.commit(); conn.close()

    src = SqliteBlobSource(db, table="docs", ref_column="doc_id", blob_column="body",
                           where="archived = 0", content_type="text/plain")
    recs = list(src.records())
    check("sqlite: WHERE scopes rows + NULL blob skipped (2 records)", len(recs) == 2)
    check("sqlite: deterministic ref order", [r.ref for r in recs] == ["case-001", "case-002"])
    check("sqlite: sha256 over blob bytes",
          recs[0].sha256.startswith("sha256:") and recs[0].data == b"legal record one")

    try:
        SqliteBlobSource(db, table="docs; DROP TABLE docs", ref_column="doc_id", blob_column="body")
        check("sqlite: unsafe identifier rejected", False)
    except ValueError:
        check("sqlite: unsafe identifier rejected", True)

    # #5 tier-3: a 'where' with a statement terminator / comment is rejected (single expression only)
    for bad in ("archived = 0; DROP TABLE docs", "1=1 -- comment", "x /* c */ = 1"):
        try:
            SqliteBlobSource(db, table="docs", ref_column="doc_id", blob_column="body", where=bad)
            check(f"sqlite: unsafe where rejected ({bad!r})", False)
        except ValueError:
            check(f"sqlite: unsafe where rejected ({bad!r})", True)

    archive = make_archive(tmp, "arch-sqlite")
    res = await migrate(archive, src, mode="store")
    check("sqlite -> archive store: 2 notarized", res.notarized == 2)
    manifest = await reconcile(archive, src)
    check("sqlite reconcile: complete", manifest["complete"] is True)
    vr = await archive.verify_chain()
    check("sqlite chain verifies",
          getattr(vr, "valid", False) and len(await archive.list_entries()) == 2)

    # --- S3Source (fake client; same adapter used live against MinIO) --------------------
    objects = {
        "legacy/health/pat-1.json": b'{"patient": 1}',
        "legacy/health/pat-2.json": b'{"patient": 2}',
        "legacy/health/sub/scan.bin": b"\x00\x01\x02pqc",
        "legacy/other/skip.txt": b"outside prefix",
        "legacy/health/folder/": b"",
    }
    s3 = S3Source(FakeS3Client(objects), bucket="legacy-bucket", prefix="legacy/health/",
                  content_type="application/octet-stream")
    recs = list(s3.records())
    check("s3: prefix scoping + folder placeholder skipped (3 records)", len(recs) == 3)
    check("s3: refs are prefix-stripped",
          sorted(r.ref for r in recs) == ["pat-1.json", "pat-2.json", "sub/scan.bin"])
    check("s3: pagination preserved order + bytes",
          [r.ref for r in recs] == ["pat-1.json", "pat-2.json", "sub/scan.bin"]
          and recs[2].data == b"\x00\x01\x02pqc")
    check("s3: metadata carries original key",
          recs[0].metadata.get("s3_key") == "legacy/health/pat-1.json")

    archive2 = make_archive(tmp, "arch-s3")
    res = await migrate(archive2, s3, mode="bridge")
    check("s3 -> archive bridge: 3 notarized hash-only", res.notarized == 3)
    res2 = await migrate(archive2, s3, mode="bridge")
    check("s3 bridge idempotent (3 skipped)", res2.skipped == 3)
    manifest = await reconcile(archive2, s3)
    check("s3 reconcile: complete", manifest["complete"] is True)
    vr = await archive2.verify_chain()
    check("s3 chain verifies",
          getattr(vr, "valid", False) and len(await archive2.list_entries()) == 3)

    print(f"\n=== SOURCES RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
