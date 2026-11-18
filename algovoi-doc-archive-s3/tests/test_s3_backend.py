"""Tests for the S3 backend using an in-memory fake S3 client (no boto3 / live AWS needed)."""
from __future__ import annotations

import io

import pytest

from algovoi_doc_archive import Archive, HybridPqcEncryptor, signing
from algovoi_doc_archive.backend import StorageBackend
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_doc_archive_s3 import S3Backend

DOC = b"Quarterly board minutes - confidential. " * 30


class _NotFound(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "NoSuchKey"}}


class FakeS3:
    """Minimal in-memory stand-in for a boto3 S3 client."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], bytes] = {}

    def put_object(self, Bucket, Key, Body):  # noqa: N803
        self.store[(Bucket, Key)] = bytes(Body)

    def get_object(self, Bucket, Key):  # noqa: N803
        if (Bucket, Key) not in self.store:
            raise _NotFound()
        return {"Body": io.BytesIO(self.store[(Bucket, Key)])}

    def head_object(self, Bucket, Key):  # noqa: N803
        if (Bucket, Key) not in self.store:
            raise _NotFound()
        return {}

    def list_objects_v2(self, Bucket, Prefix="", ContinuationToken=None, **kw):  # noqa: N803
        keys = [k for (b, k) in self.store if b == Bucket and k.startswith(Prefix)]
        return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False}


def _backend(prefix=""):
    return S3Backend("bkt", client=FakeS3(), prefix=prefix)


def test_satisfies_storage_backend_protocol():
    assert isinstance(_backend(), StorageBackend)


async def test_put_get_exists_missing():
    b = _backend()
    await b.put("blob/x", b"hello")
    assert await b.get("blob/x") == b"hello"
    assert await b.exists("blob/x") is True
    assert await b.get("blob/missing") is None
    assert await b.exists("blob/missing") is False


async def test_prefix_namespacing_and_list():
    fake = FakeS3()
    b = S3Backend("bkt", client=fake, prefix="archive-1")
    await b.put("entry/000000000000.json", b"e0")
    await b.put("entry/000000000001.json", b"e1")
    # stored under the prefix inside the bucket…
    assert ("bkt", "archive-1/entry/000000000000.json") in fake.store
    # …but list returns prefix-stripped keys
    assert await b.list_prefix("entry/") == ["entry/000000000000.json", "entry/000000000001.json"]


async def test_end_to_end_archive_over_s3():
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    arc = Archive(secret_key=sk, public_key=pk, storage=_backend("arch"),
                  encryptor=HybridPqcEncryptor(kem_pk, kem_sk), issuer_did="did:web:test")
    a = await arc.notarize(data=DOC, title="minutes", content_type="application/pdf")
    await arc.notarize(data=DOC + b"!", title="minutes-rev")
    # chain verifies, document round-trips, and what's stored is ciphertext
    res = await arc.verify_chain()
    assert res.valid and res.length == 2
    assert await arc.retrieve(doc_hash=a["doc_hash"]) == DOC
    raw = await arc.storage.get(f"blob/{a['doc_hash'].split(':')[1]}")
    assert raw is not None and raw != DOC and len(raw) > len(DOC)
