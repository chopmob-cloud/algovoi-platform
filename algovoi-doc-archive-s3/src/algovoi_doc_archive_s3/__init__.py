"""
algovoi-doc-archive-s3 — S3 / S3-compatible storage backend for the AlgoVoi Verifiable Archive.

Drop-in replacement for the local filesystem backend; the archive engine and its post-quantum
encryption are unchanged — only the storage target differs. Works with Amazon S3, MinIO, Cloudflare
R2, Wasabi, Ceph (anything S3-compatible) via ``endpoint_url``.

Usage::

    from algovoi_doc_archive import Archive, HybridPqcEncryptor, signing
    from algovoi_doc_archive.encryption import generate_mlkem_keypair
    from algovoi_doc_archive_s3 import S3Backend

    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    backend = S3Backend("my-archive-bucket", region_name="eu-west-2", prefix="archive-1")
    # S3-compatible: S3Backend("bucket", endpoint_url="https://<acct>.r2.cloudflarestorage.com", ...)
    arc = Archive(secret_key=sk, public_key=pk, storage=backend,
                  encryptor=HybridPqcEncryptor(kem_pk, kem_sk))

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_doc_archive_s3.backend import S3Backend

__version__ = "0.1.1"

__all__ = ["S3Backend", "__version__"]
