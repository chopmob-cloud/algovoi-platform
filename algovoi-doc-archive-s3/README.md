# AlgoVoi Verifiable Archive — S3 backend

The **S3 / S3-compatible** storage backend for [`algovoi-doc-archive`](../algovoi-doc-archive). A
drop-in `StorageBackend` over Amazon S3, **MinIO, Cloudflare R2, Wasabi, Ceph** — any S3-compatible
object store.

The archive engine encrypts every document **before** it reaches storage, so this backend only ever
stores **ciphertext**. The evidence model — content-addressing, ML-KEM-1024 + AES-256-GCM encryption,
Falcon-1024-signed append-only chain, offline verification — is identical to the local-filesystem
backend. **Only the storage target changes.**

## Install

```bash
pip install algovoi-doc-archive-s3      # pulls in algovoi-doc-archive + boto3
```

## Use

```python
from algovoi_doc_archive import Archive, HybridPqcEncryptor, signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_doc_archive_s3 import S3Backend

pk, sk = signing.generate_keypair()
kem_pk, kem_sk = generate_mlkem_keypair()

# Amazon S3
backend = S3Backend("my-archive-bucket", region_name="eu-west-2", prefix="archive-1")

# S3-compatible (Cloudflare R2 / MinIO / Wasabi) — just set endpoint_url
backend = S3Backend(
    "my-archive-bucket",
    endpoint_url="https://<account>.r2.cloudflarestorage.com",
    aws_access_key_id="…", aws_secret_access_key="…",
)

# …or inject a pre-configured boto3 client:
#   import boto3; backend = S3Backend("bucket", client=boto3.client("s3", ...))

arc = Archive(secret_key=sk, public_key=pk, storage=backend,
              encryptor=HybridPqcEncryptor(kem_pk, kem_sk))

e = await arc.notarize(data=pdf_bytes, title="MSA v3", content_type="application/pdf")
assert (await arc.verify_chain()).valid
doc = await arc.retrieve(doc_hash=e["doc_hash"])
```

Everything else — the service app factory, verification, the portal — comes from
`algovoi-doc-archive`; this package only supplies the `S3Backend`.

## Hard WORM

For storage-level immutability (beyond the chain's tamper-*evidence*), enable **S3 Object Lock** on
the bucket. The chain proves nothing was altered or back-dated; Object Lock prevents overwrites/deletes
at the storage layer. Use both for regulated WORM (SEC 17a-4 / MiFID II).

## Licence

Commercial — `LicenseRef-AlgoVoi-Commercial-1.0`. Not open source; not published to public
registries. See `LICENSE.md`. Contact **chopmob@gmail.com**.

## Third-party dependencies & attribution

This package **depends on** the following open-source libraries (installed from PyPI under their own licences). AlgoVoi does **not** vendor, copy, or modify them — they are imported as ordinary dependencies, not embedded. All are permissive (MIT / BSD / Apache-2.0); none are copyleft.

| Library | Licence |
|---|---|
| [`boto3`](https://github.com/boto/boto3) | Apache-2.0 |

Full attribution and the bundling obligation are in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).


## Licence — required to run

This is a commercial package and is **runtime-licence-enforced**: it refuses to initialise without a
valid AlgoVoi licence. Set your licence key in the `ALGOVOI_LICENSE_KEY` environment variable (or point
`ALGOVOI_LICENSE_FILE` at a file containing it) before constructing the engine. Running several suite
packages together? `ALGOVOI_LICENSE_KEY` may hold several keys (whitespace/comma-separated) — each picks
its own.

Install with the index token from your purchase (it also pulls this package's private suite
dependencies, so one `pip install` resolves the whole chain). Terms: the Self-Serve Starter Licence
(clickwrap, accepted at purchase) or your Enterprise/OEM agreement.
