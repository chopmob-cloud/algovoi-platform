# AlgoVoi Verifiable Archive

**Tamper-evident, post-quantum document archiving.** Every document is content-addressed,
**encrypted at rest** (ML-KEM-1024 + AES-256-GCM), and recorded as a **Falcon-1024-signed** entry in
an **append-only, hash-linked chain** that anyone can verify offline. Prove a document existed at a
point in time, hasn't been altered, and sits in a record that can't be back-dated, reordered, or
silently deleted — the evidence model regulated record-keeping needs.

This is **not** a document-management system (no folders, sharing, or search). It is the *evidence
layer* for documents: integrity, provenance, and verifiable retention.

```
  document bytes ──▶ sha256 (content address)
                 ──▶ encrypt  (ML-KEM-1024 + AES-256-GCM)  ──▶ store ciphertext (local FS or S3)
                 ──▶ Falcon-1024-signed entry, linked to the previous one (prev_receipt_hash)
                          │
   append-only chain:  e0 ◀─ e1 ◀─ e2 ◀─ … ◀─ head
                          │
   verify offline (public key only):  every entry signed · sequential · correctly hash-linked
                                       ⇒ nothing inserted, removed, reordered, or back-dated
```

## Why it exists

- **Evidence-grade integrity.** A document's hash is bound into a post-quantum-signed entry; the
  chain proves the whole archive's order and completeness. Tampering is detectable, not deniable.
- **Encrypted with one method, everywhere.** Encryption happens in the engine, before storage — so a
  local-disk archive and an S3 archive are sealed identically. ML-KEM-1024 + AES-256-GCM (a fresh
  per-document key) makes the archive **post-quantum on both axes**, signed *and* encrypted.
- **Offline-verifiable.** Entries and the chain verify with nothing but the issuer's public key — no
  service to trust at audit time.
- **Content-addressed.** The document *is* its hash; integrity is intrinsic, dedup is free.
- **Backend-swappable.** Same evidence model on local disk (this package) or S3 / S3-compatible
  (`algovoi-doc-archive-s3`) — the storage target is a plug-in, the cryptography is not.

## What you inject

| Dependency | What it is | How |
|---|---|---|
| **Falcon keypair** | The archive signing key (entries) | `Archive(secret_key=…, public_key=…)` |
| **ML-KEM keypair** | The encryption key (public encrypts; secret decrypts — a node can be write-only) | `HybridPqcEncryptor(kem_pk, kem_sk)` |
| **Storage backend** | Where ciphertext lands | `Archive(storage=LocalFsBackend("./archive"))` |
| **API token** *(optional)* | Bearer token gating notarize / retrieve | `create_app(auth_dependency=bearer_token_auth(…))` |

## Install

```bash
pip install algovoi-doc-archive            # engine + local filesystem backend
pip install "algovoi-doc-archive[serve]"   # + uvicorn to run the service
pip install algovoi-doc-archive-s3         # add the S3 / S3-compatible backend
```

Python ≥ 3.11. Deps: `fastapi`, `pydantic`, `rfc8785`, `pqcrypto`, `cryptography`.

## Run the service

```bash
python examples/run_service.py
# → http://127.0.0.1:8083  (notarize, verify, verify-chain, retrieve, /archive/verify portal, pqc-keys)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/archive/notarize` | bearer | Archive a document (`data_b64`, encrypted+stored) or notarize by `doc_hash` only. |
| `POST` | `/v1/archive/verify` | public | Verify a single entry's signature + structure. |
| `GET` | `/v1/archive/verify-chain` | public | Verify the whole chain's integrity and ordering. |
| `GET` | `/v1/archive/entry/{seq}` | public | Fetch an entry receipt + payload. |
| `GET` | `/v1/archive/retrieve/{doc_hash}` | bearer | Decrypt and return a stored document (integrity-checked). |
| `GET` | `/archive/verify` | public | Browser portal. |
| `GET` | `/.well-known/pqc-keys.json` | public | The archive's Falcon public key + `kid`. |

## Embed directly

```python
from algovoi_doc_archive import Archive, LocalFsBackend, HybridPqcEncryptor, signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair

pk, sk = signing.generate_keypair()
kem_pk, kem_sk = generate_mlkem_keypair()
arc = Archive(secret_key=sk, public_key=pk, storage=LocalFsBackend("./archive"),
              encryptor=HybridPqcEncryptor(kem_pk, kem_sk))

e = await arc.notarize(data=pdf_bytes, title="MSA v3", content_type="application/pdf")
assert (await arc.verify_chain()).valid
doc = await arc.retrieve(doc_hash=e["doc_hash"])     # decrypts + verifies the hash
```

## Two backends, one evidence model

| Package | Storage | Use |
|---|---|---|
| **algovoi-doc-archive** (this) | Local filesystem | On-prem, air-gapped, single-node. Pure-Python. |
| **algovoi-doc-archive-s3** | S3 / S3-compatible (MinIO, R2, Wasabi, …) | Cloud / durable object storage. |

Both encrypt-then-store with the same method and produce the same verifiable chain — pick the
storage target per deployment.

## Guarantees

- **Tamper-evident.** Any alteration, insertion, deletion, reorder, or back-date breaks `verify-chain`.
- **Encrypted at rest, always.** Storage backends only ever see ciphertext; plaintext never lands on disk/S3.
- **Hash-only mode.** Notarize a document's existence without storing it (privacy / large files).
- **Append-only, single-writer** per archive (back it with a transactional store/lock for multi-node).
- **No fund movement, read-mostly** — an evidence system, not an execution one.

## Key recovery (included, free)

The archive's ML-KEM master key is the one thing whose loss is catastrophic. **Recovery Vault** —
included at no extra charge — protects it with **threshold (Shamir k-of-n)** recovery: the master key
is split into *n* shares, any *k* reconstruct it, fewer reveal nothing. So a lost or destroyed share
never locks you out, and no single holder can decrypt your data.

- **Self-custody by default** — every share is yours; AlgoVoi holds nothing.
- **Optional support-assisted recovery** — AlgoVoi holds **one** sub-threshold (inert) share it can
  contribute to a verified break-glass; it can never decrypt or recover on its own. Disable anytime.
- Ships as a sealed, client-deployed appliance (`algovoi-recovery-vault`); a 2-of-3 recovery is
  emitted automatically when you create archive keys.

See the Recovery Vault `HOWTO.md` / `DEPLOY.md`, and verify AlgoVoi's published recovery-key
fingerprint (`c8655d786306af53`) before opting in to support-assisted recovery.

## Licence

Commercial — `LicenseRef-AlgoVoi-Commercial-1.0`. Not open source; not published to public
registries. See `LICENSE.md`. Contact **chopmob@gmail.com**.

## Third-party dependencies & attribution

This package **depends on** the following open-source libraries (installed from PyPI under their own licences). AlgoVoi does **not** vendor, copy, or modify them — they are imported as ordinary dependencies, not embedded. All are permissive (MIT / BSD / Apache-2.0); none are copyleft.

| Library | Licence |
|---|---|
| [`fastapi`](https://github.com/fastapi/fastapi) | MIT |
| [`pydantic`](https://github.com/pydantic/pydantic) | MIT |
| [`rfc8785`](https://github.com/trailofbits/rfc8785.py) | Apache-2.0 |
| [`pqcrypto`](https://github.com/kpdemetriou/pqcrypto) | MIT |
| [`cryptography`](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause |
| [`uvicorn`](https://github.com/encode/uvicorn) _(optional)_ | BSD-3-Clause |

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
