# algovoi-records-vault-importer

Volume importer **add-on** for [AlgoVoi Records Vault](https://docs.algovoi.co.uk/records-vault). Bring an
existing document estate (filesystem, SQLite blob tables, S3) into the post-quantum Verifiable Archive,
and choose the signing strategy **per import** to trade granularity against throughput.

Licensed product (runtime-enforced, fail-closed). Not open source.

## Two strategies, one call

```python
from algovoi_records_vault_importer import import_records, import_records_fs
from algovoi_records_vault import FsSource

# One signature PER DOCUMENT: maximum granularity, each record its own signed entry.
await import_records(archive, FsSource("/data"), strategy="falcon", mode="bridge")

# One signature PER BATCH: volume throughput (~300x), with an offline inclusion proof per document.
await import_records_fs(archive, "/data", strategy="merkle", batch_size=1000, workers=8, mode="bridge")
```

- **`strategy="falcon"`** - one Falcon-1024 signature per document. Every record is an independent,
  individually revocable signed archive entry. Throughput is bounded by signing (~one sign per doc).
- **`strategy="merkle"`** - a batch of documents is folded into one SHA-256 Merkle root and only that root
  is signed, so throughput is bounded by hashing and IO, not signing. Each document keeps a short offline
  **inclusion proof** against the signed batch root (`verify_document_in_batch`, `compact_proof`).

Both strategies support **bridge** mode (notarise content hashes, no bytes moved: the zero-disruption
on-ramp) and **store** mode (ML-KEM-encrypt and store each blob). The import is idempotent and resumable
(re-runs skip already-committed records), streams the source at constant memory, and can hash the
filesystem in parallel.

## Throughput

Measured end to end on a clean Linux box, real files read from disk (3,000 documents of 100 KB), real
Falcon-1024. `merkle` throughput is bounded by read and hashing (bridge) or encryption and storage
(store), not by signing, so MB/s is the stable figure:

| Strategy / mode | Throughput | Bandwidth |
| --- | --- | --- |
| `falcon` bridge (per document) | ~116 docs/s | signing-bound |
| `merkle` bridge (hash only) | ~6,500 docs/s | ~660 MB/s |
| `merkle` store (encrypt + store) | ~1,150 docs/s | ~120 MB/s |

At those rates a ten-million-record estate (100 KB average) imports in roughly **30 minutes** with
`merkle` bridge, or about **2.4 hours** with `merkle` store, versus roughly a day per document with
`falcon`. Larger documents lower the docs/s but hold the MB/s, so size your estimate by total bytes.
Verification stays offline in both cases: per-document receipts for `falcon`, per-document inclusion
proofs against the signed batch root for `merkle`.

## Command line — `algovoi-rv-import`

The same signed-batch importer as a console script (`[project.scripts]`), so an operator imports a
folder with one command. Prints a JSON summary.

```bash
# import a document estate (resumable, idempotent, batch-signed)
algovoi-rv-import import <source_dir> --archive <dir> --keys-dir <dir> \
    --strategy merkle --mode bridge --batch-size 1000 --workers 8 \
    --checkpoint <path> --progress

# verify one document sha against a signed batch envelope
algovoi-rv-import verify --doc-sha <sha256> --batch-envelope <b64u> --public-key <pk_file>
```

Subcommands: **`import`** (folder → signed archive), **`watch`** (continuous drop-folder ingest), and
**`verify`**. Key `import` flags: `--strategy {merkle,falcon}`, `--mode {bridge,store}`, `--batch-size`,
`--workers`, `--checkpoint` (resume), `--no-skip` (do not dedup), `--progress` (stream to stderr).
`--keys-dir` holds/creates the persistent Falcon + ML-KEM keypair (secret keys written `0600`), so
re-runs dedup and batches stay offline-verifiable.

## Opt-in folder watcher

`watch(...)` (library, and the `algovoi-rv-import watch` subcommand) is a stdlib-only polling watcher
for continuous ingestion. It runs an idempotent import only once the folder has been **quiescent** (no
size change for `--quiescent-secs`, default 5s), so half-written files are never imported mid-write;
each cycle commits only genuinely new documents. It is **fail-closed** — a cycle error is reported via
`on_error` and the watcher keeps polling, never silently dropping input — and **off by default** (enable
per vault only when there is a real streaming source). Whoever can write to the watched folder can get
records notarized, so it should be an allowlisted, access-controlled path (the caller owns that policy).

```bash
algovoi-rv-import watch --source <drop_dir> --archive <dir> --keys-dir <dir> \
    --poll-secs 10 --quiescent-secs 5 --strategy merkle --mode bridge
```

The CLI `watch` runs until SIGINT/SIGTERM (clean shutdown under systemd), streams committing cycles to
stderr, and prints a JSON summary on exit. `clock` / `sleep` / `stop` are injectable on the library
`watch(...)` for deterministic tests. A `docs/SECURE_INGEST.md` runbook covers a per-tenant chrooted,
write-only SFTP landing zone that feeds the watcher.

## Verifying a merkle-batch document offline

```python
from algovoi_records_vault_importer import verify_document_in_batch
assert verify_document_in_batch(doc_sha256, batch_envelope, public_key)   # True == in the signed batch
```
The verifier checks the batch's Falcon-1024 signature and that the document is a leaf under the signed
Merkle root. It never raises on malformed input.

## Licence

Commercial add-on to Records Vault. Requires a valid AlgoVoi licence; set `ALGOVOI_LICENSE_KEY` (or
`ALGOVOI_LICENSE_FILE`). Fail-closed: no valid licence, no import.
