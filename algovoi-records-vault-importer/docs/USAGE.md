# Records Vault volume importer — use, build, test

The importer ingests an existing document estate into the Records Vault PQC archive, choosing a signing
strategy per run: `merkle` (one Falcon-1024 signature per SHA-256 batch — throughput bound by read/hash,
~300x faster, with an offline per-document inclusion proof) or `falcon` (one signature per document —
maximum granularity). Every run is **idempotent** (re-running skips documents already present, deduped by
content) and **resumable** (checkpoint file). Commercial add-on; runtime-licensed, fail-closed.

There are three ways to drive it. They are layers, not alternatives: a **designated folder** is always the
transport; the **CLI** and **watcher** are how you trigger it; the **CCC page** is a control surface over
the same call. Browser upload is deliberately not the bulk path (no resume, memory limits).

## Options

### 1. Designated folder + CLI (primary)

The folder is the ingest staging area; one command imports it.

```bash
algovoi-rv-import import /data/estate \
    --archive /vault/archive \
    --keys-dir /vault/keys \
    --strategy merkle --mode bridge \
    --batch-size 1000 --checkpoint /vault/import.ckpt --progress
```

- `--keys-dir` persists the Falcon + ML-KEM keypair (created on first run, reused after) so batches stay
  offline-verifiable and re-runs dedup. Keep it access-controlled; secret keys are written `0600`.
- `--mode bridge` records hashes only (no bytes moved); `--mode store` encrypts and stores the bytes.
- `--checkpoint` makes an interrupted import resumable; re-running with the same checkpoint continues.
- Output is a JSON summary (`total`, `committed`, `skipped`, `batches`, `signatures`, `docs_per_sec`).

Verify a single document against its signed batch (offline, no archive needed):

```bash
algovoi-rv-import verify --doc-sha <sha256-hex> \
    --batch-envelope <b64u-envelope> --public-key /vault/keys/falcon_pk.key
```

Library equivalent (async):

```python
from algovoi_records_vault_importer import import_records_fs
result = await import_records_fs(archive, "/data/estate", strategy="merkle",
                                 mode="bridge", batch_size=1000, checkpoint_path="/vault/import.ckpt")
```

### 2. Folder watcher (opt-in automation)

For continuous ingestion from a system that drops files into the folder. It polls, and runs an idempotent
import only once the folder has been **quiescent** for `quiescent_secs` (no size change), so a
mid-write file is never imported. Fail-closed: an error in one cycle is reported and watching continues.

```python
from algovoi_records_vault_importer import watch
await watch(archive, "/data/dropbox", strategy="merkle", batch_size=1000,
            poll_secs=10.0, quiescent_secs=5.0,
            on_cycle=lambda r: log.info("imported %d (skipped %d)", r.committed, r.skipped),
            on_error=lambda e: log.error("import cycle failed: %s", e),
            stop=lambda: shutting_down)
```

Trust boundary: whoever can write to the watched folder can get records notarized, so make it an
allowlisted, access-controlled path. Off by default; enable per vault only with a real streaming source.

### 3. CCC control surface (recommended UI)

The Compliance Command Center is the place to *configure and monitor* imports, not to transport bytes: a
page that sets the folder + strategy/mode/batch, triggers a run, streams progress from the importer's
`progress` callback, and shows the resulting Merkle root, signed batch envelope, CCC posture tier, and
per-document compact proofs. A small drag-drop for a handful of files simply writes them into the folder
and triggers a run. Reference wiring (same call the CLI uses):

```python
# inside a CCC route: stream ImportResult snapshots to the browser (SSE/websocket)
async def run_import(cfg, publish):
    return await import_records_fs(open_vault_archive(cfg.vault), cfg.folder,
        strategy=cfg.strategy, mode=cfg.mode, batch_size=cfg.batch_size,
        checkpoint_path=cfg.checkpoint, progress=lambda r: publish(vars(r)))
```

## Build

Pure-Python package; build a wheel with the standard backend:

```bash
cd algovoi-records-vault-importer
python -m build --wheel          # -> dist/algovoi_records_vault_importer-0.2.0-py3-none-any.whl
pip install dist/*.whl           # installs the algovoi-rv-import console script
```

Runtime dependencies (resolved from the AlgoVoi index / bundle): `algovoi-records-vault`,
`algovoi-doc-archive`, `substrate2`, `pqcrypto`, `rfc8785`. It ships inside the AV-VCS bundle; the runtime
licence gate (`licensing.require_license`) fails closed if no valid licence is present.

## Test

Two standalone, runnable suites (need `pqcrypto` + `rfc8785` + `substrate2` importable):

```bash
python tests/test_importer.py        # signing strategies, bridge/store, resume, proofs, licence gate
python tests/test_cli_watcher.py     # CLI import + idempotent re-run + verify; watcher quiescence + fail-closed
```

The CLI/watcher suite bypasses the licence gate for the unit run and uses an injected clock so the
watcher test is deterministic and instant. Clean-box check (fresh container, install the wheel, run a
real import against a temp estate) mirrors the fleet clean-box discipline:

```bash
docker run --rm python:3.11-slim bash -c '
  pip install -q --extra-index-url https://pip.algovoi.co.uk/simple/ algovoi-records-vault-importer &&
  algovoi-rv-import --version'
```

## Performance

Throughput is dominated by file size, so figures are only meaningful with the size stated. Two reference
points, both measured on a VM2-class host, importing into a Falcon-1024-signed archive:

| Files | merkle / bridge | merkle / store | falcon / per-doc |
|-------|-----------------|----------------|------------------|
| ~100 KB | ~6,500 docs/s (~660 MB/s) | ~1,150 docs/s (~120 MB/s) | ~116 docs/s |
| ~512 B  | ~14,000 docs/s | ~2,100 docs/s | ~110 docs/s |

Two facts hold across sizes: **memory is constant** (20,000 documents import in ~90 to 100 MB RSS,
because the source is streamed and each batch is flushed, not buffered) and **merkle signs once per
batch** (one Falcon-1024 signature per `--batch-size` documents), so signing is never the bottleneck on
the bridge lane; hashing and disk are. `store` mode is slower because it also encrypts each document;
`falcon` is signing-bound at roughly one signature per document.

Driving the same import from the **Compliance Command Center Import page** rather than the CLI costs
about 15% on the fast bridge lane (each batch is signed by the console key into the vault the console
browses) and is within measurement noise on `store` and `falcon`. Constant memory holds either way.
