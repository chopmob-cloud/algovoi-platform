# Changelog

## 0.3.0
- **`algovoi-rv-import watch` subcommand.** The folder watcher is now driveable from the CLI (previously
  library-only): `watch --source <dir> --archive <dir> --keys-dir <dir> [--poll-secs --quiescent-secs
  --strategy --mode --batch-size --checkpoint]`. Runs until SIGINT/SIGTERM so it shuts down cleanly under
  systemd, streams committing cycles to stderr, prints a JSON summary on exit. No change to the signing
  core; wraps `watch(...)`.
- **Secure Ingest hardening runbook** (`docs/SECURE_INGEST.md`): a per-tenant chrooted `internal-sftp` +
  `rrsync -wo` write-only landing zone that feeds the watcher, with the chroot ownership rules, sshd
  config, per-tenant account setup, a systemd template, a threat model, and optional hardening (quota,
  per-source keys, dedicated ingest host). Transport is stock OpenSSH/rsync; the value is the governed,
  least-privilege envelope wired into the importer.

## 0.2.0
- Two operator interface options over the same signed-batch importer, plus a use/build/test guide
  (`docs/USAGE.md`):
  - **CLI** `algovoi-rv-import` (`[project.scripts]`): `import <folder>` runs a resumable, idempotent,
    batch-signed import from a designated folder with persistent keys (`--keys-dir`) and streamed
    progress (`--progress`); `verify` checks a document sha against a signed batch envelope. Prints a
    JSON summary.
  - **Folder watcher** `watch(...)` (`watcher.py`): opt-in, stdlib-only polling for continuous
    ingestion. Runs an idempotent import only once the folder is *quiescent* (no size change for
    `quiescent_secs`), so half-written files are never imported; fail-closed (reports and keeps
    watching on error). `clock`/`sleep`/`stop` are injectable for deterministic tests. Off by default.
- No change to the signing core; both options wrap `import_records_fs`.

## 0.1.0
- Initial release. Volume importer add-on for Records Vault with a switchable signing strategy chosen per
  import: `falcon` (one Falcon-1024 signature per document, maximum granularity) or `merkle` (one signature
  per SHA-256 Merkle batch, throughput bounded by read/hash and storage rather than signing). Measured end
  to end on real 100 KB files: merkle bridge ~6,500 docs/s (~660 MB/s), merkle store ~1,150 docs/s
  (~120 MB/s), vs ~116 docs/s per-document falcon (about 56x in bridge mode; size estimates by total
  bytes). Both support bridge and store modes, are idempotent/resumable, stream the source at constant
  memory, and hash the filesystem in parallel. `merkle` batches carry an offline per-document inclusion
  proof (`verify_document_in_batch`, `compact_proof`); the verifier never raises on malformed input.
  Reuses the Records Vault `FsSource` / `SqliteBlobSource` / `S3Source` connectors. Runtime licence
  enforced, fail-closed.
