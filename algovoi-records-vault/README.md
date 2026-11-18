# AlgoVoi Records Vault

Regulated-records preservation on the AlgoVoi PQC Verifiable Archive — the migration on-ramp and
product facade for bringing existing records (filesystem, SQLite blob tables, S3-compatible object
stores) into a tamper-evident, post-quantum, offline-verifiable archive.

Composes `algovoi-doc-archive` (Falcon-1024 signing, ML-KEM-1024 + AES-256-GCM at rest, SHA-256
hash-linked chain). **No cryptography is reimplemented in this package.**

## What it does

- **`migrate(archive, source, mode=...)`** — `"bridge"` notarizes content hashes without moving
  bytes (zero-disruption on-ramp: any later change to a source record is detectable);
  `"store"` pulls bytes, ML-KEM-encrypts, and stores them (legacy store can be decommissioned).
  Idempotent / content-addressed: re-runs skip records already in the chain.
- **`reconcile` + `sign_manifest` / `verify_manifest`** — Falcon-1024-signed, offline-verifiable
  migration manifest proving the migrated set is complete and matches the source.
- **`detect_drift`** — flags bridged records whose source bytes changed after notarisation.
- **Sources** — `FsSource` (directory trees), `SqliteBlobSource` (blob tables, `WHERE`-scoped),
  `S3Source` (AWS S3 / MinIO / R2 via boto3, prefix-scoped). All yield deterministic, ref-ordered
  record streams so manifests are stable.
- **`RecordsVault`** — the product facade composing all of the above over an `Archive`;
  enforces a valid `algovoi-records-vault` OEM licence fail-closed at construction.

## The served vault (access-controlled evidence surface)

Beyond the one-shot migration on-ramp, the package runs as a long-lived **served vault** over the same
Falcon-1024-signed, offline-verifiable chain. Every capability below appends to its own append-only
`_VaultStream`, so *what happened and who did it* is itself tamper-evident evidence.

- **Access control (ACL + principals).** `ACLRegistry` records signed `(principal, resource, actions)`
  grants (resource = `doc_hash` / `matter_id` / `"*"`; actions = `read` / `notarize` / `hold` /
  `release` / `"*"`, with optional expiry) and answers `check` offline from the chain. A `Principal`
  is the minimal accountable identity (DID + authenticating key id + scopes) recorded on every
  evidence event; a denial (fail-closed on a corrupt or expired grant) is logged.
- **Read-access audit log (F3).** `AccessLog` wraps `Archive.retrieve` and seals a signed
  `granted` / `denied` `access_event` (principal, doc hash, reason) *before* returning or re-raising —
  the HIPAA §164.312(b) read trail the base archive does not provide. `to_jsonl` exports for SIEM/GRC.
- **Legal hold / e-discovery (F2).** `LegalHoldRegistry` sets and releases matter holds as signed
  entries; `RetentionPolicy` treats a held record as **never disposable**, so preservation overrides
  routine retention. A release is itself blocked until the preservation window passes.
- **Consent + GDPR bridge (F5).** `ConsentLedger` records signed consent receipts (pinned `terms_hash`,
  authorised uses, optional expiry; revocation is a new linked entry) answering `is_authorized` /
  `verify_consent` offline. `LegalHoldBridge` optionally mirrors vault holds onto control_plane's
  payment-ledger GDPR purge gate (best-effort, no-op unless a bridge URL + admin token are set); the
  vault chain stays the system-of-record.
- **Redaction + crypto-shred (F4).** `redact` emits a signed redacted *derivation* as a new record
  (original stays sealed), and `seal_fields` / `unseal_field` / `crypto_shred` erase a single field by
  dropping its per-field AES-256-GCM key while the record and a signed proof it existed survive.
- **Custody + key longevity (F6/F7).** `CustodyLog` records a signed, cross-signable chain of custody
  (batch attestations + custodian handoffs naming the prior custodian). `Keyring` records cross-signed
  `old → new` rotation proofs and emits the `/.well-known/pqc-keys.json` structure, so records outlive
  the keys that signed them and stay verifiable across decades of rotation.

### Running it as a service

`serve.py` builds `algovoi_doc_archive.create_app` from environment config and adds one thing on top:
a startup hook that self-registers with the Compliance Command Center (via `hub_client`) when the
`CCC_HUB_*` env vars are set, so the vault appears in the console's "Live service health" panel.

```bash
algovoi-records-vault-serve            # console script (pip install '...[serve]')
# or: uvicorn algovoi_records_vault.serve:app
```

Configure via `RV_ARCHIVE_DIR` / `RV_ARCHIVE_KEY_FILE` / `RV_ARCHIVE_TOKEN` / `RV_ARCHIVE_AES_KEY_B64`
/ `RV_SERVE_HOST` / `RV_SERVE_PORT`, and the `CCC_HUB_URL` / `CCC_HUB_TOKEN` / `CCC_HUB_NAME` /
`CCC_HUB_SELF_URL` set for Command Center registration. Registration is best-effort and never raises,
so an absent or unreachable Command Center cannot stop the vault from booting.

## Quickstart

```python
from algovoi_doc_archive.archive import Archive
from algovoi_records_vault import RecordsVault, S3Source

vault = RecordsVault(archive=archive, signing_secret_key=sk, signing_public_key=pk)
result = await vault.migrate(S3Source(s3, bucket="legacy", prefix="health/"), mode="bridge")
manifest = await vault.reconcile(source)
envelope = vault.sign_manifest(manifest)        # offline-verifiable with the public key alone
```

## Licence

Commercial — AlgoVoi Commercial Licence v1.0 (`LicenseRef-AlgoVoi-Commercial-1.0`).
Set `ALGOVOI_LICENSE_KEY` or `ALGOVOI_LICENSE_FILE`. Not for redistribution. See `LICENSE.md`.
