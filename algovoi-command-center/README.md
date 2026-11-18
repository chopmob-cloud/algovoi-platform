# algovoi-command-center — Compliance Command Center

Self-hosted compliance management layer for the AlgoVoi estate. Ingests exported evidence packs,
**re-verifies every signed chain offline** (trust base: `pqcrypto` + `rfc8785` only), aggregates a
compliance-posture dashboard, and exports a consolidated auditor pack.

**Proven, not asserted** — every figure on the dashboard is recomputed from a Falcon-1024 signed,
hash-linked chain; the auditor re-verifies the exported pack independently, with no AlgoVoi service.

Commercial product; runtime-licensed. v1: read-only web app. Enterprise auth (RBAC/ACL, LDAP/AD +
OIDC/SAML SSO) and BYO-key custody for the console key are the next build phases.

```bash
COMMAND_CENTER_INGEST_DIR=/path/to/evidence-packs algovoi-command-center   # serves on :8200
```

## Records-Vault secure ingest

For bulk volumes that would be impractical to push through the browser, the console drives the
`algovoi-records-vault-importer` add-on directly against a **server-visible folder** and Merkle-batch-signs
the whole estate into the same Records Vault it browses. The browser is never the data path, so volume is
bounded by disk and hashing, not by an HTTP upload. Ingest surfaces (one page, `/ingest`):

- **Secure ingest** — SFTP/rsync landing zones under `COMMAND_CENTER_INGEST_DIR` (default
  `./evidence-ingest`): the root plus each immediate subdir as a per-source drop folder, with live file
  counts. The console only *reads* the landed files; the jailed, write-only drop (chroot SFTP +
  `rrsync -wo`) is provisioned on the host, not by the console.
- **Import** — one-shot import of a server path. Strategy `merkle` (one Falcon-1024 signature per batch)
  or `falcon`; mode `bridge` (hashes only), `store` (also encrypts and stores bytes). Re-runs are
  idempotent (dedup by content), so a restart never double-commits.
- **Watcher** — a folder watcher that imports whenever a drop folder goes quiescent, for a standing feed.

Writers are serialized — one import OR the watcher at a time — so the signed archive chain stays linear.
Host-side provisioning of the write-only drop is documented in the `docs/SECURE_INGEST.md` runbook.
