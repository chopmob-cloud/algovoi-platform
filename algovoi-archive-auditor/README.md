# AlgoVoi Archive Auditor

**Reporting & auditing for the [Verifiable Archive](../algovoi-doc-archive).** Runs **read-only**
over the same storage backend (local filesystem or S3) and turns the archive's tamper-evident chain
into the things auditors, regulators, and compliance teams actually need — then **feeds your existing
SIEM / observability / GRC tools** instead of reinventing them.

```
                          ┌──────────────────── Archive Auditor ────────────────────┐
  archive storage  ─────▶ │ verify chain · sign reports · attest · retention · pack  │
  (local FS or S3,        └───────┬───────────────────────────────────┬─────────────┘
   read-only)                     │ cryptographic outputs              │ export adapters
                    Falcon-signed audit report                  SIEM  (JSON-lines / syslog / CEF)
                    continuous integrity attestation            Grafana (Prometheus /metrics)
                    retention / compliance report               GRC / BI (CSV)
                    records inventory · evidence pack
```

## What it produces

- **Signed audit reports** — verify the whole chain and emit a Falcon-1024-signed report
  (*N entries, head hash X, intact at T, period A–B, totals by type*). Offline-verifiable evidence.
- **Continuous integrity attestation** — scheduled, chained "still intact as of T" proofs →
  provable *continuous* custody (what 17a-4 / MiFID audits want, not a one-off check).
- **Retention / compliance reports** — apply a retention policy (per content type) and flag records
  `over` / `within` retention.
- **Records inventory** — every entry's metadata (type, size, date, encryption, stored vs hash-only).
- **Evidence packs** — a portable, signed bundle (selected entries + manifest + the archive public
  key) a regulator/court can verify independently.

## Export adapters (feed existing tools, don't replace them)

| Target | Adapter |
|---|---|
| Splunk / Elastic / Datadog | `exporters.to_jsonl` (JSON-lines) — also at `GET /v1/audit/events.jsonl` |
| Any syslog SIEM | `exporters.to_syslog` (RFC 5424) |
| ArcSight / SIEM | `exporters.to_cef` (CEF) |
| Grafana / alerting | `exporters.to_prometheus` — scrape `GET /metrics` |
| GRC / BI (AuditBoard, ServiceNow, …) | `exporters.to_csv` |

> The auditor owns the **cryptographic** part (signed verification + attestation + evidence pack);
> it *exports* to the commoditised dashboard/alert/GRC layer rather than competing with it.

## Install

```bash
pip install algovoi-archive-auditor      # pulls in algovoi-doc-archive
# add the S3 backend if your archive lives in object storage:
pip install algovoi-doc-archive-s3
```

## Use

```python
from algovoi_doc_archive import signing
from algovoi_doc_archive import LocalFsBackend            # or: from algovoi_doc_archive_s3 import S3Backend
from algovoi_archive_auditor import Auditor, RetentionPolicy, create_app, exporters

backend = LocalFsBackend("./archive-data")               # the SAME store the archive writes to
rpk, rsk = signing.generate_keypair()                    # the auditor's own attestation key

auditor = Auditor(archive_public_key=archive_pk, storage=backend,
                  report_secret_key=rsk, report_public_key=rpk,
                  retention_policy=RetentionPolicy(default_days=2557))   # ~7 years

report = await auditor.audit_report()                    # signed, offline-verifiable
events = await auditor.siem_events()
splunk_payload = exporters.to_jsonl(events)

app = create_app(auditor)                                # serves /v1/audit/* + /metrics
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/v1/audit/report` | public | Signed audit report (verify + summarise the chain). |
| `GET` | `/v1/audit/inventory` | public | Records inventory. |
| `POST` | `/v1/audit/retention` | public | Retention/compliance report for a supplied policy. |
| `POST` | `/v1/audit/attest` | bearer | Signed continuous-integrity attestation. |
| `POST` | `/v1/audit/evidence-pack` | bearer | Portable signed evidence bundle. |
| `POST` | `/v1/audit/verify-report` | public | Verify a signed report/attestation/manifest. |
| `GET` | `/metrics` | public | Prometheus exposition. |
| `GET` | `/v1/audit/events.jsonl` | public | SIEM feed (JSON-lines). |
| `GET` | `/audit/verify` | public | Browser portal. |

## Notes

- **Read-only.** The auditor never writes to the archive; it cannot alter entries, only verify them.
- **Separate provenance.** Reports are signed with the auditor's own key (distinct from the archive's),
  so "who archived" and "who audited" are cryptographically distinct.
- **Hard WORM** is a storage-layer concern (S3 Object Lock / worm media) — the auditor proves
  tamper-*evidence*; pair with storage immutability for enforced WORM.

## Licence

Commercial — `LicenseRef-AlgoVoi-Commercial-1.0`. Not open source; not published to public
registries. See `LICENSE.md`. Contact **chopmob@gmail.com**.

## Third-party dependencies & attribution

This package **depends on** the following open-source libraries (installed from PyPI under their own licences). AlgoVoi does **not** vendor, copy, or modify them — they are imported as ordinary dependencies, not embedded. All are permissive (MIT / BSD / Apache-2.0); none are copyleft.

| Library | Licence |
|---|---|
| [`fastapi`](https://github.com/fastapi/fastapi) | MIT |
| [`pydantic`](https://github.com/pydantic/pydantic) | MIT |
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
