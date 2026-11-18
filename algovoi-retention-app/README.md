# AlgoVoi Retention App

**Commercial / local-only.** Stateful payment-receipt retention service. Builds
on the public `algovoi-retention-chain` primitive (the open reference) and adds
the sellable product:

- A **DSN-backed, append-only, per-issuer retention store** (SQLite default,
  Postgres via the same DSN). The caller supplies only a receipt hash; the
  service derives the sequence, the previous link, and the `retention_chain_ref`.
- A **Falcon-1024 signed, offline-verifiable evidence pack** (the `.epi`
  pattern), which is simultaneously the regulator pack and a **Compliance
  Command Center** ingestable pack (entry_type `retention_chain_link`).
- **CCC bolt-in**: live service health (self-registers on boot) and signed
  evidence posture, mapped to **MiCA Art. 68(9), DORA Art. 17, AMLR Art. 77**.

Trust is store-independent: every `chain_ref` is content-addressed and every
exported pack is re-verifiable offline with `pqcrypto` + `rfc8785` +
`algovoi-retention-chain` only. A database swap or corruption cannot forge a
chain.

## Run

```
pip install -e ".[serve]"
algovoi-retention-app-serve            # 0.0.0.0:8097
```

To bolt into a Compliance Command Center:

```
CCC_HUB_URL=http://command-center:8200 CCC_HUB_TOKEN=<service token> \
CCC_HUB_NAME=retention-app CCC_HUB_SELF_URL=http://retention-app:8097 \
algovoi-retention-app-serve
```

## API

| Method/Path | Purpose |
|---|---|
| `POST /v1/receipts` | ingest a receipt hash; returns the derived record |
| `GET  /v1/chains/{issuer}` | the issuer's chain records |
| `POST /v1/verify` | verify a sequence of records (contiguous or subset) |
| `GET  /v1/export/{issuer}` | signed evidence pack (zip) for one issuer |
| `GET  /v1/export` | signed evidence pack (zip) for all issuers |
| `GET  /v1/posture` | per-issuer compliance posture |
| `GET  /health` | liveness |

Licensed under LicenseRef-AlgoVoi-Commercial. Not published to public indexes.
