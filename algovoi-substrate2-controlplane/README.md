# algovoi-substrate2-controlplane

> **License:** AlgoVoi Commercial License v1.0 — evaluation use only.

A lean, self-hosted control plane for the **substrate-2 federation + ZK-proof**
services. It bridges three services and accepts bolt-on addons — and contains
**none** of the platform monolith (no payments, KYC, sanctions, compliance).

## What it does

1. **Issuer trust registry** — the single source of truth for issuer DID →
   Falcon-1024 public key. The federation + ZK services pull their trust set
   from here instead of each being configured independently.
2. **Service bridge** — registers the substrate-2 services
   (`federation-validator`, `zkp-receipt`, `atb-credential-verifier`) plus any
   bolt-on addon, and reports a unified health posture.
3. **Signed audit** — every trust change is appended to an HMAC-chained log.

It serves the trust set in every shape the three services already consume:

| Endpoint | Shape | Consumed by |
|---|---|---|
| `GET /v1/issuer-pks` | `{did: pk_b64}` | federation-validator, zkp-receipt (`*_ISSUER_PKS`) |
| `GET /.well-known/atb-keys.json` | canonical hub doc | atb-credential-verifier (`hub_resolver`) |
| `GET /issuers/{did}/atb-keys.json` | per-issuer doc | multi-hub deployments |

## Out of the box

A bare `docker run` generates its admin token + audit key and comes up healthy
with an empty registry. Air-gap capable.

**Persistence:** SQLite by default (a single file under `S2CP_DATA_DIR`, stdlib,
no server). Set `S2CP_DB` to a `postgresql://...` DSN to use PostgreSQL instead
(`pip install '.[postgres]'`) — same SQL, same code, so a SQLite deployment can be
moved to Postgres later without a rewrite.

```bash
docker run --rm algovoi-substrate2-controlplane:clean python scripts/acceptance.py
```

## Substrate-neutral registry

The control plane can register the existing substrate families without changing their
canonical evidence contracts. Register an adapter with the family, version, capability
set and health endpoint:

```bash
curl -X POST http://localhost:8094/v1/substrates \
  -H "Authorization: Bearer ${S2CP_ADMIN_TOKEN}" -H "Content-Type: application/json" \
  -d '{"name":"payment-rails","family":"payment-rails","version":"1",\
       "adapter":"payment-rails","base_url":"http://payment-rails:8090",\
       "capabilities":["x402","mpp","ap2","a2a"]}'
```

`GET /v1/posture` and the web panel include substrate health, adapter and capability
metadata; both are admin-authenticated reads because they consume persisted topology.
Substrate registration and removal are admin-gated; addon registration requires a name-bound scoped token. Changes are appended to the HMAC audit
chain. The registry is metadata and posture coordination only: it does not canonicalise,
settle or mutate substrate evidence.
Before this request, configure `S2CP_REGISTRATION_TOKEN` and `S2CP_REGISTRATION_NAME=my-addon` on the control plane, and pass the same scoped token to the addon:

```bash
curl -X POST http://localhost:8094/v1/services -H "Authorization: Bearer ${S2CP_REGISTRATION_TOKEN}" \
  -d '{"name":"my-addon","type":"addon","base_url":"http://my-addon:9000"}'
```
