# algovoi-atb-credential-verifier

Standalone verifier for AlgoVoi ATB Pass Certificates (`X-ATB-Credential` and `X-ATB-ZK-Credential`).

Verifies Falcon-1024 signed Phase 1 certificates and Bulletproofs ZKP Phase 2 certificates. Multi-hub, offline-capable, LRU-cached.

```bash
pip install algovoi-atb-credential-verifier
pip install algovoi-atb-credential-verifier[verify]  # includes Falcon-1024 verification
```

IETF anchor: `draft-hopley-x402-atb-reputation-credential-00`  
Docs: https://docs.algovoi.co.uk/atb-reputation-credential

## Also runs as a hub-federated service

Beyond the library above, the verifier ships a stateless FastAPI service that
bolts into the substrate-2 control plane exactly like `federation-validator` and
`zkp-receipt`. It boots clean with no configuration.

Endpoints:

- `GET /health` — liveness plus the current issuer count.
- `POST /verify` — verify an `X-ATB-Credential` / `X-ATB-ZK-Credential` header
  value (`{"credential": "<base64url>"}`). Fully offline: Falcon-1024 signature
  plus Bulletproofs range proof, no external ZKP service.

Configuration (environment variables):

- `ATB_VERIFIER_ISSUER_PKS` — JSON `{"<did>": "<falcon1024-pk-base64>"}`. Optional.
- `ATB_VERIFIER_ISSUER_PKS_FILE` — path to the same JSON, read when the env var is unset.
- `S2_HUB_URL` — substrate-2 control plane hub. When set, the service live-pulls
  its issuer trust set from `<hub>/v1/issuer-pks` (merged over any local set).
- `S2_HUB_TOKEN` — set with `S2_HUB_URL` to self-register (`POST <hub>/v1/services`)
  so the service appears in the control-plane posture.
- `ATB_VERIFIER_BIND` — bind address (default `0.0.0.0:8095`).

An empty trust set is fine: the service starts healthy and `/verify` rejects
until issuers are registered.

### Docker

```bash
docker build -t algovoi-atb-credential-verifier .
docker run -p 8095:8095 \
  -e S2_HUB_URL=http://control-plane:8080 \
  -e S2_HUB_TOKEN=<hub-token> \
  algovoi-atb-credential-verifier
```
