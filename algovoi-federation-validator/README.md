# algovoi-federation-validator

> **License:** AlgoVoi Commercial License v1.0 — evaluation use only.
> Production / commercial use requires a written Commercial License Agreement.
> Contact: hello@algovoi.co.uk

Cross-issuer ZKP federation token validator for agentic payment credentials.

Compose independent Falcon-1024 / ML-DSA-65 PQC credentials from different
issuers into a single federation token. **No shared trust root required.**

IETF anchors: `draft-hopley-x402-pqc-credential-binding-00`,
`draft-hopley-x402-federation-zkp-00`

## Install

```bash
pip install algovoi-federation-validator
# Full signature verification (Falcon-1024):
pip install "algovoi-federation-validator[verify]"
```

## Quick start

```python
from algovoi_federation_validator import FederationValidator

validator = FederationValidator(
    validator_secret=b"...",   # 32+ random bytes, held only by the validator
    issuer_pks={
        "did:algovoi:bench:prod": "<falcon1024-pk-base64>",
        "did:algovoi:bench:eu":   "<falcon1024-pk-base64>",
    },
)

result = validator.compose([cert_a_b64url, cert_b_b64url])
if result.valid:
    # Present result.token.raw as X-Fed-Credential header
    print(result.token.fed_commitment_hex)
```

## Protocol summary

1. Each credential is verified independently against its issuer's public key
   (Falcon-1024 signature over JCS-canonical payload, plus Bulletproofs ZKP
   field shape check).
2. A per-composition nonce is sampled (`os.urandom(32)`).
3. A composite commitment is computed:
   `fed_commitment = SHA-256(domain || comm_0 || comm_1 || … || nonce)`
4. A federation token is issued: HMAC-SHA256-signed JSON envelope containing
   the composite commitment, issuer list, and validity window.
5. The validator signs with its own key — neither issuer is involved.

## HTTP service

The validator also runs as a stateless FastAPI microservice that bolts into the
substrate-2 control plane.

Endpoints:

- `POST /compose` — verify N PQC credentials and return a composite federation token.
- `POST /verify` — verify a federation token's HMAC signature and expiry.
- `GET /health` — liveness probe (issuer count, min credentials, internal-bypass flag).

Configuration (environment variables):

- `FEDERATION_VALIDATOR_SECRET` — hex HMAC key (>= 64 hex chars = 32 bytes). If
  unset, read from `FEDERATION_VALIDATOR_SECRET_FILE`, else bootstrapped and
  persisted under `FEDERATION_DATA_DIR` (default `/app/data`) on first run.
- `FEDERATION_ISSUER_PKS` / `FEDERATION_ISSUER_PKS_FILE` — issuer trust set as
  JSON `{"<did>": "<falcon1024-pk-base64>"}`.
- `FEDERATION_MIN_CREDENTIALS` — minimum credentials to accept (default `2`).
- `FEDERATION_INTERNAL_TOKEN` / `FEDERATION_INTERNAL_TTL_SECS` — optional internal
  service-to-service bypass token (hex) and its token TTL (default `3600`).
- `S2_HUB_URL` — substrate-2 control plane hub. When set, the service live-pulls
  its issuer trust set from `<hub>/v1/issuer-pks` (merged over any local set).
- `S2_HUB_TOKEN` — set with `S2_HUB_URL` to self-register (`POST <hub>/v1/services`)
  so the service appears in the control-plane posture.
- `FEDERATION_BIND` — bind address (default `0.0.0.0:8092`).

An empty trust set is a configure-me state, not a fatal error: the service starts
healthy and the external `/compose` path rejects until issuers are registered.

## CHANGELOG

See [CHANGELOG.md](CHANGELOG.md).
