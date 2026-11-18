# algovoi-zkp-receipt

> **License:** AlgoVoi Commercial License v1.0 — evaluation use only.
> Production / commercial use requires a written Commercial License Agreement.
> Contact: hello@algovoi.co.uk

ZKP-bound payment receipt attestation for agentic x402 payments.

Binds an ATB Phase 2 ZKP credential to a specific on-chain payment receipt.
Proves: *"the agent that made this payment has ATB score ≥ threshold"*
without revealing the exact score.

IETF anchor: `draft-hopley-x402-pqc-credential-binding-00`

## Install

```bash
pip install algovoi-zkp-receipt
pip install "algovoi-zkp-receipt[verify]"   # Falcon-1024 verification
```

## Quick start

```python
from algovoi_zkp_receipt import PaymentReceipt, build_zkp_receipt_payload, verify_zkp_receipt

# Build unsigned payload (send to issuer for signing)
receipt = PaymentReceipt(
    payment_id="pay_abc123",
    chain="algorand",
    amount_microusd=100_000,
    recipient="ALGO...",
    tx_id="TXID...",
    settled_at="2026-06-03T12:00:00Z",
)
payload = build_zkp_receipt_payload(
    receipt=receipt,
    commitment_b64="<from ATB ZKP service>",
    proof_b64="<from ATB ZKP service>",
    threshold_milliunits=700,
    issuer_did="did:algovoi:bench:prod",
    expires_at="2026-06-04T12:00:00Z",
    issued_at="2026-06-03T12:00:00Z",
)

# Verify a signed receipt
result = verify_zkp_receipt(signed_envelope_b64url, pk_b64="<issuer-pk>")
if result.valid:
    print(result.payment_id, result.chain, result.tx_id)
```

## HTTP service

The library also runs as a stateless FastAPI service that bolts into the
substrate-2 control plane. It starts healthy with zero configuration.

Endpoints:

- `POST /build` — construct an unsigned ZKP receipt payload (send to the issuer for signing).
- `POST /verify` — verify a signed ZKP receipt envelope (`envelope_b64url`, with an
  optional per-request `pk_b64`).
- `GET /health` — liveness probe (issuer count).

Configuration (environment variables):

- `ZKP_RECEIPT_ISSUER_PKS` / `ZKP_RECEIPT_ISSUER_PKS_FILE` — issuer PK registry as
  JSON `{"<did>": "<falcon1024-pk-base64>"}`. Optional: `/verify` also accepts a
  per-request `pk_b64`.
- `S2_HUB_URL` — substrate-2 control plane hub. When set, the service live-pulls
  its issuer trust set from `<hub>/v1/issuer-pks` (merged over any local set).
- `S2_HUB_TOKEN` — set with `S2_HUB_URL` to self-register (`POST <hub>/v1/services`)
  so the service appears in the control-plane posture.
- `ZKP_RECEIPT_BIND` — bind address (default `0.0.0.0:8093`).
