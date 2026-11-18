# AlgoVoi Proofs

**Privacy-preserving compliance proofs.** Mint a zero-knowledge proof that a payment was
screened/compliant **and** the payer's risk score is above a threshold — *without revealing any PII
or the score itself* — then let a counterparty, partner, or regulator verify it independently.

Proofs are **post-quantum signed** (Falcon-1024 / FN-DSA, FIPS 206) and **self-contained**: a
verifier needs only the proof and the issuer's public key. No database, no shared infrastructure, no
call back to the issuer.

```
   payment + screen verdict + score          ┌─────────────┐
   ───────────────────────────────────────▶  │   Proofs    │
   (PII stays on YOUR side, never leaves)     │   issuer    │
                                              └──────┬──────┘
                       range proof (score ≥ threshold)  │ Falcon-1024 signed
                       + compliance receipt hash         ▼
                                              proof_envelope (base64url)
                                                     │
   ┌──────────────────┐   public verify     ┌────────▼──────────┐
   │ partner /        │ ◀──────────────────▶│ /v1/proofs/verify │  → verified, no PII
   │ regulator        │   (no PII, no score) └───────────────────┘
   └──────────────────┘
```

## Why it exists

- **Prove compliance without exposing data.** Share *that* a payer cleared screening and scored
  above your bar — not who they are or what they scored. Solves the "show the regulator, not the
  customer's data" problem.
- **Quantum-resistant attestations.** Every proof is Falcon-1024 signed; it stays verifiable against
  a "harvest-now-decrypt-later" adversary.
- **Zero infrastructure for verifiers.** Verification is a pure function of the proof + the issuer
  public key. Hand a partner the package (or just the public key) and they self-serve.
- **Composite binding.** Each proof binds *both* a Bulletproofs range proof (score ≥ threshold) and
  a content-addressed compliance receipt hash — one envelope attests the whole decision.

## What you inject

| Dependency | What it is | How |
|---|---|---|
| **Falcon issuer keypair** | Your post-quantum signing key (SK 2305 B / PK 1793 B) | `create_app(secret_key=…, public_key=…)` |
| **Prover URL** | A Bulletproofs range-proof service (you run it) | `create_app(prover_url="http://…/")` |
| **API token** *(optional)* | Bearer token gating the issue endpoint | `create_app(api_token=…)` |

The range-proof math is produced by a small stateless service (Ristretto255 Bulletproofs,
transcript `ATB-RangeProof-v1`, scores in milliunits `0..1000`). Point `prover_url` at your
deployment. Everything else — the compliance receipt, the composite hash, the Falcon envelope, and
verification — is **bundled in this package**.

## Install

```bash
pip install algovoi-proofs            # from your private index
pip install "algovoi-proofs[serve]"   # + uvicorn to run the service
```

Requires Python ≥ 3.11. Pure-Python deps only (`fastapi`, `pydantic`, `httpx`, `rfc8785`,
`pqcrypto`).

## Run the service

```bash
python examples/run_service.py
# → http://127.0.0.1:8081  (issue, verify, /proofs/verify portal, /.well-known/pqc-keys.json)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/proofs/issue` | Bearer (if token set) | Build compliance receipt → range proof → Falcon-signed proof envelope. `503` if the prover is unreachable (never fails open). |
| `POST` | `/v1/proofs/verify` | public | Verify the issuer signature + structure; optionally re-check the range proof and the compliance binding. |
| `GET` | `/proofs/verify` | public | Browser portal: paste a proof, see the verdict. |
| `GET` | `/.well-known/pqc-keys.json` | public | The issuer's Falcon public key + `kid`. |
| `GET` | `/health` | public | Liveness + issuer `kid`. |

### Issue

```bash
curl -X POST http://127.0.0.1:8081/v1/proofs/issue \
  -H "Authorization: Bearer $PROOFS_API_TOKEN" -H 'content-type: application/json' -d '{
    "payment": {"payment_id":"pay_1","chain":"algorand","amount_microusd":1500000,
                "recipient":"WHGJ…","tx_id":"TX123","settled_at":"2026-06-01T00:00:00Z"},
    "screen_result": "ALLOW", "score_milliunits": 800, "threshold_milliunits": 600
  }'
# → { "proof_envelope": "eyJ…", "compliance_receipt": {…}, "kid": "…", "expires_at": "…" }
```

### Verify

```bash
curl -X POST http://127.0.0.1:8081/v1/proofs/verify -H 'content-type: application/json' \
  -d '{"proof_envelope":"eyJ…","verify_range_proof":true}'
# → { "verified": true, "payment_id": "pay_1", "chain": "algorand",
#     "threshold_milliunits": 600, "range_proof_valid": true,
#     "compliance_verified": null, "issuer_did": "…", "kid": "…" }
```

Pass the issuer's `compliance_receipt` alongside the envelope to also confirm the composite binding
(`compliance_verified: true`).

## Embed in your own app

```python
from algovoi_proofs import create_app, ProofIssuer, verify_proof

app = create_app(secret_key=sk, public_key=pk, prover_url="http://127.0.0.1:8091",
                 issuer_did="did:web:issuer.acme.com", api_token="…")

# or drive issuance/verification directly:
issuer = ProofIssuer(secret_key=sk, public_key=pk, prover=prover, issuer_did="did:web:issuer.acme.com")
out = await issuer.issue(payment=payment, score_milliunits=800, threshold_milliunits=600)
result = await verify_proof(out["proof_envelope"], pk)
```

## Guarantees

- **No PII in a proof, ever.** The payer reference is `sha256(network:address)`; the score is hidden
  behind a range proof. The envelope carries only payment id, chain, amount, tx id, threshold, and
  the compliance receipt hash.
- **Never fails open.** A missing/unreachable prover yields `503` on issue and a `null`
  (not `true`) range-proof result on verify. A tampered envelope verifies `false`.
- **Interoperable wire format.** The proof envelope matches the AlgoVoi platform's ZKP receipt
  format, so proofs issued here verify on the platform and vice-versa.

## Licence

Commercial — `LicenseRef-AlgoVoi-Commercial-1.0`. Not open source; not published to public
registries. See `LICENSE.md`. Contact **chopmob@gmail.com**.

## Third-party dependencies & attribution

This package **depends on** the following open-source libraries (installed from PyPI under their own licences). AlgoVoi does **not** vendor, copy, or modify them — they are imported as ordinary dependencies, not embedded. All are permissive (MIT / BSD / Apache-2.0); none are copyleft.

| Library | Licence |
|---|---|
| [`fastapi`](https://github.com/fastapi/fastapi) | MIT |
| [`pydantic`](https://github.com/pydantic/pydantic) | MIT |
| [`httpx`](https://github.com/encode/httpx) | BSD-3-Clause |
| [`rfc8785`](https://github.com/trailofbits/rfc8785.py) | Apache-2.0 |
| [`pqcrypto`](https://github.com/kpdemetriou/pqcrypto) | MIT |
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
