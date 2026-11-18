# AlgoVoi Compliance Gate v2

**A post-quantum, no-PII compliance *decision engine*.** Screen a payer across a composite of
typed checks (sanctions / PEP / jurisdiction / risk / travel-rule — each via *your* provider),
fold them by a **content-addressed policy**, and emit a categorical **ALLOW / REFER / DENY**
verdict that is, in one artifact:

- **no-PII** — the payer is recorded only as `payer_ref = sha256(network:address)`;
- **policy-bound** — carries `policy_ref` + `policy_bound_ref`, so a verdict is provably decided
  under a specific policy and a later **silent policy rotation is detectable** (the record fails to
  recompute under an edited policy);
- **action-bound** — optionally bound to the `action_ref` of the action it gates, so a verdict
  can't be replayed onto a different payment;
- **chained** — hash-linked into an append-only **decision ledger** (tamper-evident, version-provable);
- **explained** — closed-enum `reason_codes` + structured `obligations` (`SAR_REQUIRED`,
  `EDD_REQUIRED`, `STEP_UP_KYC`, `TRAVEL_RULE_FILING`) — audit-grade, machine-actionable, no free text;
- **post-quantum signed** — Falcon-1024 (optional ML-DSA-65 co-signature), offline-verifiable;
- **hub-ready** — emits a Compliance Command Center-ingestable evidence pack (entry_type
  `compliance_gate_verdict`) with a bundled standalone verifier whose trust base is only
  `pqcrypto` + `rfc8785` (no AlgoVoi code required to verify).

The crypto core is `substrate2` throughout. The single-signal `screen_and_certify` path is retained
unchanged — it is the **origination side of [Proofs](../algovoi-proofs)**: the receipt it produces is
exactly the one `algovoi-proofs` binds and proves.

```
  payer address ──▶ ┌──────────────┐  your Screener (sanctions/PEP/AML provider, injected)
  network           │  Compliance  │  ──────────────────────────▶ ALLOW / REFER / DENY
  amount/context    │  Gate        │
                    └──────┬───────┘
        payer_ref = sha256(network:address)   ← content-addressed, NO PII
                           ▼
   Falcon-signed compliance receipt  { screen_result, payer_ref, provider, jurisdiction, timestamp }
                           │
        verify offline (public key)   ·   feed receipt_hash into algovoi-proofs to prove it privately
```

## Why it exists

- **The verdict that Proofs proves.** Proofs shows *that* a payer cleared screening without revealing
  data — but something has to *make* that decision and sign it. The Gate is that something.
- **No PII in the artifact.** The address goes *in* (you have to screen it); only `sha256(network:address)`
  comes *out*. The signed receipt is shareable with a regulator/partner with nothing personal in it.
- **Categorical, audit-grade verdict.** `ALLOW / REFER / DENY` is a closed enumeration — a `REFER` is
  byte-distinct from a `DENY` (the UK POCA-style "this needs a SAR" vs "blocked" distinction), and the
  receipt is post-quantum signed and offline-verifiable.
- **Bring your own screening.** The Gate never holds sanctions data — you inject a `Screener` over your
  provider (Chainalysis, TRM, Elliptic, an internal list…). The Gate orchestrates and certifies.
- **Interoperable by construction.** The receipt format and content hash match `algovoi-proofs`, so a
  Gate receipt drops straight into a Proofs proof.

## What you inject

| Dependency | What it is | How |
|---|---|---|
| **Falcon keypair** | The gate's signing key (SK 2305 B / PK 1793 B) | `ComplianceGate(secret_key=…, public_key=…)` |
| **Screener** | Your sanctions/PEP/AML provider, behind the `Screener` protocol | `ComplianceGate(screener=…)` — `AllowAllScreener`/`DenylistScreener` bundled |
| **API token** *(optional)* | Bearer token gating `/screen` | `create_app(auth_dependency=bearer_token_auth(…))` |

## Install

```bash
pip install algovoi-compliance-gate            # from your private index
pip install "algovoi-compliance-gate[serve]"   # + uvicorn to run the service
```

Python ≥ 3.11. Pure-Python deps only (`fastapi`, `pydantic`, `rfc8785`, `pqcrypto`).

## Run the service

```bash
python examples/run_service.py
# → http://127.0.0.1:8086  (screen, verify, /compliance/verify portal, pqc-keys)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/compliance/screen` | bearer | Screen a payer → signed no-PII compliance receipt. |
| `POST` | `/v1/compliance/verify` | public | Verify a compliance receipt offline. |
| `GET` | `/compliance/verify` | public | Browser portal. |
| `GET` | `/.well-known/pqc-keys.json` | public | The gate's Falcon public key + `kid`. |
| `GET` | `/health` | public | Liveness. |

## Embed directly

```python
from algovoi_compliance_gate import ComplianceGate, DenylistScreener, verify_compliance_receipt, signing

pk, sk = signing.generate_keypair()
gate = ComplianceGate(secret_key=sk, public_key=pk,
                      screener=DenylistScreener(deny={"0xBAD…"}),     # or your own Screener
                      gate_did="did:web:compliance.acme.com")

out = await gate.screen_and_certify(network="base", address="0x…")
#   out["result"] in {ALLOW, REFER, DENY}; out["receipt"], out["receipt_envelope"], out["receipt_hash"]
assert verify_compliance_receipt(out["receipt_envelope"], pk).verified

# feed it to algovoi-proofs to prove it privately (optional):
#   proofs.issue(..., compliance receipt = out["receipt"])  → binds out["receipt_hash"]
```

Implement your provider:

```python
from algovoi_compliance_gate import ScreenResult

class MyScreener:
    async def screen(self, *, network, address, amount_microusd=None, context=None) -> ScreenResult:
        verdict, score = await my_sanctions_provider.check(network, address)   # your call
        return ScreenResult(result=verdict, provider_did="did:web:my-screener", risk_score=score)
```

## Guarantees

- **No PII leaves.** Only `sha256(network:address)` is recorded; the address is never echoed or stored
  in the receipt. (Handle the inbound address over TLS, behind the bearer token.)
- **Closed enumeration.** `screen_result ∈ {ALLOW, REFER, DENY}` — each value is byte-distinct in the hash.
- **Signed + offline-verifiable.** Every receipt is Falcon-1024 signed; verify from the public key alone.
- **Proofs-compatible.** `receipt` shape + `receipt_hash` match `algovoi-proofs` exactly.

## Licence

Commercial — `LicenseRef-AlgoVoi-Commercial-1.0`. Not open source; not published to public
registries. See `LICENSE.md`. Contact **chopmob@gmail.com**.

## Third-party dependencies & attribution

This package **depends on** the following open-source libraries (installed from PyPI under their own licences). AlgoVoi does **not** vendor, copy, or modify them — they are imported as ordinary dependencies, not embedded. All are permissive (MIT / BSD / Apache-2.0); none are copyleft.

| Library | Licence |
|---|---|
| [`fastapi`](https://github.com/fastapi/fastapi) | MIT |
| [`pydantic`](https://github.com/pydantic/pydantic) | MIT |
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
