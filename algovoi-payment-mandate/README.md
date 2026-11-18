# AlgoVoi Payment Mandate

**The verifiable authorization that makes recurring and agentic crypto payments possible.**

Crypto has no direct debit — no card-on-file, no network that lets you pull funds from a wallet on
a schedule. A **mandate** is the missing primitive: a payer authorizes *once* — "you may charge me
up to **X per period** until **Y**" — and that authorization is **post-quantum signed**,
**offline-verifiable**, **revocable**, and **enforced** on every pull against its per-period cap.

```
  payer authorizes once                    ┌──────────────┐
  "≤ 50 USDC / month until 2027" ────────▶ │   Mandate    │  Falcon-1024 signed
                                            │   issuer     │  envelope (base64url)
                                            └──────┬───────┘
                                                   │ mandate
        ┌───────────── each recurring / agent pull ▼ ───────────────┐
        │  authorize-charge(mandate, charge_id, amount)             │
        │   → checks signature · expiry · revocation · payee        │
        │   → checks amount vs per-charge + PER-PERIOD cap (ledger) │
        │   → authorized / declined  + remaining_this_period        │
        └───────────────────────────────────────────────────────────┘
```

## Why it exists

- **Solves the no-direct-debit problem.** A signed mandate is the authorization a platform needs
  before it can pull a recurring subscription or let an agent spend — the thing card networks give
  you for free and crypto doesn't.
- **Enforced, not just asserted.** Most "mandates" are a signed claim. This one is checked on every
  charge against a **per-period cap** via a store-backed ledger — so the payer's "≤ 50/month" is
  actually held to, with idempotent, double-spend-safe accounting.
- **Quantum-resistant + offline-verifiable.** Falcon-1024 signed; any party verifies with just the
  public key — no callback, no shared infrastructure.
- **Built for agents.** Pairs with [Agent Passport](../algovoi-agent-passport): the Passport says
  *who the agent is and its standing trust*; the Mandate says *what the account holder authorized*.
  Together: "this trusted agent may charge this account up to X." Aligned with AP2-style mandates.
- **Keeps your engine private.** This is the authorization + verification layer; your recurring
  execution engine stays yours.

## What you inject

| Dependency | What it is | How |
|---|---|---|
| **Falcon keypair** | The mandate authority signing key (SK 2305 B / PK 1793 B) | `MandateIssuer(secret_key=…, public_key=…)` |
| **Store** | Persistence for mandates + the charge ledger | `MandateIssuer(store=…)` — `InMemoryStore`/`SqliteStore` bundled, or your own |
| **API token** *(optional)* | Bearer token gating issue / revoke / authorize-charge | `create_app(auth_dependency=bearer_token_auth(…))` |

## Install

```bash
pip install algovoi-payment-mandate            # from your private index
pip install "algovoi-payment-mandate[serve]"   # + uvicorn to run the service
```

Python ≥ 3.11. Pure-Python deps only (`fastapi`, `pydantic`, `rfc8785`, `pqcrypto`).

## Run the service

```bash
python examples/run_service.py
# → http://127.0.0.1:8082  (issue, verify, authorize-charge, revoke, /mandates/verify portal, pqc-keys)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/mandates/issue` | bearer | Mint a signed mandate (payer, payee, cap, period, scope, expiry). |
| `POST` | `/v1/mandates/verify` | public | Verify signature + terms + expiry + revocation. |
| `POST` | `/v1/mandates/authorize-charge` | bearer | Authorize/decline a single pull against the mandate's per-period cap. Idempotent on `charge_id`. |
| `POST` | `/v1/mandates/revoke` | bearer | Revoke a mandate. |
| `GET` | `/v1/mandates/status/{kid}/{mandate_id}` | public | `active` / `revoked` / `expired` / `unknown`. |
| `GET` | `/mandates/crl/{kid}.json` | public | Cacheable revocation list. |
| `GET` | `/mandates/verify` | public | Browser portal. |
| `GET` | `/.well-known/pqc-keys.json` | public | The authority's Falcon public key + `kid`. |

### Issue → authorize a charge

```bash
curl -X POST localhost:8082/v1/mandates/issue -H "Authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{
    "payer":"acct:alice","payee":"merchant:acme","max_amount":50000000,"period":"month",
    "scope":["subscription"],"asset":"USDC"}'
# → { "mandate_id":"…", "mandate":"eyJ…", "kid":"…", "expires_at":"…" }

curl -X POST localhost:8082/v1/mandates/authorize-charge -H "Authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{
    "mandate":"eyJ…","charge_id":"inv-2026-06","amount":20000000}'
# → { "authorized":true, "period":"month", "period_key":"2026-06",
#     "period_total_after":20000000, "remaining_this_period":30000000 }
```

A second charge that would breach the monthly cap returns `{"authorized": false,
"decline_reason": "PERIOD_CAP_EXCEEDED", ...}`. Re-presenting the same `charge_id` returns the
original decision (`idempotent: true`) and never double-counts.

## Embed directly

```python
from algovoi_payment_mandate import MandateIssuer, InMemoryStore, verify_mandate, signing

pk, sk = signing.generate_keypair()
issuer = MandateIssuer(secret_key=sk, public_key=pk, store=InMemoryStore())

out = await issuer.issue(payer="acct:alice", payee="merchant:acme",
                         max_amount=50_000_000, period="month")        # 50 USDC/mo (micro-USD)
assert (await verify_mandate(out["mandate"], pk)).verified

ok  = await issuer.authorize_charge(mandate=out["mandate"], charge_id="c1", amount=20_000_000)
assert ok.authorized and ok.remaining_this_period == 30_000_000
```

## Guarantees

- **Never fails open.** A malformed/tampered mandate verifies `false`; an unverifiable mandate
  cannot authorize a charge; the per-period cap is enforced on every pull.
- **Idempotent, double-spend-safe.** `charge_id` is the idempotency key; declines are recorded so a
  retry can't slip a second charge through.
- **Amounts are integers in the asset's minor units** (e.g. micro-USD) — no floating point.
- **No fund movement.** This authorizes and accounts; your execution layer does the on-chain pull.

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
