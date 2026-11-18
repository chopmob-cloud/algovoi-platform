# AlgoVoi Agent Passport

**Post-quantum trust credentials for AI agents.**

Before an autonomous agent moves funds or accesses a resource, the relying party needs a verifiable
answer to one question: *is this agent authorised, for what, up to what limit — and has that
authorisation been revoked?* An **Agent Passport** is a **Falcon-1024-signed**, **offline-verifiable**,
**revocable** credential that answers exactly that, and stays valid into the post-quantum era.

```
  issuer signs a passport                  ┌──────────────┐
  agent_did + scopes + spend limit ──────▶ │   Passport   │  Falcon-1024 signed
  + expiry                                  │   issuer     │  credential (base64url)
                                            └──────┬───────┘
                                                   │ credential
        ┌──────── before granting spend authority ▼ ───────────────┐
        │  verify_passport(credential)                             │
        │   → checks signature · expiry · revocation               │
        │   → optional required_scope / expected_agent_did         │
        │   → verified ; status = active | revoked | expired       │
        └───────────────────────────────────────────────────────────┘
   revoke → cacheable CRL (/passport/crl/{kid}.json); verification fails closed
```

## Why it exists

- **Agent identity as a payments primitive.** A passport is the thing a platform checks before
  letting an autonomous agent spend — scopes, a spend limit, and an expiry bound into one signed
  credential, not a generic API key.
- **Quantum-resistant from day one.** Falcon-1024 signing means a long-lived agent identity stays
  verifiable past the migration to post-quantum cryptography.
- **Offline verification.** A counterparty verifies with only the issuer's public key — no callback,
  no shared infrastructure. The credential proves itself wherever it travels.
- **Revocation that actually ships.** Instant revoke plus a cacheable revocation list, so authority
  can be withdrawn in real time — and verification fails closed.
- **Built for the agentic stack.** Pairs with [Payment Mandate](../algovoi-payment-mandate): the
  Passport says *who the agent is and its standing trust*; the Mandate says *what the account holder
  authorized*. Together: "this trusted agent may charge this account up to X."
- **Optionally Substrate 2-bound.** A verified passport becomes a signed, audit-ready
  [Substrate 2](https://docs.algovoi.co.uk/substrate-2) receipt; reputation via zero-knowledge.

## What you inject

| Dependency | What it is | How |
|---|---|---|
| **Falcon keypair** | The issuer signing key (SK 2305 B / PK 1793 B) | `PassportIssuer(secret_key=…, public_key=…)` |
| **Store** | Persistence for issued passports + revocations | `PassportIssuer(store=…)` — `InMemoryStore`/`SqliteStore` bundled, or your own |
| **API token** *(optional)* | Bearer token gating issue / revoke | `create_app(auth_dependency=bearer_token_auth(…))` |

## Install

```bash
pip install algovoi-agent-passport            # from your private index
pip install "algovoi-agent-passport[serve]"   # + uvicorn to run the service
```

Python ≥ 3.11. Pure-Python deps only (`fastapi`, `pydantic`, `rfc8785`, `pqcrypto`).

## Run the service

```bash
python examples/run_service.py
# → http://127.0.0.1:8080  (issue, verify, revoke, status, /passport/crl, /passport/verify portal)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/passport/issue` | bearer | Mint a signed passport (agent_did, scopes, spend limit + window, expiry). |
| `POST` | `/v1/passport/verify` | public | Verify signature + expiry + revocation; optional `required_scope` / `expected_agent_did`. |
| `GET` | `/v1/passport/status/{kid}/{passport_id}` | public | `active` / `revoked` / `expired` / `unknown`. |
| `POST` | `/v1/passport/revoke` | bearer | Revoke a passport. |
| `GET` | `/passport/crl/{kid}.json` | public | Cacheable revocation list. |
| `GET` | `/passport/verify` | public | Browser portal. |
| `GET` | `/health` | public | Liveness + issuer `kid`. |

### Issue → verify → revoke

```bash
curl -X POST localhost:8080/v1/passport/issue -H "Authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{
    "agent_did":"did:web:agent.example.com","scopes":["payments.send"],
    "spend_limit_microusd":50000000,"spend_window":"per_day"}'
# → { "passport_id":"…", "credential":"eyJ…", "kid":"…", "expires_at":"…", "status_url":"…" }

curl -X POST localhost:8080/v1/passport/verify -H 'content-type: application/json' \
  -d '{"credential":"eyJ…","required_scope":"payments.send"}'
# → { "verified":true, "status":"active", "agent_did":"did:web:agent.example.com",
#     "scopes":["payments.send"], "spend_limit_microusd":50000000, "kid":"…", "expires_at":"…" }
```

After `POST /v1/passport/revoke`, the same credential verifies `{"verified": false, "status":
"revoked"}` and appears on `/passport/crl/{kid}.json`. `spend_window` is one of
`per_tx · per_day · per_week · per_month · total`.

## Embed directly

```python
from algovoi_agent_passport import PassportIssuer, InMemoryStore, verify_passport, signing

pk, sk = signing.generate_keypair()                       # or load a persistent issuer key
issuer = PassportIssuer(secret_key=sk, public_key=pk, store=InMemoryStore())   # or SqliteStore("p.db")

res = await issuer.issue(agent_did="did:web:agent.example.com",
                         scopes=["payments.send"], spend_limit_microusd=50_000_000)
assert (await verify_passport(res["credential"], pk, store=issuer.store)).verified
await issuer.revoke(passport_id=res["passport_id"])
assert (await verify_passport(res["credential"], pk, store=issuer.store)).status == "revoked"
```

## Guarantees

- **Fails closed.** A malformed/tampered credential verifies `false`; an expired one is `expired`; a
  revoked one is `revoked`. Signature and expiry are always enforced; revocation is checked against
  the store.
- **Offline-verifiable.** Verification needs only the issuer public key — no callback to the issuer.
- **Authorization evidence, not enforcement.** The scopes and spend limit are what the credential
  *asserts*; the relying platform still owns the actual spend decision. The passport is the
  authorisation proof, not the spend gate.
- **Amounts are integers in minor units** (micro-USD) — no floating point.

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
