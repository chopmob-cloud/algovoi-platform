# AlgoVoi Spend Guardrail

**The decision point for agentic payments.** One self-hosted call a platform makes *before executing
a payment*: verify the agent's **Agent Passport**, run the payer's **Payment Mandate** per-period
cap, apply your **policy**, and get back a **Falcon-1024-signed ALLOW/DENY decision receipt**.

It is the [Agent Passport](../algovoi-agent-passport) + [Payment Mandate](../algovoi-payment-mandate)
**authorization stack wired into a single enforcement gate**. It **moves no funds** — your platform
executes the payment iff the decision is ALLOW.

```
  agent wants to pay
  passport + mandate + {charge_id, amount, payee} ─▶ ┌───────────────┐
                                                      │ Spend         │  1. verify Passport (active? scopes? limit?)
                                                      │ Guardrail     │  2. apply platform policy
                                                      └───────┬───────┘  3. Mandate per-period cap (authorize-charge)
                                                              │              ▼
                              Falcon-signed DECISION receipt: ALLOW / DENY  (+ reasons, remaining_this_period)
                                                              │
                    platform executes the payment ◀────── iff ALLOW        (the guardrail moves no funds)
```

## Why it exists

- **The missing control point.** Passport says *who the agent is*; Mandate says *what the payer
  authorized*. Neither is the single check a platform runs *at the moment of spend*. The Guardrail is.
- **Defence in depth, one call.** Passport validity + scopes + the passport's spend limit + your
  policy (allowlists, per-tx caps) + the mandate's enforced per-period cap — evaluated together,
  fail-closed, in deterministic order.
- **Every decision is evidence.** ALLOW *and* DENY produce a signed, offline-verifiable receipt
  recording who decided, what, and why — an audit trail for every agent spend.
- **Moves no funds.** It returns a decision; your execution layer does the on-chain pull. Low
  regulatory surface — no custody, no settlement.
- **Sells as the authorization stack.** Passport + Mandate + Guardrail is the agentic-payments
  control plane, delivered as one self-hosted product.

## What you inject

| Dependency | What it is | How |
|---|---|---|
| **Agent Passport public key** | verifies agent credentials | `SpendGuardrail(passport_public_key=…, passport_store=…)` |
| **Payment Mandate issuer** | authorizes charges against the per-period cap + ledger | `SpendGuardrail(mandate_issuer=…)` |
| **Decision keypair** | the guardrail's own Falcon key, signs decision receipts | `SpendGuardrail(decision_secret_key=…, decision_public_key=…)` |
| **Policy** *(optional)* | allowlists, per-tx cap, required scope, denied agents | `SpendGuardrail(policy=Policy(…))` |
| **API token** *(optional)* | bearer token gating `/authorize` | `create_app(auth_dependency=bearer_token_auth(…))` |

## Install

```bash
pip install algovoi-spend-guardrail            # pulls in agent-passport + payment-mandate
pip install "algovoi-spend-guardrail[serve]"   # + uvicorn to run the service
```

Python ≥ 3.11.

## Run the service

```bash
python examples/run_service.py
# → http://127.0.0.1:8085  (authorize, verify-decision, /guardrail/verify portal, pqc-keys)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/guardrail/authorize` | bearer | Evaluate a proposed spend → signed ALLOW/DENY decision. |
| `POST` | `/v1/guardrail/verify-decision` | public | Verify a decision receipt offline. |
| `GET` | `/guardrail/verify` | public | Browser portal. |
| `GET` | `/.well-known/pqc-keys.json` | public | The guardrail's decision public key + `kid`. |
| `GET` | `/health` | public | Liveness. |

## Embed directly

```python
from algovoi_agent_passport import PassportIssuer, InMemoryStore as PStore, signing
from algovoi_payment_mandate import MandateIssuer, InMemoryStore as MStore
from algovoi_spend_guardrail import SpendGuardrail, Policy, verify_decision

ppk, psk = signing.generate_keypair()   # passport issuer
mpk, msk = signing.generate_keypair()   # mandate authority
gpk, gsk = signing.generate_keypair()   # guardrail decision key

mandate_issuer = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore())
guard = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mandate_issuer,
                       decision_secret_key=gsk, decision_public_key=gpk,
                       policy=Policy(max_amount_per_tx=25_000_000, required_scope="payments.send"))

d = await guard.authorize(passport_credential=cred, mandate=mandate,
                          charge_id="inv-1", amount=20_000_000, payee="merchant:acme")
if d.allowed:                            # d.decision == "ALLOW", d.remaining_this_period set
    ...                                  # execute the payment
assert verify_decision(d.decision_receipt, gpk).verified
```

## Guarantees

- **Moves no funds.** The Guardrail authorizes and accounts; your execution layer does the pull.
- **Deterministic, fail-closed order:** passport → policy + spend limit → mandate per-period cap. The
  **mandate ledger is only consumed when everything else passes** — a policy-denied charge never eats
  the period cap.
- **Every decision signed.** ALLOW and DENY both yield a Falcon-1024 decision receipt that verifies
  offline from the public key — a complete, tamper-evident audit trail of agent spend.
- **Amounts are integers in minor units** — no floating point.

## Security

An adversarial code audit of the engine, service, and examples — threat model, findings, and fixes —
is in [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) (v0.2.0). It assumes an attacker controls every HTTP
input and covers forging an ALLOW, exhausting a mandate cap, bypassing a policy control, or corrupting
the audit trail. Note H1: leaving `GUARDRAIL_API_TOKEN` unset leaves `/authorize` unauthenticated — set
a bearer token in production.

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
