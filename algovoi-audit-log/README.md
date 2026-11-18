# AlgoVoi Verifiable Audit Log

**A tamper-evident, post-quantum chain of business events.** Append any event — a payment decision,
an admin action, a config change, a compliance verdict — and it is content-addressed and recorded as
a **Falcon-1024-signed** entry linked to the previous one. The result is an **append-only log** anyone
can verify offline: no entry can be **altered, inserted, removed, reordered, or back-dated**.

It is the [Verifiable Archive](../algovoi-doc-archive) chain generalised from *documents* to
*arbitrary events* — the event is recorded inline (no blob store, no encryption needed), so it's a
lightweight, immutable system-of-record for anything you need an auditor to trust.

```
  append(event_type, event, actor)
     ──▶ sha256(JCS event)                          (content address)
     ──▶ Falcon-signed entry, linked to the previous one (prev_entry_hash)

  append-only chain:   e0 ◀─ e1 ◀─ e2 ◀─ … ◀─ head

  verify offline (public key only):  every entry signed · sequential · hash-linked · event-consistent
                                     ⇒ nothing altered, inserted, removed, reordered, or back-dated
```

## Why it exists

- **An audit trail you can prove.** A database audit table can be edited by whoever owns the database.
  This chain is cryptographic: tampering is detectable from the public key alone, by anyone.
- **Post-quantum and long-lived.** Falcon-1024 signing means a record written now stays verifiable
  past the migration to post-quantum cryptography — the right horizon for retained audit logs.
- **Offline, vendor-independent.** Verification is a pure function of the entries and the public key.
  Hand an auditor the log and the key; they verify it themselves, no service required.
- **Record anything.** The event is an arbitrary JSON object, content-addressed and recorded inline —
  payments, decisions, access events, config/state changes, compliance verdicts.
- **Optionally Substrate 2-bound.** Entries fold into the broader [Substrate 2](/substrate-2) evidence
  chain alongside receipts and document evidence.

## What you inject

| Dependency | What it is | How |
|---|---|---|
| **Falcon keypair** | The log's signing key (SK 2305 B / PK 1793 B) | `AuditLog(secret_key=…, public_key=…)` |
| **Store** | Append-only persistence for the entries | `AuditLog(store=…)` — `InMemoryStore`/`SqliteStore` bundled, or your own |
| **API token** *(optional)* | Bearer token gating `/append` | `create_app(auth_dependency=bearer_token_auth(…))` |

## Install

```bash
pip install algovoi-audit-log            # from your private index
pip install "algovoi-audit-log[serve]"   # + uvicorn to run the service
```

Python ≥ 3.11. Pure-Python deps only (`fastapi`, `pydantic`, `rfc8785`, `pqcrypto`).

## Run the service

```bash
python examples/run_service.py
# → http://127.0.0.1:8087  (append, verify, verify-chain, entry, /audit-log/verify portal, pqc-keys)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/audit-log/append` | bearer | Append an event → signed chain entry. |
| `POST` | `/v1/audit-log/verify` | public | Verify a single entry's signature + event-hash. |
| `GET` | `/v1/audit-log/verify-chain` | public | Verify the whole chain's integrity and ordering. |
| `GET` | `/v1/audit-log/entry/{seq}` | public | Fetch an entry receipt + payload. |
| `GET` | `/audit-log/verify` | public | Browser portal. |
| `GET` | `/.well-known/pqc-keys.json` | public | The log's Falcon public key + `kid`. |
| `GET` | `/health` | public | Liveness + entry count. |

## Embed directly

```python
from algovoi_audit_log import AuditLog, InMemoryStore, verify_chain, signing

pk, sk = signing.generate_keypair()
log = AuditLog(secret_key=sk, public_key=pk, store=InMemoryStore())   # or SqliteStore("audit.db")

e = await log.append(event_type="payment.authorized",
                     event={"payment_id": "pay_1", "amount_microusd": 1_500_000, "decision": "ALLOW"},
                     actor="did:web:gateway")
assert (await log.verify_chain()).valid                              # whole-chain integrity

# read-only / verify view (no secret key) — can verify, cannot append:
reader = AuditLog(public_key=pk, store=log.store)
assert (await reader.verify_chain()).valid
```

## Guarantees

- **Tamper-evident.** Any alteration, insertion, deletion, reorder, or back-date breaks `verify-chain`.
- **Event-consistent.** Each entry pins `event_hash = sha256(JCS(event))`; swapping the event is caught.
- **Append-only.** The store interface has no update or delete; `append` is single-writer per log.
- **Read-only verification.** Construct an `AuditLog` without the secret key to verify without writing.

> **Hard immutability** is a storage-layer concern: the chain proves tamper-*evidence*. For
> write-once enforcement, back it with append-only / WORM storage (S3 Object Lock, an append-only DB).

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
