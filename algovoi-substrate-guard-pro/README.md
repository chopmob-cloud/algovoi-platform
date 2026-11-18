# AlgoVoi Substrate Guard (Pro)

Verifiable admission control for the JCS (RFC 8785) canonicalization substrate. The commercial parent of
the open [`algovoi-substrate-guard`](https://pypi.org/project/algovoi-substrate-guard/) lite gate.

A deterministic input-bounds gate runs **before** canonicalization and rejects a well-formed but hostile
payload with a **named code**, never truncating or repairing. On top of the lite tier's structural bounds
(size / depth / object-keys / array-length / string-length / total-nodes / number-safety) it adds the
bound a differential fuzz of **nine independent JCS implementations** proved was missing:

* **`string_safety` → `REJECT_INVALID_UTF8`** — a string (value or object key) that is not valid UTF-8
  (a lone surrogate such as `"\ud800"`, or any non-scalar code unit) is rejected. The fuzzer showed that
  on such input AlgoVoi's Python canonicalizer (rfc8785) fail-closes while the Node canonicalizer
  (canonicalize 3.0.0) accepts and emits bytes — two conforming impls disagreeing at the input-domain
  boundary. Rejecting it here, in one pass, makes the two behave identically regardless of which
  canonicalizer runs next.

Every ADMIT/REJECT is recorded as a **Falcon-1024** (optionally **hybrid ML-DSA-65**) signed,
content-addressed, hash-linked decision:

* `profile_ref` — the content address of the bounds in force (pinnable; rotation-detectable).
* `subject_ref` — for an ADMIT, the canonical content address of the admitted value.
* `guard_decision_ref` — binds the verdict to the profile, and to the subject (ADMIT) or the named code
  (REJECT). No payload is carried (no-PII; a rejected value may not be canonicalisable).

The chain exports as the same no-PII evidence pack the **Compliance Command Center** ingests
(`entry_type = "guard_decision"`), offline-verifiable next to settlement, spend, passport, and mandate
evidence. Altering or dropping one decision breaks the chain from that point on.

```python
from algovoi_substrate_guard_pro import GuardService, signing, verify_guard_chain

pk, sk = signing.generate_keypair()
gate = GuardService(decision_secret_key=sk, decision_public_key=pk)

r = gate.evaluate({"agent": "acct:alice", "amount": 25_000_000})
assert r.admitted and r.subject_ref.startswith("sha256:")

bad = gate.evaluate({"a": "\ud800"})           # lone surrogate
assert not bad.admitted and bad.reject_code == "REJECT_INVALID_UTF8"

assert verify_guard_chain(gate.ledger.envelopes, pk).verified   # the admission log verifies offline
```

Run as a service (`pip install 'algovoi-substrate-guard-pro[serve]'`):

```python
from algovoi_substrate_guard_pro import GuardService, signing
from algovoi_substrate_guard_pro.app import create_app, bearer_token_auth
pk, sk = signing.generate_keypair()
app = create_app(GuardService(decision_secret_key=sk, decision_public_key=pk),
                 auth_dependency=bearer_token_auth("my-token"))
# uvicorn module:app
```

Persistence is pluggable (`AdmissionStore`, SQLite by default / Postgres via `SUBSTRATE_GUARD_DB`); the
signing key is injected; licence enforcement is offline and fail-closed at the gate constructor.

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
