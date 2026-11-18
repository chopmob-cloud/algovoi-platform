# Security Audit — `algovoi-spend-guardrail` v0.2.0

**Audited:** `src/algovoi_spend_guardrail/`, `examples/run_service.py`, `tests/`  
**Threat model:** Attacker controls all HTTP inputs (`passport_credential`, `mandate`, `charge_id`,
`amount`, `payee`, `asset`). The guardrail's own keys, `PassportIssuer`, and `MandateIssuer` are
trusted. Goals: forge an ALLOW, exhaust a mandate cap, bypass a policy control, or corrupt the
audit trail.

---

## HIGH

### H1 — `GUARDRAIL_API_TOKEN` unset → `/authorize` silently unauthenticated

**Files:** `examples/run_service.py:50`, `src/algovoi_spend_guardrail/app.py:38`

```python
# run_service.py
auth_dependency=bearer_token_auth(os.environ.get("GUARDRAIL_API_TOKEN"))

# app.py — when auth_dependency is None it is replaced with a no-op
if auth_dependency is None:
    async def auth_dependency():
        return None
```

`os.environ.get("GUARDRAIL_API_TOKEN")` returns `None` when the variable is not set.
`bearer_token_auth(None)` returns `None`, which `create_app` replaces with a no-op dependency.
The result is that `/v1/guardrail/authorize` — the endpoint that consumes the mandate ledger
and produces binding ALLOW decisions — is completely unprotected.

**Recommended change — `run_service.py`:**

```python
api_token = os.environ.get("GUARDRAIL_API_TOKEN")
if not api_token:
    raise RuntimeError(
        "GUARDRAIL_API_TOKEN is not set. "
        "Set it to a strong random token to protect /v1/guardrail/authorize."
    )
app = create_app(guardrail, decision_public_key=gpk,
                 auth_dependency=bearer_token_auth(api_token))
```

**Recommended change — `app.py` (defence-in-depth):**

```python
# Replace the silent no-op with a hard 401 when no dependency is supplied
if auth_dependency is None:
    from fastapi import HTTPException
    async def auth_dependency():
        raise HTTPException(status_code=401, detail="no auth configured")
```

If a truly open (no-auth) guardrail is intentional, the caller must pass
`auth_dependency=lambda: None` explicitly — the default must not silently remove protection.

---

### H2 — `decision_ttl_secs=0` accepted silently → decisions born-expired

**File:** `src/algovoi_spend_guardrail/guardrail.py:72`

```python
self.decision_ttl_secs = int(decision_ttl_secs)
```

Zero (or negative) values are accepted without error. The expiry timestamp is set to
`now + timedelta(seconds=0)` and the freshness check uses `>=`, so a zero-TTL decision is
already expired at the moment of signing. A verifier that enforces freshness rejects every
decision the guardrail emits, causing a complete availability failure that may be silent.

**Recommended change:**

```python
self.decision_ttl_secs = int(decision_ttl_secs)
if self.decision_ttl_secs < 1:
    raise ValueError(
        f"decision_ttl_secs must be ≥ 1 (got {self.decision_ttl_secs}). "
        "Use decision_ttl_secs=300 (5 minutes) or longer for production."
    )
```

---

## MEDIUM

### M1 — Hybrid receipt passes Falcon-only verification without ML-DSA check

**File:** `src/algovoi_spend_guardrail/verifier.py:51`

```python
if "sig2" in env:
    if mldsa_public_key is None:
        return True, False   # hybrid receipt, ML-DSA not checked
```

A receipt signed with both Falcon-1024 and ML-DSA-65 returns `verified=True, hybrid=False`
when no `mldsa_public_key` is supplied. Downstream code that checks only `verified` accepts
the receipt without validating the ML-DSA co-signature. An attacker who can replace `sig2`
with a signature under a different ML-DSA key would produce a receipt that any Falcon-only
verifier accepts undetected.

**Recommended change** — add a `require_hybrid` guard:

```python
def verify_decision(
    decision_receipt: str,
    public_key: bytes,
    *,
    mldsa_public_key: bytes | None = None,
    require_hybrid: bool = False,          # <-- new
) -> VerifyDecisionResult:
    ...
    ok, hyb = _verify_sigs(payload, env, public_key, mldsa_public_key)
    if not ok:
        return VerifyDecisionResult(verified=False, kid=kid, error="signature verification failed")
    if require_hybrid and not hyb:
        return VerifyDecisionResult(
            verified=False, kid=kid,
            error="hybrid receipt requires mldsa_public_key but none was supplied"
        )
    ...
```

Also add a docstring note that `hybrid=False` on a hybrid receipt means the second signature
was **not** checked — this is a weakened security level, not full verification.

---

### M2 — `_allow_history` grows without bound → memory DoS (in-memory mode)

**File:** `src/algovoi_spend_guardrail/guardrail.py:85`, `guardrail.py:157`

```python
self._allow_history: list[tuple[str | None, int, datetime]] = []
...
self._allow_history.append((agent_did, int(amount or 0), now))
```

In in-memory mode (no `DecisionStore`), every ALLOW appends a tuple. The velocity check
filters by `ts >= cutoff` but never prunes the list. A long-running process accumulates
O(n) tuples indefinitely.

**Recommended change** — prune after append:

```python
if decision == "ALLOW" and self.ledger.store is None:
    now_ts = datetime.now(timezone.utc)
    self._allow_history.append((agent_did, int(amount or 0), now_ts))
    # Prune entries outside the velocity window so the list stays bounded.
    if win := self.policy.velocity_window_secs:
        cutoff = now_ts - timedelta(seconds=win)
        self._allow_history = [
            (a, amt, ts) for (a, amt, ts) in self._allow_history if ts >= cutoff
        ]
```

When no velocity window is configured there is no cap; consider also bounding to a
reasonable maximum (e.g. 10 000 entries) regardless.

---

### M3 — `/v1/guardrail/decisions/export` is unauthenticated

**File:** `src/algovoi_spend_guardrail/app.py:67`

```python
@app.get("/v1/guardrail/decisions/export")
async def export_chain() -> dict:
    return {"type": "spend_decision", "kid": guardrail.kid, "count": guardrail.ledger.seq,
            "envelopes": list(guardrail.ledger.envelopes)}
```

Every signed decision envelope — including `agent_did`, `charge_id`, `amount`, and `payee`
in plaintext — is publicly readable. The `/authorize` endpoint is gated by
`auth_dependency`; this one is not.

**Recommended change** — apply the same dependency:

```python
@app.get(
    "/v1/guardrail/decisions/export",
    dependencies=[Depends(auth_dependency)],   # <-- add
)
async def export_chain() -> dict:
    ...
```

---

### M4 — `bearer_token_auth` timing side-channel (upstream dependency)

**File:** `src/algovoi_spend_guardrail/__init__.py:34` (imported from `algovoi_agent_passport`)

HTTP bearer token comparisons must use `hmac.compare_digest` (constant-time), not `==`.
A timing oracle built from enough requests can reconstruct the token character by character.

**Action:** Verify that `algovoi_agent_passport.bearer_token_auth` uses constant-time
comparison. If not, patch upstream or wrap locally:

```python
import hmac

def _safe_bearer_auth(expected_token: str):
    from fastapi import HTTPException
    from fastapi.security import HTTPBearer

    bearer = HTTPBearer()

    async def _dep(credentials=Depends(bearer)):
        if not hmac.compare_digest(credentials.credentials, expected_token):
            raise HTTPException(status_code=401, detail="invalid token")
    return _dep
```

---

## LOW

### L1 — Async race on in-memory velocity check

**File:** `src/algovoi_spend_guardrail/guardrail.py:219`

```python
if self._velocity_exceeded(agent_did, amount, datetime.now(timezone.utc)):
    return self._decide("DENY", ["policy:velocity_exceeded"], ...)
```

In an asyncio FastAPI process, two concurrent `authorize` coroutines can both pass the
velocity check before either appends to `_allow_history`. The `await` at step 3
(`mandate_issuer.authorize_charge`) is the yield point between the check and the append.
With a cap of `N`, a burst of two concurrent requests at exactly `N-1` total spent can
each pass the check and both be approved, resulting in `N+1` total spend.

**Recommended change** — record a tentative reservation before the `await`:

```python
# Step 2b — reserve before yielding
if self._velocity_exceeded(agent_did, amount, datetime.now(timezone.utc)):
    return self._decide("DENY", ["policy:velocity_exceeded"], ...)

# Tentatively record the pending amount for concurrent-call protection
if self.ledger.store is None and self.policy.velocity_window_secs:
    _sentinel = (agent_did, amount, datetime.now(timezone.utc))
    self._allow_history.append(_sentinel)

try:
    ch = await self.mandate_issuer.authorize_charge(...)
finally:
    if self.ledger.store is None and self.policy.velocity_window_secs:
        # Remove the reservation; the real entry is added on ALLOW in _decide
        self._allow_history.remove(_sentinel)
```

Alternatively, document this as an accepted race (it requires precisely timed concurrent
requests and is bounded by the mandate's own per-period cap, which serializes at the DB).

---

### L2 — `verify_decision_chain` checks type before signature

**File:** `src/algovoi_spend_guardrail/verifier.py:101`

```python
if payload.get("type") != ENTRY_TYPE or payload.get("canon_version") != CANON_VERSION:
    return ChainVerifyResult(verified=False, ..., error="wrong entry type")
# signature check is here — after the structural check
ok, hyb = _verify_sigs(payload, env, public_key, mldsa_public_key)
```

The error message `"wrong entry type"` vs `"bad signature"` allows an external caller to
distinguish structural rejection from cryptographic rejection, which slightly aids probing
of the chain format.

**Recommended change** — verify the signature before checking structural fields:

```python
ok, hyb = _verify_sigs(payload, env, public_key, mldsa_public_key)
if not ok:
    return ChainVerifyResult(verified=False, count=i, first_bad_seq=i, error="bad signature")
if payload.get("type") != ENTRY_TYPE or payload.get("canon_version") != CANON_VERSION:
    return ChainVerifyResult(verified=False, count=i, first_bad_seq=i, error="wrong entry type")
```

---

### L3 — Swallowed mandate-parse exception leaves silent `mandate_ref=None` on DENY receipt

**File:** `src/algovoi_spend_guardrail/guardrail.py:119`

```python
except Exception:  # noqa: BLE001
    mandate_ref_ = None
```

A malformed mandate credential silently produces `mandate_ref=None`. Audit consumers
relying on the presence of `mandate_ref` as a signal that a mandate was inspected will
misread the record as "no mandate presented" rather than "mandate was malformed."

**Recommended change** — surface the failure in the DENY reasons:

```python
except Exception:  # noqa: BLE001
    mandate_ref_ = None
    _mandate_parse_failed = True   # flag to inject into reasons below
```

Then in the DENY path that follows a passport failure (where `mandate_ref_` being `None`
due to a parse error is most relevant), add `"mandate:parse_failed"` to the reasons list
when the flag is set.

---

### L4 — Ephemeral passport key generated silently when `GUARDRAIL_PASSPORT_PK_B64` is unset

**File:** `examples/run_service.py:36`

```python
passport_pk = base64.b64decode(ppk_b64) if ppk_b64 else _kp("_", "_", "passport")[0]
```

A randomly-generated ephemeral key is used as the trusted passport verifier. Every real
passport will fail with `passport:INVALID_SIGNATURE`, causing a silent 100% DENY rate.
The "dev only" warning is printed for mandate and decision keys but not here.

**Recommended change:**

```python
ppk_b64 = os.environ.get("GUARDRAIL_PASSPORT_PK_B64")
if not ppk_b64:
    print(
        "WARNING: GUARDRAIL_PASSPORT_PK_B64 not set — generating an ephemeral passport "
        "verification key (dev only). All real Agent Passport credentials will be DENIED."
    )
    passport_pk = signing.generate_keypair()[0]
else:
    passport_pk = base64.b64decode(ppk_b64)
```

---

## INFORMATIONAL

### I1 — No rate limiting at the HTTP layer

The bounds gate (`bounds.check`) correctly rejects oversized input before any cryptographic
work. There is no per-IP or per-client rate limit at the service level. This is the
operator's responsibility via a reverse proxy (nginx, Cloudflare, etc.), but it should be
called out in the deployment guide so it is not overlooked.

### I2 — `decision_ttl_secs` default of 300 s may be too short for async payment flows

A 5-minute freshness window is tight for a payment pipeline that includes human approval
steps (e.g. after a REFER decision is escalated and re-submitted as an ALLOW). Consider
exposing a separate `refer_ttl_secs` for REFER decisions, or documenting that REFER
receipts should not be re-submitted as authorization tokens.

### I3 — License bypass in tests is correct and does not ship in the wheel

`tests/conftest.py` uses `monkeypatch` to neutralise `require_license` for all three
packages. Confirmed: `hatch.build.targets.wheel.packages = ["src/algovoi_spend_guardrail"]`
excludes the test tree. No action required.

---

## Prioritised fix order

| Priority | ID | One-line fix |
|---|---|---|
| 1 | H1 | Raise `RuntimeError` in `run_service.py` when `GUARDRAIL_API_TOKEN` is unset; make `create_app` default to 401, not no-op |
| 2 | H2 | Add `if self.decision_ttl_secs < 1: raise ValueError(...)` in `SpendGuardrail.__init__` |
| 3 | M3 | Add `dependencies=[Depends(auth_dependency)]` to the `/decisions/export` route |
| 4 | M2 | Prune `_allow_history` after every append using the velocity window cutoff |
| 5 | M1 | Add `require_hybrid` parameter to `verify_decision`; document the weakened-verification case |
| 6 | M4 | Verify `bearer_token_auth` in `algovoi_agent_passport` uses `hmac.compare_digest` |
| 7 | L1 | Document or mitigate the async velocity race; note it is bounded by the mandate per-period cap |
| 8 | L2 | Move signature check before type check in `verify_decision_chain` |
| 9 | L3 | Surface `"mandate:parse_failed"` in DENY reasons when the envelope parse throws |
| 10 | L4 | Add explicit warning when `GUARDRAIL_PASSPORT_PK_B64` is unset in `run_service.py` |
