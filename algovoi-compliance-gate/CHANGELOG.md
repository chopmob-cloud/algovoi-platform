# Changelog

## 0.2.0
- Post-quantum, no-PII compliance decision engine (v2). Screen a payer across a composite of typed
  checks (sanctions, PEP, jurisdiction, risk, travel-rule, each via your own provider), fold them by a
  content-addressed policy, and emit a categorical ALLOW / REFER / DENY verdict that is, in one
  artifact: no-PII (`payer_ref = sha256(network:address)`); policy-bound (`policy_ref` +
  `policy_bound_ref`, so a later silent policy rotation is detectable); optionally action-bound (to the
  `action_ref` of the gated payment, so a verdict cannot be replayed); chained into an append-only,
  tamper-evident decision ledger; explained via closed-enum `reason_codes` and structured
  `obligations`; Falcon-1024 signed with an optional ML-DSA-65 co-signature, offline-verifiable; and
  emitted as a Compliance Command Center-ingestable evidence pack.
- Runtime licence enforced, fail-closed. Test suite bypasses the gate only inside the test tree via
  `conftest.py`, never in the shipped wheel.
