# AlgoVoi Mandate Auditor Suite

Self-verifiable retention-chain audit reports for `algovoi-payment-mandate` charge histories.

Every authorized charge is stamped with a `chain_seq` and `chain_ref` at authorization time.
An `AuditReport` is a snapshot of the full charge history for one mandate, ordered by `chain_seq`,
with each record carrying its `receipt_hash` and `chain_ref`. Any party holding the report can
verify its integrity offline by recomputing every `chain_ref` from local data alone -- no AlgoVoi
infrastructure, registry lookup, or network access required.

Regulatory coverage: MiCA Art. 68(9), DORA Art. 17, AMLR Art. 77.

## How it works

Each authorized charge carries:

```
receipt_hash   = sha256(JCS({amount, asset, charge_id, mandate_id, period_key, ts}))
chain_ref      = sha256(JCS({chain_seq, issuer_id, prev_receipt_hash, receipt_hash}))
issuer_id      = "mandate:<mandate_id>"
```

The chain is per-mandate, starting at `chain_seq=0`. Only authorized charges are chained;
declined charges are recorded for idempotency but excluded from the chain. This matches the
`algovoi-retention-chain` primitive exactly -- the auditor's `verify_audit_report` delegates
directly to `verify_chain_sequence` from that package.

## Library

```python
from algovoi_mandate_auditor import build_audit_report, verify_audit_report
from datetime import datetime, timezone

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
report = await build_audit_report(store, kid=issuer.kid, mandate_id=mid, generated_at=generated_at)

ok, reason = verify_audit_report(report)  # True, None on success
```

## HTTP Service

```bash
MANDATE_STORE_PATH=mandates.db algovoi-mandate-auditor
# GET http://localhost:8097/v1/audit/{kid}/{mandate_id}          -- live report
# GET http://localhost:8097/v1/audit/{kid}/{mandate_id}/export   -- downloadable audit pack
```

Mount as a router onto an existing app:

```python
from algovoi_mandate_auditor.service import create_auditor_app
auditor_app = create_auditor_app(issuer.store, kid=issuer.kid)
```

## Acceptance

```bash
python scripts/acceptance.py   # exit 0 + "ALL GREEN"
```

## Licence

AlgoVoi Commercial Software License. Contact chopmob@gmail.com.
