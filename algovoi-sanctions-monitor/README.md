# algovoi-sanctions-monitor

**Continuous sanctions monitoring as signed, no-PII delta evidence.**

Point-in-time screening (Compliance Gate) confirms a counterparty is clean *now*. Designations change —
someone you transacted with last month can land on OFSI / OFAC / EU tomorrow. This engine keeps a
**watchlist**, re-screens it on every sweep, and emits a **Falcon-1024-signed delta receipt** the moment
a verdict changes — the timestamped, offline-verifiable proof an MLRO or regulator wants for ongoing
monitoring. Receipts carry **no PII**: only `subject_ref = sha256(network:address)`.

This is the engine core; the **continuous-monitor appliance** (persistent watchlist + scheduled sweeps +
loopback API) wraps it for turnkey deployment.

## What it does
- **Watchlist** — `watch(network, address)` adds a subject, content-addressed (`subject_ref`); no PII held
  in evidence.
- **`sweep()`** — re-screens every watched subject via your injected screener and returns a signed delta
  receipt for each **verdict change** (`newly_hit` / `cleared` / `escalated` / `de-escalated`). The first
  sweep sets the baseline silently; receipts only fire on change.
- **No-PII delta receipt** — `Falcon-1024`-signed, `canon_version: jcs-rfc8785-v1`, carrying
  `subject_ref`, prior/new verdict, transition, provider DID, run id, timestamps. Binds into the
  Substrate 2 evidence chain.
- **Offline verify** — `verify_monitor_receipt(envelope, pubkey)`; issuer public key alone.

## Why it matters
Ongoing-monitoring evidence is a hard regulatory requirement (UK MLR 2017, EU AMLD). A signed receipt
that proves *when* a counterparty's status changed and *that you caught it* is exactly the artifact a
supervisor looks for — and it completes the suite's compliance-receipt family:
[Compliance Gate](../algovoi-compliance-gate) (point-in-time) → [Travel Rule](../algovoi-travel-rule)
(FATF R.16) → **Continuous Monitoring** (ongoing).

## Embed
```python
from algovoi_sanctions_monitor import SanctionsMonitor, DenylistScreener, verify_monitor_receipt, signing

pk, sk = signing.generate_keypair()
screener = DenylistScreener()                      # or the AlgoVoi live OFSI/OFAC/EU screener — same
                                                   # interface as Compliance Gate, drop-in
mon = SanctionsMonitor(secret_key=sk, public_key=pk, screener=screener, monitor_did="did:web:acme")

ref = mon.watch(network="base", address="0x..")
await mon.sweep()                                  # baseline, no delta

screener.deny.add("0x..")                          # counterparty becomes sanctioned
deltas = await mon.sweep()                          # -> one signed "newly_hit" delta receipt
assert verify_monitor_receipt(deltas[0]["receipt_envelope"], pk).verified
```

## Guarantees
- **No PII in receipts** — only `sha256(network:address)`. Verified in the test suite.
- **Bring your own screener** — no AlgoVoi data dependency; the same `Screener` you run for point-in-time.
- **Offline-verifiable** — no service, no callback.
- **Free for every Substrate 2 customer** — any valid AlgoVoi suite licence unlocks it; fail-closed
  without one.

## Run as an appliance (Docker)
The continuous-monitor **appliance** wraps the engine with a persistent **PQC-encrypted** SQLite
watchlist, a daily sweep loop, and a loopback API. Generate the keys once, then deploy one container with
the DB on a **volume**:

```bash
# ML-KEM-1024 keypair for PQC-at-rest (required, fail-closed):
python -c "import base64; from algovoi_sanctions_monitor.encryption import generate_mlkem_keypair as g; pk,sk=g(); print('PK',base64.b64encode(pk).decode()); print('SK',base64.b64encode(sk).decode())"

docker run -d --name sanctions-monitor \
  -v monitor_data:/app/data \                      # persistent volume — the watchlist must survive restarts
  -e MONITOR_MLKEM_PK_B64=... -e MONITOR_MLKEM_SK_B64=... \
  -e SCREEN_URL=https://your-screen-endpoint/screen \   # your screener (or the AlgoVoi /compliance/screen)
  -e MONITOR_API_TOKEN=... \
  -p 127.0.0.1:8088:8088 algovoi-sanctions-monitor
```

API: `POST /v1/watch` · `DELETE /v1/watch/{ref}` · `GET /v1/watchlist` · `POST /v1/sweep` ·
`GET /v1/deltas` · `GET /v1/pubkey` · `GET /healthz`. The watchlist `(network, address)` is ML-KEM-1024 +
AES-256-GCM encrypted on disk; verdicts, timestamps, and signed receipts are non-PII and stored in clear.

## Licence
Commercial — `LicenseRef-AlgoVoi-Commercial-1.0`. **Included free for every AlgoVoi Substrate 2
customer.** Not open source; not published to public registries. Contact **chopmob@gmail.com**.
