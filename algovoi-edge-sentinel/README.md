# AlgoVoi Edge Sentinel

Verifiable **runtime** edge defence for agentic payment infrastructure — Layer 2 of the AlgoVoi security
suite. (Layer 1 is the deterministic [`algovoi-substrate-guard`](https://pypi.org/project/algovoi-substrate-guard/)
input-bounds gate.)

Four runtime checks, first-block-wins, fail-closed:

| Check | Blocks on | Named codes |
|---|---|---|
| **IP / geo / ASN** | country, ASN, IP-range (allowlist or denylist) | `BLOCK_GEO_COUNTRY`, `BLOCK_GEO_ASN`, `BLOCK_IP_CIDR`, `BLOCK_GEO_NOT_ALLOWLISTED` |
| **Rate / velocity** | sliding-window request count per IP or key | `BLOCK_RATE_EXCEEDED` |
| **Identity allow/deny** | agent DID, key id, wallet | `BLOCK_DID_DENIED`, `BLOCK_KEY_DENIED`, `BLOCK_WALLET_DENIED`, `BLOCK_DID_NOT_ALLOWLISTED` |
| **Replay / nonce / freshness** | replayed nonce, stale or unparseable timestamp, missing nonce | `BLOCK_REPLAY`, `BLOCK_STALE`, `BLOCK_MISSING_NONCE` |

The mechanics are commodity (every WAF does geo/rate). The difference: **every allow/deny is a
Falcon-1024 (optionally hybrid ML-DSA-65) signed, content-addressed, hash-linked `edge_decision`** bound
to the `policy_ref` in force and a **no-PII** `subject_ref` (client IP, DID, key and wallet are
hash-folded; country/ASN stay clear for audit). The chain exports as the same evidence pack the
**Compliance Command Center** ingests — so a geo-block isn't a dropped packet, it's offline-verifiable
proof that *policy P blocked subject S for reason R at time T*.

> **Honest scope.** This is the RUNTIME layer: stateful (rate counters, nonce cache) and environment-aware
> (client IP, geo data, clock). It is deliberately **not** a substrate / byte-parity property — the
> deterministic, cross-language, offline-reproducible guarantee lives in Layer 1. Keeping that line sharp
> is what keeps the substrate claims credible.

```python
from algovoi_edge_sentinel import EdgeSentinel, EdgePolicy, RequestContext, signing, verify_edge_chain
from algovoi_edge_sentinel.geo import InMemoryGeoProvider

pk, sk = signing.generate_keypair()
policy = EdgePolicy(deny_countries=("KP",), rate_max=100, rate_window_s=60, require_nonce=True)
geo = InMemoryGeoProvider([{"cidr": "203.0.113.0/24", "country": "KP", "asn": 64500}])
s = EdgeSentinel(decision_secret_key=sk, decision_public_key=pk, policy=policy, geo_provider=geo)

r = s.evaluate(RequestContext(ip="203.0.113.5", nonce="n1"))
assert not r.allowed and r.reason_code == "BLOCK_GEO_COUNTRY"
assert verify_edge_chain(s.ledger.envelopes, pk).verified     # the block is verifiable evidence
```

Run ahead of an app as ASGI middleware (`pip install 'algovoi-edge-sentinel[serve]'`):

```python
from algovoi_edge_sentinel.app import EdgeMiddleware
app.add_middleware(EdgeMiddleware, sentinel=s)   # BLOCK -> 403 + named reason; decision already chained
```

Geo resolution is pluggable (`GeoProvider`); plug in a MaxMind/IP2Location-backed provider in production,
`InMemoryGeoProvider` for tests. The signing key is injected, the chain store is pluggable
(`EdgeStore`, SQLite/Postgres via `EDGE_SENTINEL_DB`), rate/nonce state is in-memory by default
(inject a shared backend for multi-process), and licence enforcement is offline + fail-closed.

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
