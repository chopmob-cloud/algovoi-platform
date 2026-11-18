"""
algovoi-edge-sentinel — verifiable runtime edge defence for agentic payment infrastructure.

Layer 2 of the AlgoVoi security suite (Layer 1 is the deterministic ``algovoi-substrate-guard`` /
``-pro`` input gate). The edge sentinel runs four runtime checks — IP/geo/ASN blocking, rate/velocity
limiting, identity allow/deny, and replay/nonce/freshness — and records EVERY allow/deny as a Falcon-1024
(optionally hybrid ML-DSA-65) signed, content-addressed, hash-linked ``edge_decision`` the Compliance
Command Center ingests. The mechanics are commodity; the differentiator is that every decision is
offline-verifiable, PQC-signed evidence bound to the ``policy_ref`` in force, with no-PII subjects.

This is the RUNTIME layer: stateful and environment-aware, deliberately NOT a substrate / byte-parity
property. The determinism guarantee lives in Layer 1.

Embed::

    from algovoi_edge_sentinel import EdgeSentinel, EdgePolicy, RequestContext, signing
    from algovoi_edge_sentinel.geo import InMemoryGeoProvider

    pk, sk = signing.generate_keypair()
    policy = EdgePolicy(deny_countries=("KP",), rate_max=100, rate_window_s=60)
    geo = InMemoryGeoProvider([{"cidr": "203.0.113.0/24", "country": "KP", "asn": 64500}])
    sentinel = EdgeSentinel(decision_secret_key=sk, decision_public_key=pk, policy=policy, geo_provider=geo)

    r = sentinel.evaluate(RequestContext(ip="203.0.113.5"))
    assert not r.allowed and r.reason_code == "BLOCK_GEO_COUNTRY"

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_agent_passport import signing

from algovoi_edge_sentinel import hybrid
from algovoi_edge_sentinel.geo import GeoProvider, InMemoryGeoProvider
from algovoi_edge_sentinel.ledger import EdgeLedger
from algovoi_edge_sentinel.models import (
    ChainVerifyResult,
    EdgeResult,
    RequestContext,
    VerifyDecisionResult,
)
from algovoi_edge_sentinel.policy import DEFAULT_POLICY, EdgePolicy
from algovoi_edge_sentinel.refs import edge_decision_ref, policy_ref, subject_ref
from algovoi_edge_sentinel.sentinel import EdgeSentinel
from algovoi_edge_sentinel.state import InMemoryNonceCache, InMemoryRateLimiter
from algovoi_edge_sentinel.store import EdgeStore
from algovoi_edge_sentinel.verifier import verify_edge_chain, verify_edge_decision

__version__ = "0.1.1"

__all__ = [
    "EdgeSentinel",
    "EdgePolicy",
    "DEFAULT_POLICY",
    "RequestContext",
    "EdgeResult",
    "VerifyDecisionResult",
    "ChainVerifyResult",
    "GeoProvider",
    "InMemoryGeoProvider",
    "EdgeLedger",
    "EdgeStore",
    "InMemoryRateLimiter",
    "InMemoryNonceCache",
    "verify_edge_decision",
    "verify_edge_chain",
    "policy_ref",
    "subject_ref",
    "edge_decision_ref",
    "hybrid",
    "signing",
    "__version__",
]
