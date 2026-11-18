"""The edge sentinel: runs the configured checks and records every decision as signed, verifiable evidence.

``EdgeSentinel.evaluate(ctx)`` resolves geo (via the injected provider), runs the enabled checks in policy
order, and the first BLOCK wins (fail-closed). The verdict is recorded as a Falcon-1024 (optionally hybrid
ML-DSA-65) signed, content-addressed, hash-linked ``edge_decision`` bound to the ``policy_ref`` in force
and a no-PII ``subject_ref``. BLOCKs are always chained (the examiner-grade events); ALLOWs are chained
only when ``policy.log_allows`` is set (runtime volume).

This is the RUNTIME layer: stateful (rate counters, nonce cache) and environment-aware (client IP, geo
data, clock). It is deliberately NOT a substrate / byte-parity property — the determinism guarantee lives
in Layer 1 (substrate-guard). What this layer adds over a commodity WAF is that every allow/deny is
offline-verifiable, PQC-signed evidence the Compliance Command Center ingests.
"""
from __future__ import annotations

from datetime import datetime, timezone

from algovoi_edge_sentinel import checks as _checks
from algovoi_edge_sentinel.ledger import EdgeLedger
from algovoi_edge_sentinel.licensing import require_license
from algovoi_edge_sentinel.models import EdgeResult, RequestContext
from algovoi_edge_sentinel.policy import DEFAULT_POLICY, EdgePolicy
from algovoi_edge_sentinel.refs import build_descriptor, edge_decision_ref, subject_ref
from algovoi_edge_sentinel.state import InMemoryNonceCache, InMemoryRateLimiter


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EdgeSentinel:
    """Runtime edge gate over one signing key and one policy. Fail-closed on licence."""

    def __init__(self, *, decision_secret_key: bytes, decision_public_key: bytes,
                 policy: EdgePolicy = DEFAULT_POLICY, geo_provider=None,
                 mldsa_secret_key: bytes | None = None, mldsa_public_key: bytes | None = None,
                 store=None, rate_limiter=None, nonce_cache=None,
                 clock=_utcnow, _skip_license: bool = False) -> None:
        if not _skip_license:
            require_license()
        self.policy = policy
        self.policy_ref = policy.ref()
        self.geo = geo_provider
        self.clock = clock
        self.rate_limiter = rate_limiter or InMemoryRateLimiter()
        self.nonce_cache = nonce_cache or InMemoryNonceCache()
        self.ledger = EdgeLedger(decision_secret_key, decision_public_key,
                                 mldsa_secret_key, mldsa_public_key, store)

    @property
    def hybrid(self) -> bool:
        return self.ledger.mldsa_pk is not None

    def _resolve_geo(self, ctx: RequestContext) -> dict:
        # SECURITY (2026-08-19): when a geo provider is configured it is AUTHORITATIVE — client-asserted
        # country/asn must NOT override server-side resolution. Previously any caller-supplied country OR
        # asn short-circuited the provider, so an attacker asserted an allowlisted country to bypass the
        # geo gate AND, by supplying only a country, nulled the asn and silently disabled the ASN deny-list.
        # Only trust caller-supplied geo when NO provider is wired (the integrator-supplies-resolved-geo
        # case, e.g. the /evaluate API). With a provider but no IP there is no trustworthy signal.
        if self.geo is not None:
            return self.geo.resolve(ctx.ip) if ctx.ip else {"country": None, "asn": None}
        return {"country": ctx.country, "asn": ctx.asn}

    def evaluate(self, ctx: RequestContext) -> EdgeResult:
        now_dt = self.clock()
        now = now_dt.timestamp()
        evaluated_at = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        geo = self._resolve_geo(ctx)

        decision, check_name, reason = _checks.ALLOW, "none", "ALLOW"
        for name in self.policy.checks:
            if name == "geo":
                d, c = _checks.check_geo(ctx, self.policy, geo)
            elif name == "identity":
                d, c = _checks.check_identity(ctx, self.policy)
            elif name == "rate":
                d, c = _checks.check_rate(ctx, self.policy, self.rate_limiter, now)
            elif name == "replay":
                d, c = _checks.check_replay(ctx, self.policy, self.nonce_cache, now)
            else:
                continue
            if d == _checks.BLOCK:
                decision, check_name, reason = _checks.BLOCK, name, c
                break

        desc = build_descriptor(ip=ctx.ip, country=geo.get("country"), asn=geo.get("asn"),
                                agent_did=ctx.agent_did, key_id=ctx.key_id, wallet=ctx.wallet)
        sref = subject_ref(desc)
        edref = edge_decision_ref(policy_ref_=self.policy_ref, decision=decision, check=check_name,
                                  reason_code=reason, subject_ref_=sref)
        envelope = None
        if decision == _checks.BLOCK or self.policy.log_allows:
            core = {
                "decision": decision,
                "check": check_name,
                "reason_code": reason,
                "policy_ref": self.policy_ref,
                "subject_ref": sref,
                "edge_decision_ref": edref,
                "evaluated_at": evaluated_at,
            }
            envelope, _payload = self.ledger.append(core)

        return EdgeResult(allowed=(decision == _checks.ALLOW), decision=decision, check=check_name,
                          reason_code=reason, policy_ref=self.policy_ref, subject_ref=sref,
                          edge_decision_ref=edref, evaluated_at=evaluated_at,
                          envelope=envelope, hybrid=self.hybrid)

    def export_pack(self, out_dir: str) -> str:
        return self.ledger.export_pack(out_dir)


__all__ = ["EdgeSentinel"]
