"""The four runtime checks. Each is a pure function returning ``(decision, reason_code)`` where decision
is ``"ALLOW"`` or ``"BLOCK"``. A check with no signal to act on (e.g. no IP for the geo check) returns
ALLOW — it cannot block on input it was not given. The sentinel runs the enabled checks in policy order
and the first BLOCK wins (fail-closed)."""
from __future__ import annotations

from datetime import datetime, timezone

from algovoi_edge_sentinel.geo import ip_in_any
from algovoi_edge_sentinel.models import RequestContext
from algovoi_edge_sentinel.policy import EdgePolicy

ALLOW = "ALLOW"
BLOCK = "BLOCK"
_OK = (ALLOW, "ALLOW")


def check_geo(ctx: RequestContext, policy: EdgePolicy, geo: dict) -> tuple[str, str]:
    ip, country, asn = ctx.ip, geo.get("country"), geo.get("asn")
    if ip and policy.deny_cidrs and ip_in_any(ip, policy.deny_cidrs):
        return BLOCK, "BLOCK_IP_CIDR"
    if ip and policy.allow_cidrs and ip_in_any(ip, policy.allow_cidrs):
        return _OK  # trusted IP bypasses the remaining geo rules
    if asn is not None and asn in policy.deny_asns:
        return BLOCK, "BLOCK_GEO_ASN"
    if country and country in policy.deny_countries:
        return BLOCK, "BLOCK_GEO_COUNTRY"
    if policy.allow_countries and country not in policy.allow_countries:
        return BLOCK, "BLOCK_GEO_NOT_ALLOWLISTED"
    return _OK


def check_identity(ctx: RequestContext, policy: EdgePolicy) -> tuple[str, str]:
    if ctx.agent_did and ctx.agent_did in policy.deny_dids:
        return BLOCK, "BLOCK_DID_DENIED"
    if ctx.key_id and ctx.key_id in policy.deny_keys:
        return BLOCK, "BLOCK_KEY_DENIED"
    if ctx.wallet and ctx.wallet in policy.deny_wallets:
        return BLOCK, "BLOCK_WALLET_DENIED"
    if policy.allow_dids and ctx.agent_did not in policy.allow_dids:
        return BLOCK, "BLOCK_DID_NOT_ALLOWLISTED"
    return _OK


def check_rate(ctx: RequestContext, policy: EdgePolicy, rate_limiter, now: float) -> tuple[str, str]:
    if policy.rate_max is None:
        return _OK
    value = ctx.ip if policy.rate_scope == "ip" else (ctx.key_id or ctx.agent_did)
    if not value:
        return _OK  # no scope value -> nothing to limit
    count = rate_limiter.hit(f"{policy.rate_scope}:{value}", now, policy.rate_window_s)
    if count > policy.rate_max:
        return BLOCK, "BLOCK_RATE_EXCEEDED"
    return _OK


def _parse_epoch(iso: str) -> float | None:
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except Exception:  # noqa: BLE001
        return None


def check_replay(ctx: RequestContext, policy: EdgePolicy, nonce_cache, now: float) -> tuple[str, str]:
    if policy.freshness_window_s is not None:
        # SECURITY (2026-08-19): freshness must be MANDATORY when a window is configured. Previously a
        # missing timestamp skipped the check, so a client simply omitted the header to replay an old
        # request. A missing/unparseable/out-of-window timestamp now fails closed.
        if ctx.timestamp is None:
            return BLOCK, "BLOCK_MISSING_TIMESTAMP"
        ts = _parse_epoch(ctx.timestamp)
        if ts is None or abs(now - ts) > policy.freshness_window_s:
            return BLOCK, "BLOCK_STALE"  # unparseable or outside window -> fail closed
    if policy.require_nonce and not ctx.nonce:
        return BLOCK, "BLOCK_MISSING_NONCE"
    if ctx.nonce and nonce_cache.seen_before(ctx.nonce, now, policy.nonce_ttl_s):
        return BLOCK, "BLOCK_REPLAY"
    return _OK


__all__ = ["check_geo", "check_identity", "check_rate", "check_replay", "ALLOW", "BLOCK"]
