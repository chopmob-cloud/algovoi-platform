"""The edge policy — the rules in force, content-addressed by ``policy_ref``.

A single frozen, JSON-serialisable document covering all four check families. ``snapshot()`` is the
deterministic preimage of ``policy_ref`` (tuples become sorted-by-JCS lists), so a decision can prove
exactly which rules admitted or blocked it, and a changed policy is detectable by a changed ref.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from algovoi_edge_sentinel.refs import policy_ref as _policy_ref


@dataclass(frozen=True)
class EdgePolicy:
    name: str = "edge-policy-v1"

    # --- IP / geo / ASN ---
    allow_countries: tuple[str, ...] = ()      # allowlist mode when non-empty
    deny_countries: tuple[str, ...] = ()
    deny_asns: tuple[int, ...] = ()
    deny_cidrs: tuple[str, ...] = ()
    allow_cidrs: tuple[str, ...] = ()          # trusted IPs that bypass the remaining geo rules

    # --- rate / velocity ---
    rate_max: int | None = None                # None disables rate limiting
    rate_window_s: int = 60
    rate_scope: str = "ip"                     # "ip" | "key"

    # --- identity allow / deny ---
    allow_dids: tuple[str, ...] = ()           # allowlist mode when non-empty
    deny_dids: tuple[str, ...] = ()
    deny_keys: tuple[str, ...] = ()
    deny_wallets: tuple[str, ...] = ()

    # --- replay / nonce / freshness ---
    freshness_window_s: int | None = None      # None disables the freshness check
    require_nonce: bool = False
    nonce_ttl_s: int = 300

    # --- orchestration ---
    checks: tuple[str, ...] = ("geo", "identity", "rate", "replay")
    log_allows: bool = False                   # chain ALLOWs too (default: chain only BLOCKs)

    def snapshot(self) -> dict:
        return {
            "name": self.name,
            "allow_countries": sorted(self.allow_countries),
            "deny_countries": sorted(self.deny_countries),
            "deny_asns": sorted(self.deny_asns),
            "deny_cidrs": sorted(self.deny_cidrs),
            "allow_cidrs": sorted(self.allow_cidrs),
            "rate_max": self.rate_max,
            "rate_window_s": self.rate_window_s,
            "rate_scope": self.rate_scope,
            "allow_dids": sorted(self.allow_dids),
            "deny_dids": sorted(self.deny_dids),
            "deny_keys": sorted(self.deny_keys),
            "deny_wallets": sorted(self.deny_wallets),
            "freshness_window_s": self.freshness_window_s,
            "require_nonce": self.require_nonce,
            "nonce_ttl_s": self.nonce_ttl_s,
            "checks": list(self.checks),
            "log_allows": self.log_allows,
        }

    def ref(self) -> str:
        return _policy_ref(self.snapshot())


DEFAULT_POLICY = EdgePolicy()

__all__ = ["EdgePolicy", "DEFAULT_POLICY"]
