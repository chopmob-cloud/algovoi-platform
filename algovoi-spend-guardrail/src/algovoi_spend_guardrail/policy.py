"""Platform spend policy — applied on top of the Passport + Mandate checks."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Policy:
    """Optional platform-level controls evaluated alongside the credential + mandate.

    Anything left ``None`` is unconstrained. Amounts are integers in the asset's minor units.

    Three tiers of control:
      * **hard deny** — ``denied_agents`` / ``allowed_payees`` / ``allowed_assets`` / ``required_scope``
        / ``max_amount_per_tx`` (:meth:`evaluate`);
      * **review (REFER)** — ``refer_above_amount`` / ``refer_payees`` (:meth:`review`): not auto-approved,
        not hard-denied — escalated for a human/step-up decision, and the mandate ledger is **not** consumed;
      * **velocity** — ``velocity_window_secs`` + ``velocity_max_amount``: a rolling-window cap the gate
        enforces over its own recent ALLOWs (catches bursts that calendar period caps miss).
    """

    allowed_payees: set[str] | None = None       # None = any payee
    allowed_assets: set[str] | None = None       # None = any asset
    required_scope: str | None = None            # scope the passport must carry
    max_amount_per_tx: int | None = None         # hard per-charge ceiling
    denied_agents: set[str] = field(default_factory=set)
    # review tier -> REFER
    refer_above_amount: int | None = None        # at/above this, send to review (still under the hard cap)
    refer_payees: set[str] = field(default_factory=set)   # payees that always need review
    # velocity tier -> rolling-window cap (enforced by the guardrail over its decision history)
    velocity_window_secs: int | None = None
    velocity_max_amount: int | None = None

    def snapshot(self) -> dict:
        """A deterministic, JSON-safe document of the policy in force.

        Sets become sorted lists so the snapshot canonicalises identically every time; this is the
        ``policy_document`` whose hash is the ``policy_ref`` bound into each decision. Rotating any
        control changes the snapshot, so a decision made under one policy does not recompute under
        another (rotation-detectable, the same property algovoi-policy-binding gives).
        """
        def _s(v: set[str] | None):
            return sorted(v) if v is not None else None
        return {
            "allowed_payees": _s(self.allowed_payees),
            "allowed_assets": _s(self.allowed_assets),
            "required_scope": self.required_scope,
            "max_amount_per_tx": self.max_amount_per_tx,
            "denied_agents": sorted(self.denied_agents),
            "refer_above_amount": self.refer_above_amount,
            "refer_payees": sorted(self.refer_payees),
            "velocity_window_secs": self.velocity_window_secs,
            "velocity_max_amount": self.velocity_max_amount,
        }

    def evaluate(self, *, agent_did: str | None, scopes: list[str] | None,
                 asset: str | None, payee: str, amount: int) -> list[str]:
        """Return a list of hard-deny reasons (empty == no hard denial)."""
        reasons: list[str] = []
        if self.denied_agents and agent_did in self.denied_agents:
            reasons.append("policy:agent_denied")
        if self.allowed_payees is not None and payee not in self.allowed_payees:
            reasons.append("policy:payee_not_allowed")
        # SECURITY (2026-08-19): an asset allow-list must FAIL CLOSED on an unspecified asset. The
        # previous `asset is not None` guard let a caller omit `asset` to skip the allow-list entirely
        # and then charge in the mandate's own (possibly disallowed) asset. If a list is configured, an
        # undeclared asset cannot be confirmed in-list, so it is denied.
        if self.allowed_assets is not None and asset not in self.allowed_assets:
            reasons.append("policy:asset_not_allowed")
        if self.required_scope and self.required_scope not in (scopes or []):
            reasons.append("policy:scope_missing")
        if self.max_amount_per_tx is not None and amount > self.max_amount_per_tx:
            reasons.append("policy:per_tx_cap_exceeded")
        return reasons

    def review(self, *, payee: str, amount: int) -> list[str]:
        """Return a list of review reasons (empty == no review needed). Drives a REFER verdict."""
        reasons: list[str] = []
        if self.refer_above_amount is not None and amount >= self.refer_above_amount:
            reasons.append("policy:amount_needs_review")
        if payee in self.refer_payees:
            reasons.append("policy:payee_needs_review")
        return reasons
