"""The gate's content-addressed policy — the ruleset the verdict is decided under.

The policy is a plain JSON object. Its content hash (``substrate2.policy_ref``) is bound
into every verdict (``policy_bound_ref``), so a record sealed under policy P fails to
recompute under any silently-rotated P' — version-provable + rotation-detectable.

``combine`` is the deterministic, policy-driven fold from the multi-signal check manifest
to the final categorical verdict + closed reason codes + structured obligations.
"""
from __future__ import annotations

from algovoi_compliance_gate.checks import CheckResult

_RANK = {"ALLOW": 0, "REFER": 1, "DENY": 2}
_UNRANK = {v: k for k, v in _RANK.items()}


def default_policy() -> dict:
    """A conservative starter policy. Replace with your own ruleset; its content hash binds
    into every verdict, so changing it is detectable in the records sealed under it."""
    return {
        "policy_id": "algovoi.compliance_gate",
        "version": 1,
        "deny_risk": 900,                       # composite/risk >= -> DENY
        "refer_risk": 600,                      # composite/risk >= -> at least REFER
        "deny_jurisdictions": [],               # ISO country codes to block
        "travel_rule_threshold_microusd": 1_000_000_000,  # ~$1,000.00 (FATF de-minimis)
        "refer_on_pep": True,
    }


def combine(check_results: list[CheckResult], policy: dict) -> tuple[str, list[str], list[str], int | None]:
    """Fold the check manifest into ``(verdict, reason_codes, obligations, composite_risk)``.

    Verdict = worst-of (any DENY -> DENY; else any REFER -> REFER; else ALLOW). Reason codes
    are the closed-enum codes of every non-CLEAR check (sorted, de-duplicated). Obligations are
    derived structurally: a REFER carries SAR_REQUIRED (POCA); a PEP match adds STEP_UP_KYC; a
    high composite risk adds EDD_REQUIRED; travel-rule applicability adds TRAVEL_RULE_FILING.
    Composite risk is the max of the per-check risk scores.
    """
    verdict_rank = max((_RANK[c.result] for c in check_results), default=0)
    verdict = _UNRANK[verdict_rank]

    reasons = sorted({c.reason_code for c in check_results
                      if c.reason_code and c.reason_code != "CLEAR"})

    risks = [c.risk_score for c in check_results if isinstance(c.risk_score, int)]
    composite = max(risks) if risks else None

    obligations: set[str] = set()
    if verdict == "REFER":
        obligations.add("SAR_REQUIRED")
    if "PEP_MATCH" in reasons and policy.get("refer_on_pep", True):
        obligations.add("STEP_UP_KYC")
    if composite is not None and composite >= int(policy.get("refer_risk", 600)) and verdict != "DENY":
        obligations.add("EDD_REQUIRED")
    if "TRAVEL_RULE_REQUIRED" in reasons:
        obligations.add("TRAVEL_RULE_FILING")

    return verdict, reasons, sorted(obligations), composite


__all__ = ["default_policy", "combine"]
