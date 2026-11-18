"""Typed, composable compliance checks — the multi-signal layer under the verdict.

Each check returns a :class:`CheckResult` (a categorical ALLOW/REFER/DENY plus a closed
reason code and an optional risk score). The gate runs every configured check, records
them as a no-PII *check manifest*, and a deterministic policy-driven combiner
(:mod:`policy`) folds them into the final verdict. No PII leaves a check — only the
categorical result, a closed reason code, the provider DID, and a numeric risk score.

Built-ins cover the common signals (sanctions/AML via your injected Screener, PEP,
jurisdiction, risk threshold, travel-rule applicability); inject your own by implementing
the :class:`Check` protocol.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import substrate2

from algovoi_compliance_gate.screener import SCREEN_RESULTS, Screener

# Closed enumerations — byte-distinct, audit-grade, machine-actionable (no free text).
REASON_CODES = {
    "CLEAR", "DENYLIST", "SANCTIONS_HIT", "PEP_MATCH", "RISK_THRESHOLD",
    "JURISDICTION_BLOCK", "TRAVEL_RULE_REQUIRED", "RISK_UNAVAILABLE",
}
OBLIGATIONS = {"SAR_REQUIRED", "EDD_REQUIRED", "STEP_UP_KYC", "TRAVEL_RULE_FILING"}

_RANK = {"ALLOW": 0, "REFER": 1, "DENY": 2}


@dataclass
class CheckResult:
    """The no-PII outcome of one check."""
    check: str                                   # check name, e.g. "sanctions"
    result: str                                  # ALLOW | REFER | DENY
    provider_did: str = "did:web:check.example.com"
    risk_score: int | None = None                # optional 0..1000 (milliunits)
    reason_code: str | None = None               # one of REASON_CODES

    def __post_init__(self) -> None:
        if self.result not in SCREEN_RESULTS:
            raise ValueError(f"result must be one of {sorted(SCREEN_RESULTS)}")
        if self.reason_code is not None and self.reason_code not in REASON_CODES:
            raise ValueError(f"reason_code must be one of {sorted(REASON_CODES)}")

    def manifest_entry(self) -> dict:
        """The no-PII record of this check, for the receipt's check manifest."""
        d = {"check": self.check, "result": self.result, "provider_did": self.provider_did}
        if self.risk_score is not None:
            d["risk_score"] = self.risk_score
        if self.reason_code is not None:
            d["reason_code"] = self.reason_code
        # content-address the check outcome so it is itself referenceable
        d["check_ref"] = substrate2.sha256_jcs_prefixed(d)
        return d


@runtime_checkable
class Check(Protocol):
    async def run(self, *, network: str, address: str, amount_microusd: int | None,
                  context: dict | None, policy: dict) -> CheckResult: ...


class SanctionsCheck:
    """Adapts an injected :class:`Screener` (your sanctions/AML provider) into a check."""

    def __init__(self, screener: Screener, *, check: str = "sanctions") -> None:
        self._s = screener
        self._check = check

    async def run(self, *, network, address, amount_microusd, context, policy) -> CheckResult:
        sr = await self._s.screen(network=network, address=address,
                                  amount_microusd=amount_microusd, context=context)
        reason = {"DENY": "SANCTIONS_HIT", "REFER": "DENYLIST", "ALLOW": "CLEAR"}[sr.result]
        return CheckResult(check=self._check, result=sr.result, provider_did=sr.provider_did,
                           risk_score=sr.risk_score, reason_code=reason)


class PepCheck:
    """Politically-Exposed-Person check. Reads ``context['pep']`` (bool). A PEP match is a
    REFER with a STEP_UP_KYC obligation (set by the combiner), never an automatic DENY."""

    def __init__(self, *, provider_did: str = "did:web:pep.example.com") -> None:
        self._did = provider_did

    async def run(self, *, network, address, amount_microusd, context, policy) -> CheckResult:
        is_pep = bool((context or {}).get("pep"))
        return CheckResult(check="pep", result="REFER" if is_pep else "ALLOW",
                           provider_did=self._did, reason_code="PEP_MATCH" if is_pep else "CLEAR")


class JurisdictionCheck:
    """Blocks payer jurisdictions in ``policy['deny_jurisdictions']``. Reads
    ``context['jurisdiction']`` (an ISO country code)."""

    def __init__(self, *, provider_did: str = "did:web:jurisdiction.example.com") -> None:
        self._did = provider_did

    async def run(self, *, network, address, amount_microusd, context, policy) -> CheckResult:
        juris = (context or {}).get("jurisdiction")
        blocked = juris in set(policy.get("deny_jurisdictions", []))
        return CheckResult(check="jurisdiction", result="DENY" if blocked else "ALLOW",
                           provider_did=self._did, reason_code="JURISDICTION_BLOCK" if blocked else "CLEAR")


class RiskThresholdCheck:
    """Applies the policy's numeric risk thresholds to ``context['risk_score']`` (0..1000):
    ``>= deny_risk`` → DENY, ``>= refer_risk`` → REFER, else ALLOW."""

    def __init__(self, *, provider_did: str = "did:web:risk.example.com") -> None:
        self._did = provider_did

    async def run(self, *, network, address, amount_microusd, context, policy) -> CheckResult:
        score = (context or {}).get("risk_score")
        if not isinstance(score, int):
            # SECURITY (2026-08-19): the operator added the risk check because they WANT risk evaluated —
            # so a missing/invalid score must FAIL SAFE (REFER for a human/step-up), not silently CLEAR.
            # Previously an absent score returned ALLOW, letting a caller that simply omits the score skip
            # the risk gate entirely.
            return CheckResult(check="risk", result="REFER", provider_did=self._did,
                               reason_code="RISK_UNAVAILABLE")
        if score >= int(policy.get("deny_risk", 900)):
            res = "DENY"
        elif score >= int(policy.get("refer_risk", 600)):
            res = "REFER"
        else:
            res = "ALLOW"
        return CheckResult(check="risk", result=res, provider_did=self._did, risk_score=score,
                           reason_code="RISK_THRESHOLD" if res != "ALLOW" else "CLEAR")


class TravelRuleCheck:
    """Travel-rule applicability: at/above ``policy['travel_rule_threshold_microusd']`` the
    transfer is in scope. Applicability is an *obligation* (filing), not a block — this check
    stays ALLOW and signals via its reason code so the combiner attaches the obligation."""

    def __init__(self, *, provider_did: str = "did:web:travelrule.example.com") -> None:
        self._did = provider_did

    async def run(self, *, network, address, amount_microusd, context, policy) -> CheckResult:
        thr = policy.get("travel_rule_threshold_microusd")
        applies = isinstance(amount_microusd, int) and isinstance(thr, int) and amount_microusd >= thr
        return CheckResult(check="travel_rule", result="ALLOW", provider_did=self._did,
                           reason_code="TRAVEL_RULE_REQUIRED" if applies else "CLEAR")


__all__ = [
    "REASON_CODES", "OBLIGATIONS", "CheckResult", "Check",
    "SanctionsCheck", "PepCheck", "JurisdictionCheck", "RiskThresholdCheck", "TravelRuleCheck",
]
