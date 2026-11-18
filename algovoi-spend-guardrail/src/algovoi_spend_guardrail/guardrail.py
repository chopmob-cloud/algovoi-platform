"""
The Spend Guardrail: one decision point combining Agent Passport + Payment Mandate + platform policy.

Returns a Falcon-1024-signed ALLOW/DENY **decision receipt** — it does NOT move funds. The calling
platform executes the payment iff the decision is ALLOW. Order of checks: passport -> policy/limit ->
mandate per-period cap (the mandate ledger is only consumed when everything else has passed).

Beyond the lite tier, every decision here is:
  * **content-addressed** — it carries a ``decision_ref`` built with the *published* ``guardrail_ref``
    construction over refs the gate derives from the credentials it verified, so a paid decision
    recomputes byte-for-byte the ref an AP2/A2A lite adopter pinned (the lite tier is a true feeder);
  * **replay-proof** — each decision carries a ``nonce`` and an ``expires_at`` freshness window;
  * **chained** — appended to a tamper-evident :class:`DecisionLedger` that exports a CCC-ingestable pack.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from algovoi_agent_passport import signing, verify_passport
from algovoi_payment_mandate import MandateIssuer

from algovoi_spend_guardrail import bounds as _bounds
from algovoi_spend_guardrail import licensing, refs
from algovoi_spend_guardrail.bounds import Bounds
from algovoi_spend_guardrail.ledger import DecisionLedger
from algovoi_spend_guardrail.models import DecisionResult
from algovoi_spend_guardrail.policy import Policy


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class SpendGuardrail:
    """Wire the authorization stack into a single enforcement gate.

    ``mandate_issuer`` is a :class:`algovoi_payment_mandate.MandateIssuer` (it holds the mandate
    authority public key + the charge ledger/store). ``decision_secret_key``/``decision_public_key``
    are the guardrail's own Falcon key, used to sign decision receipts (distinct from the passport
    and mandate keys, so "who decided" is its own provenance). ``decision_ttl_secs`` is the freshness
    window stamped into every decision (replay protection): a verifier rejects a decision presented
    after it expires.
    """

    def __init__(
        self,
        *,
        passport_public_key: bytes,
        mandate_issuer: MandateIssuer,
        decision_secret_key: bytes,
        decision_public_key: bytes,
        policy: Policy | None = None,
        passport_store=None,
        guardrail_did: str = "did:web:guardrail.example.com",
        decision_ttl_secs: int = 300,
        strict_revocation: bool = True,
        bounds: Bounds | None = None,
        mldsa_secret_key: bytes | None = None,
        mldsa_public_key: bytes | None = None,
        decision_store=None,
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        self.passport_pk = passport_public_key
        self.passport_store = passport_store
        self.mandate_issuer = mandate_issuer
        self.dsk = decision_secret_key
        self.dpk = decision_public_key
        self.policy = policy or Policy()
        self.did = guardrail_did
        self.decision_ttl_secs = int(decision_ttl_secs)
        # Commercial enforcement gate: fail CLOSED when revocation cannot be confirmed (see Cap B).
        self.strict_revocation = bool(strict_revocation)
        # Input-bounds profile enforced before any signature work (Cap E / substrate-guard).
        self.bounds = bounds or _bounds.DEFAULT_BOUNDS
        # Optional hybrid co-signing key (Falcon + ML-DSA-65); when set, decisions carry both sigs.
        self.mldsa_pk = mldsa_public_key
        self.kid = signing.kid_for(decision_public_key)
        # The decision chain — every decision is appended, tamper-evident, CCC-exportable.
        # With a decision_store it persists (seq continuous + velocity over the persisted ALLOWs).
        self.ledger = DecisionLedger(decision_secret_key, decision_public_key,
                                     mldsa_secret_key, mldsa_public_key, store=decision_store)
        # Recent ALLOWs (agent_did, amount, when) for the rolling-window velocity cap.
        self._allow_history: list[tuple[str | None, int, datetime]] = []
        # The policy in force, content-addressed once (it is fixed for this gate's lifetime).
        self._policy_ref = refs.policy_ref(self.policy.snapshot())

    def export_pack(self, out_dir: str) -> str:
        """Write the signed decision chain as a CCC-ingestable evidence pack."""
        return self.ledger.export_pack(out_dir)

    def _velocity_exceeded(self, agent_did: str | None, amount: int, now: datetime) -> bool:
        """True if authorizing ``amount`` would breach this agent's rolling-window velocity cap.

        Unlike the mandate's calendar-period cap, this is a true rolling window, so a burst that
        straddles a period boundary (e.g. just before and just after midnight) is still caught.
        """
        win = self.policy.velocity_window_secs
        cap = self.policy.velocity_max_amount
        if not win or cap is None:
            return False
        cutoff = now - timedelta(seconds=win)
        if self.ledger.store is not None:
            # rolling window over the PERSISTED ALLOWs (survives restart); fixed-width ISO -> lexical == chronological
            spent = self.ledger.store.velocity_total(agent_did=agent_did, since_iso=_iso(cutoff))
        else:
            spent = sum(a for (ad, a, ts) in self._allow_history if ad == agent_did and ts >= cutoff)
        return (spent + amount) > cap

    async def _refs_for(self, *, passport_payload: dict | None, mandate_str: str | None):
        """Derive (agent_ref, mandate_ref, policy_bound_ref) from what the gate actually verified.

        ``agent_ref`` is only derived from a *verified* passport payload (never from an untrusted one).
        """
        agent_ref = refs.passport_ref(passport_payload) if passport_payload else None
        mandate_ref_ = None
        if mandate_str:
            try:
                mp, _, _ = signing.open_envelope(mandate_str)
                status = await self.mandate_issuer.status(
                    kid=mp.get("kid"), mandate_id=str(mp.get("mandate_id")))
                rev = "revoked" if status == "revoked" else "active"
                mandate_ref_ = refs.mandate_ref(mp, revocation_state=rev)
            except Exception:  # noqa: BLE001 — a malformed mandate simply yields no ref
                mandate_ref_ = None
        pbref = (refs.policy_bound_ref(policy_ref_=self._policy_ref, subject_ref=agent_ref)
                 if agent_ref is not None else None)
        return agent_ref, mandate_ref_, pbref

    def _decide(self, decision: str, reasons: list[str], *, agent_did, charge_id, amount, payee, asset,
                mandate_id=None, remaining=None, passport_kid=None,
                agent_ref=None, mandate_ref_=None, policy_bound_ref_=None) -> DecisionResult:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = now + timedelta(seconds=self.decision_ttl_secs)
        decision_id = str(uuid4())
        # decision_ref: the published guardrail_ref construction — only when all inputs are present.
        d_ref = None
        if agent_ref and mandate_ref_ and policy_bound_ref_:
            try:
                d_ref = refs.decision_ref(verdict=decision, agent_ref=agent_ref,
                                          mandate_ref_=mandate_ref_, policy_bound_ref_=policy_bound_ref_)
            except ValueError:
                d_ref = None
        core = {
            "version": "1", "decision_id": decision_id, "decision": decision,
            "reasons": reasons, "agent_did": agent_did, "charge_id": charge_id, "amount": amount,
            "asset": asset, "payee": payee, "mandate_id": mandate_id,
            "remaining_this_period": remaining, "passport_kid": passport_kid,
            "agent_ref": agent_ref, "mandate_ref": mandate_ref_,
            "policy_bound_ref": policy_bound_ref_, "decision_ref": d_ref,
            "nonce": secrets.token_hex(16),
            "guardrail_did": self.did, "kid": self.kid,
            "evaluated_at": _iso(now), "expires_at": _iso(expires),
        }
        env, payload = self.ledger.append(core)
        if decision == "ALLOW" and self.ledger.store is None:
            # in-memory velocity history only when not persisted (the store is the source of truth otherwise)
            self._allow_history.append((agent_did, int(amount or 0), now))
        return DecisionResult(
            allowed=(decision == "ALLOW"), decision=decision, reasons=reasons, decision_id=decision_id,
            decision_receipt=env, agent_did=agent_did, charge_id=charge_id, amount=amount, asset=asset,
            payee=payee, mandate_id=mandate_id, remaining_this_period=remaining,
            passport_kid=passport_kid, kid=self.kid, evaluated_at=_iso(now), expires_at=_iso(expires),
            agent_ref=agent_ref, mandate_ref=mandate_ref_, policy_bound_ref=policy_bound_ref_,
            decision_ref=d_ref, seq=payload["seq"], prev_entry_hash=payload["prev_entry_hash"])

    async def authorize(
        self,
        *,
        passport_credential: str,
        mandate: str,
        charge_id: str,
        amount: int,
        payee: str,
        asset: str | None = None,
        at: str | None = None,
        expected_agent_did: str | None = None,
    ) -> DecisionResult:
        """Evaluate a proposed spend and return a signed ALLOW/DENY decision (never raises)."""
        # 0. Input bounds — reject oversized/malformed input cheaply, before any signature work.
        viol = _bounds.check(passport_credential=passport_credential, mandate=mandate,
                             charge_id=charge_id, amount=amount, payee=payee, asset=asset,
                             bounds=self.bounds)
        if viol:
            # never echo an out-of-range amount into the signed payload (it may not be JCS-safe)
            safe_amount = amount if isinstance(amount, int) and 0 <= amount < 2 ** 53 else None
            return self._decide("DENY", viol, agent_did=None, charge_id=str(charge_id)[:256],
                                amount=safe_amount, payee=str(payee)[:256], asset=asset, passport_kid=None)

        # 1. Agent Passport — must verify and be active.
        pv = await verify_passport(passport_credential, self.passport_pk, store=self.passport_store,
                                   expected_agent_did=expected_agent_did, strict=self.strict_revocation)
        passport_kid = pv.kid
        # mandate_ref is derivable even on a passport deny (the mandate itself parses); agent_ref is not.
        _, mandate_ref_, _ = await self._refs_for(passport_payload=None, mandate_str=mandate)
        if not pv.verified:
            return self._decide("DENY", [f"passport:{pv.error_code or pv.status}"],
                                agent_did=pv.agent_did, charge_id=charge_id, amount=amount,
                                payee=payee, asset=asset, passport_kid=passport_kid,
                                mandate_ref_=mandate_ref_)
        agent_did = pv.agent_did
        scopes = pv.scopes or []
        # The passport verified, so its payload is trusted — derive the content-addressed refs.
        passport_payload, _, _ = signing.open_envelope(passport_credential)
        agent_ref, mandate_ref_, policy_bound_ref_ = await self._refs_for(
            passport_payload=passport_payload, mandate_str=mandate)

        # 2. Policy + the passport's own spend limit — deny BEFORE touching the mandate ledger.
        reasons = self.policy.evaluate(agent_did=agent_did, scopes=scopes, asset=asset, payee=payee, amount=amount)
        if pv.spend_limit_microusd is not None and amount > pv.spend_limit_microusd:
            reasons.append("passport:spend_limit_exceeded")
        if reasons:
            return self._decide("DENY", reasons, agent_did=agent_did, charge_id=charge_id,
                                amount=amount, payee=payee, asset=asset, passport_kid=passport_kid,
                                agent_ref=agent_ref, mandate_ref_=mandate_ref_,
                                policy_bound_ref_=policy_bound_ref_)

        # 2b. Rolling-window velocity — a hard cap on recent ALLOWs for this agent (deny on breach).
        if self._velocity_exceeded(agent_did, amount, datetime.now(timezone.utc)):
            return self._decide("DENY", ["policy:velocity_exceeded"], agent_did=agent_did,
                                charge_id=charge_id, amount=amount, payee=payee, asset=asset,
                                passport_kid=passport_kid, agent_ref=agent_ref,
                                mandate_ref_=mandate_ref_, policy_bound_ref_=policy_bound_ref_)

        # 2c. Review tier — REFER for a human/step-up decision; the mandate ledger is NOT consumed.
        review = self.policy.review(payee=payee, amount=amount)
        if review:
            return self._decide("REFER", review, agent_did=agent_did, charge_id=charge_id,
                                amount=amount, payee=payee, asset=asset, passport_kid=passport_kid,
                                agent_ref=agent_ref, mandate_ref_=mandate_ref_,
                                policy_bound_ref_=policy_bound_ref_)

        # 3. Payment Mandate — validity + per-period cap (records the charge iff authorized).
        # SECURITY (2026-08-19): do NOT forward the caller-supplied `at` into cap accounting. The
        # charged party must not choose the accounting-period bucket (sending each charge with a
        # distinct `at` lands every one in its own empty bucket and evades the per-period cap). The
        # mandate engine now buckets by server time only; `at` is advisory metadata and is dropped here
        # so cap accounting stays safe even against an older payment-mandate build.
        ch = await self.mandate_issuer.authorize_charge(mandate=mandate, charge_id=charge_id,
                                                        amount=amount, payee=payee, asset=asset,
                                                        strict=self.strict_revocation)
        if not ch.authorized:
            return self._decide("DENY", [f"mandate:{ch.decline_reason}"], agent_did=agent_did,
                                charge_id=charge_id, amount=amount, payee=payee, asset=asset,
                                mandate_id=ch.mandate_id, passport_kid=passport_kid,
                                agent_ref=agent_ref, mandate_ref_=mandate_ref_,
                                policy_bound_ref_=policy_bound_ref_)

        return self._decide("ALLOW", [], agent_did=agent_did, charge_id=charge_id, amount=amount,
                            payee=payee, asset=asset, mandate_id=ch.mandate_id,
                            remaining=ch.remaining_this_period, passport_kid=passport_kid,
                            agent_ref=agent_ref, mandate_ref_=mandate_ref_,
                            policy_bound_ref_=policy_bound_ref_)
