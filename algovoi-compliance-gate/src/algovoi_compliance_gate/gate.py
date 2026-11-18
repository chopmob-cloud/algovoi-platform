"""The Compliance Gate.

Two surfaces:

* :meth:`ComplianceGate.screen_and_certify` — the original single-signal path: screen a
  payer, certify an ALLOW/REFER/DENY verdict as a no-PII Falcon receipt. Unchanged and
  byte-compatible with ``algovoi-proofs`` and the lite tier.

* :meth:`ComplianceGate.decide` — the comprehensive v2 decision engine. Runs a *composite*
  of typed checks (sanctions/PEP/jurisdiction/risk/travel-rule), folds them by a
  content-addressed **policy**, and emits a verdict that is simultaneously:
    - **no-PII** (payer recorded only as ``payer_ref = sha256(network:address)``),
    - **policy-bound** (``policy_ref`` + ``policy_bound_ref`` — silent rotation detectable),
    - **action-bound** (``action_ref`` of the gated action, when supplied),
    - **chained** (hash-linked into an append-only decision ledger),
    - **post-quantum signed** (Falcon-1024, optional ML-DSA-65 co-signature),
    - **CCC-ingestable** (entry_type ``compliance_gate_verdict``) and offline-verifiable.

The crypto core is ``substrate2`` throughout.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import substrate2
from substrate2 import pqc

from algovoi_compliance_gate import licensing, signing
from algovoi_compliance_gate.checks import Check, SanctionsCheck
from algovoi_compliance_gate.policy import combine, default_policy
from algovoi_compliance_gate.screener import Screener

ENTRY_TYPE = "compliance_gate_verdict"


class ComplianceGate:
    """Turns screening into signed, no-PII compliance verdicts. See module docstring."""

    def __init__(
        self,
        *,
        secret_key: bytes,
        public_key: bytes,
        screener: Screener | None = None,
        checks: list[Check] | None = None,
        policy: dict | None = None,
        gate_did: str = "did:web:compliance.example.com",
        jurisdiction_flags: tuple[str, ...] | list[str] = ("UK", "EU"),
        mldsa_keys: tuple[bytes, bytes] | None = None,
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        if checks is None:
            if screener is None:
                raise ValueError("provide either a screener or a list of checks")
            checks = [SanctionsCheck(screener)]
        self.sk = secret_key
        self.pk = public_key
        self.screener = screener
        self.checks = checks
        self.gate_did = gate_did
        self.jurisdiction_flags = list(jurisdiction_flags)
        self.kid = signing.kid_for(public_key)

        # Content-addressed policy: its hash binds into every verdict.
        self.policy = policy or default_policy()
        self.policy_ref = substrate2.policy_ref(self.policy)

        # Optional ML-DSA-65 co-signature (crypto-agility / defence-in-depth).
        self.dual_sign = mldsa_keys is not None
        self.mldsa_pk, self.mldsa_sk = (mldsa_keys or (None, None))

        # Append-only decision ledger state.
        self._seq = 0
        self._prev_hash: str | None = None
        self.envelopes: list[str] = []

    # ── legacy single-signal path (unchanged, proofs/lite-compatible) ─────────
    async def screen_and_certify(self, *, network: str, address: str,
                                 amount_microusd: int | None = None, context: dict | None = None) -> dict:
        sr = await (self.screener or self.checks[0]._s).screen(  # type: ignore[attr-defined]
            network=network, address=address, amount_microusd=amount_microusd, context=context)
        payer_ref = "sha256:" + hashlib.sha256(f"{network}:{address}".encode()).hexdigest()
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        receipt = {
            "canon_version": "jcs-rfc8785-v1",
            "jurisdiction_flags": self.jurisdiction_flags,
            "payer_ref": payer_ref,
            "screen_provider_did": sr.provider_did,
            "screen_result": sr.result,
            "screen_timestamp_ms": now_ms,
        }
        envelope = signing.make_envelope(receipt, self.sk, self.pk)
        return {
            "result": sr.result, "screen_provider_did": sr.provider_did, "payer_ref": payer_ref,
            "receipt": receipt, "receipt_envelope": envelope, "receipt_hash": signing.payload_hash(receipt),
            "kid": self.kid, "screen_timestamp_ms": now_ms, "jurisdiction_flags": list(self.jurisdiction_flags),
            "risk_score": sr.risk_score, "reasons": sr.reasons or None,
        }

    # ── comprehensive v2 decision engine ──────────────────────────────────────
    async def decide(self, *, network: str, address: str, action: dict | None = None,
                      amount_microusd: int | None = None, context: dict | None = None) -> dict:
        """Run every configured check, fold by policy, and emit a bound, chained, no-PII
        verdict. ``action`` (optional) is ``{agent_id, action_type, scope, timestamp_ms}`` —
        when given the verdict is bound to that action's ``action_ref``."""
        results = [await c.run(network=network, address=address, amount_microusd=amount_microusd,
                               context=context, policy=self.policy) for c in self.checks]
        verdict, reason_codes, obligations, composite_risk = combine(results, self.policy)

        payer_ref = "sha256:" + hashlib.sha256(f"{network}:{address}".encode()).hexdigest()
        action_ref = None
        if action is not None:
            action_ref = "sha256:" + substrate2.action_ref(
                agent_id=action["agent_id"], action_type=action["action_type"],
                scope=action["scope"], timestamp_ms=action["timestamp_ms"])
        subject_ref = action_ref or payer_ref
        policy_bound_ref = substrate2.policy_bound_ref(subject_ref, self.policy_ref)

        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        sig_alg = "Falcon-1024+ML-DSA-65" if self.dual_sign else "Falcon-1024"
        payload = {
            "canon_version": "jcs-rfc8785-v1",
            "type": ENTRY_TYPE,
            "seq": self._seq,
            "prev_entry_hash": self._prev_hash,
            "gate_did": self.gate_did,
            "jurisdiction_flags": self.jurisdiction_flags,
            "payer_ref": payer_ref,
            "action_ref": action_ref,
            "subject_ref": subject_ref,
            "policy_ref": self.policy_ref,
            "policy_bound_ref": policy_bound_ref,
            "screen_result": verdict,
            "reason_codes": reason_codes,
            "obligations": obligations,
            "checks": [r.manifest_entry() for r in results],
            "risk_score": composite_risk,
            "sig_alg": sig_alg,
            "screen_timestamp_ms": now_ms,
        }
        envelope = self._sign_envelope(payload)
        self.envelopes.append(envelope)
        self._prev_hash = substrate2.sha256_jcs_prefixed(payload)
        self._seq += 1
        return {
            "result": verdict, "reason_codes": reason_codes, "obligations": obligations,
            "risk_score": composite_risk, "payer_ref": payer_ref, "action_ref": action_ref,
            "subject_ref": subject_ref, "policy_ref": self.policy_ref, "policy_bound_ref": policy_bound_ref,
            "receipt": payload, "receipt_envelope": envelope,
            "receipt_hash": substrate2.sha256_jcs_prefixed(payload), "kid": self.kid,
            "sig_alg": sig_alg, "seq": payload["seq"], "screen_timestamp_ms": now_ms,
        }

    def _sign_envelope(self, payload: dict) -> str:
        msg = substrate2.canonicalize_bytes(payload)
        env = {"payload": payload, "alg": payload["sig_alg"], "kid": self.kid,
               "sig": signing.b64u_encode(signing.sign_bytes(self.sk, msg))}
        if self.dual_sign:
            env["sig_mldsa"] = signing.b64u_encode(pqc.sign_ml_dsa_65(self.mldsa_sk, msg))
        return signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
