"""
algovoi-spend-guardrail — the decision point for agentic payments.

One self-hosted call a platform makes **before executing a payment**: verify the agent's
**Agent Passport**, run the payer's **Payment Mandate** per-period authorize-charge, apply platform
**policy**, and return a Falcon-1024-signed **ALLOW/DENY decision receipt**. It moves no funds — the
platform executes iff the decision is ALLOW. The "authorization stack" (Agent Passport + Payment
Mandate) wired into a single enforcement gate.

Usage::

    from algovoi_agent_passport import PassportIssuer, InMemoryStore as PStore, signing
    from algovoi_payment_mandate import MandateIssuer, InMemoryStore as MStore
    from algovoi_spend_guardrail import SpendGuardrail, Policy, create_app

    ppk, psk = signing.generate_keypair()          # passport issuer key
    mpk, msk = signing.generate_keypair()          # mandate authority key
    gpk, gsk = signing.generate_keypair()          # guardrail decision key

    mandate_issuer = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore())
    guard = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mandate_issuer,
                           decision_secret_key=gsk, decision_public_key=gpk,
                           policy=Policy(max_amount_per_tx=25_000_000, required_scope="payments.send"))

    decision = await guard.authorize(passport_credential=cred, mandate=mandate,
                                     charge_id="inv-1", amount=20_000_000, payee="merchant:acme")
    if decision.allowed:
        ...                                         # execute the payment

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_agent_passport import bearer_token_auth, signing

from algovoi_spend_guardrail import bounds, hybrid, refs
from algovoi_spend_guardrail.app import create_app
from algovoi_spend_guardrail.bounds import Bounds
from algovoi_spend_guardrail.guardrail import SpendGuardrail
from algovoi_spend_guardrail.ledger import DecisionLedger
from algovoi_spend_guardrail.models import (
    AuthorizeRequest,
    ChainVerifyResult,
    DecisionResult,
    VerifyDecisionRequest,
    VerifyDecisionResult,
)
from algovoi_spend_guardrail.policy import Policy
from algovoi_spend_guardrail.store import DecisionStore
from algovoi_spend_guardrail.verifier import verify_decision, verify_decision_chain

__version__ = "0.2.1"

__all__ = [
    "SpendGuardrail",
    "Policy",
    "DecisionLedger",
    "DecisionStore",
    "Bounds",
    "verify_decision",
    "verify_decision_chain",
    "refs",
    "bounds",
    "hybrid",
    "create_app",
    "bearer_token_auth",
    "signing",
    "AuthorizeRequest",
    "DecisionResult",
    "VerifyDecisionRequest",
    "VerifyDecisionResult",
    "ChainVerifyResult",
    "__version__",
]
