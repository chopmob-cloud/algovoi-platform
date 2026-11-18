"""
algovoi-substrate-guard-pro — verifiable admission control for the canonicalization substrate.

The commercial parent of the open ``algovoi-substrate-guard`` lite gate. It keeps every structural bound
of the lite tier and adds the bound a differential fuzz of nine independent JCS implementations proved was
missing — ``string_safety`` (reject lone surrogates / non-UTF-8 strings with a named code, before
canonicalization) — then records every ADMIT/REJECT as a Falcon-1024 (optionally hybrid ML-DSA-65) signed,
content-addressed, hash-linked decision that the Compliance Command Center ingests next to settlement and
spend evidence. Prove what your gate admitted, what it refused, and under which pinned bounds — offline.

Embed::

    from algovoi_substrate_guard_pro import GuardService, signing
    pk, sk = signing.generate_keypair()
    gate = GuardService(decision_secret_key=sk, decision_public_key=pk)
    r = gate.evaluate({"agent": "acct:alice", "amount": 25_000_000})
    assert r.admitted and r.guard_decision_ref.startswith("sha256:")

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_agent_passport import signing

from algovoi_substrate_guard_pro import hybrid
from algovoi_substrate_guard_pro.bounds import DEFAULT_PROFILE, GuardError, Profile, guard, profile_ref
from algovoi_substrate_guard_pro.ledger import AdmissionLedger
from algovoi_substrate_guard_pro.models import ChainVerifyResult, GuardResult, VerifyDecisionResult
from algovoi_substrate_guard_pro.refs import guard_decision_ref, subject_ref
from algovoi_substrate_guard_pro.service import GuardService
from algovoi_substrate_guard_pro.store import AdmissionStore
from algovoi_substrate_guard_pro.verifier import verify_guard_chain, verify_guard_decision

__version__ = "0.1.0"

__all__ = [
    "GuardService",
    "guard",
    "GuardError",
    "Profile",
    "DEFAULT_PROFILE",
    "profile_ref",
    "subject_ref",
    "guard_decision_ref",
    "AdmissionLedger",
    "AdmissionStore",
    "verify_guard_decision",
    "verify_guard_chain",
    "GuardResult",
    "VerifyDecisionResult",
    "ChainVerifyResult",
    "hybrid",
    "signing",
    "__version__",
]
