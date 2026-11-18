"""
algovoi-agent-passport — Agent Passport: PQC trust credentials for AI agents (standalone).

Issue Falcon-1024 (FIPS 206 / FN-DSA) signed credentials that bind an agent identity to
scopes and spend limits; verify them (signature + expiry + revocation) before granting spend
authority; revoke. Standalone deployable app — the signing key is injected and persistence is
pluggable (bundled in-memory + SQLite stores). Depends only on fastapi, pydantic, rfc8785, pqcrypto.

Embed::

    from algovoi_agent_passport import PassportIssuer, InMemoryStore, verify_passport, signing

    pk, sk = signing.generate_keypair()
    issuer = PassportIssuer(secret_key=sk, public_key=pk, store=InMemoryStore())
    res = await issuer.issue(agent_did="did:web:agent.example.com", scopes=["payments.send"])
    verdict = await verify_passport(res["credential"], pk, store=issuer.store)

Run as a service::

    from algovoi_agent_passport import create_app, PassportIssuer, SqliteStore, bearer_token_auth, signing
    pk, sk = signing.generate_keypair()
    issuer = PassportIssuer(secret_key=sk, public_key=pk, store=SqliteStore("passports.db"))
    app = create_app(issuer, public_key=pk, auth_dependency=bearer_token_auth("my-issuer-token"))
    # uvicorn module:app

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_agent_passport import hybrid, signing
from algovoi_agent_passport.app import create_app
from algovoi_agent_passport.auth import bearer_token_auth
from algovoi_agent_passport.event_ledger import EventLedger
from algovoi_agent_passport.issuer import PassportIssuer
from algovoi_agent_passport.models import (
    IssueRequest,
    IssueResponse,
    RevokeRequest,
    VerifyRequest,
    VerifyResult,
)
from algovoi_agent_passport.refs import passport_ref, passport_ref_from_payload
from algovoi_agent_passport.store import InMemoryStore, PassportStore, SqliteStore
from algovoi_agent_passport.verifier import verify_passport, verify_passport_chain

__version__ = "0.3.1"

__all__ = [
    "PassportIssuer",
    "verify_passport",
    "verify_passport_chain",
    "passport_ref",
    "passport_ref_from_payload",
    "EventLedger",
    "hybrid",
    "PassportStore",
    "InMemoryStore",
    "SqliteStore",
    "create_app",
    "bearer_token_auth",
    "signing",
    "IssueRequest",
    "IssueResponse",
    "VerifyRequest",
    "VerifyResult",
    "RevokeRequest",
    "__version__",
]
