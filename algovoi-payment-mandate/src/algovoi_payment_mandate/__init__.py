"""
algovoi-payment-mandate — Payment Mandate: verifiable authorization for recurring & agentic payments.

Crypto has no direct debit. A **mandate** is the missing primitive: a Falcon-1024 (FIPS 206 /
FN-DSA) signed authorization that a payer issues once — "you may charge me up to X per period
until Y" — that any platform can verify offline and check each pull against. Standalone deployable
app: the signing key is injected, persistence is pluggable (bundled in-memory + SQLite stores), and
the per-period cap is enforced by the store-backed charge ledger. Depends only on fastapi, pydantic,
rfc8785, pqcrypto.

Embed::

    from algovoi_payment_mandate import MandateIssuer, InMemoryStore, verify_mandate, signing

    pk, sk = signing.generate_keypair()
    issuer = MandateIssuer(secret_key=sk, public_key=pk, store=InMemoryStore())
    out = await issuer.issue(payer="acct:alice", payee="merchant:acme",
                             max_amount=50_000_000, period="month")   # 50 USDC/mo (micro-USD)
    verdict = await verify_mandate(out["mandate"], pk, store=issuer.store)
    charge = await issuer.authorize_charge(mandate=out["mandate"], charge_id="inv-001", amount=20_000_000)

Run as a service::

    from algovoi_payment_mandate import create_app, MandateIssuer, SqliteStore, bearer_token_auth, signing
    pk, sk = signing.generate_keypair()
    issuer = MandateIssuer(secret_key=sk, public_key=pk, store=SqliteStore("mandates.db"))
    app = create_app(issuer, public_key=pk, auth_dependency=bearer_token_auth("my-token"))
    # uvicorn module:app

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_payment_mandate import hybrid, periods, signing
from algovoi_payment_mandate.app import create_app
from algovoi_payment_mandate.auth import bearer_token_auth
from algovoi_payment_mandate.charge_ledger import ChargeLedger
from algovoi_payment_mandate.issuer import MandateIssuer
from algovoi_payment_mandate.models import (
    ChargeAuthorizationRequest,
    ChargeAuthorizationResult,
    IssueRequest,
    IssueResponse,
    RevokeRequest,
    VerifyRequest,
    VerifyResult,
)
from algovoi_payment_mandate.refs import mandate_ref, mandate_ref_from_payload
from algovoi_payment_mandate.store import InMemoryStore, MandateStore, SqliteStore
from algovoi_payment_mandate.verifier import verify_mandate, verify_mandate_chain

__version__ = "0.3.1"

__all__ = [
    "MandateIssuer",
    "verify_mandate",
    "verify_mandate_chain",
    "mandate_ref",
    "mandate_ref_from_payload",
    "ChargeLedger",
    "hybrid",
    "MandateStore",
    "InMemoryStore",
    "SqliteStore",
    "create_app",
    "bearer_token_auth",
    "signing",
    "periods",
    "IssueRequest",
    "IssueResponse",
    "VerifyRequest",
    "VerifyResult",
    "ChargeAuthorizationRequest",
    "ChargeAuthorizationResult",
    "RevokeRequest",
    "__version__",
]
