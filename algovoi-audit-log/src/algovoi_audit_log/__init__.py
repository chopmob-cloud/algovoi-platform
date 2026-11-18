"""
algovoi-audit-log — Verifiable Audit Log: a tamper-evident, post-quantum chain of business events.

Append any event (a JSON object) and it is content-addressed and recorded as a **Falcon-1024-signed**
entry linked to the previous one, forming an **append-only** log that anyone can verify offline: no
entry can be altered, inserted, removed, reordered, or back-dated. The event is recorded inline (no
blob store). Pluggable persistence (bundled in-memory + SQLite). Depends only on fastapi, pydantic,
rfc8785, pqcrypto.

Embed::

    from algovoi_audit_log import AuditLog, InMemoryStore, verify_chain, signing

    pk, sk = signing.generate_keypair()
    log = AuditLog(secret_key=sk, public_key=pk, store=InMemoryStore())   # or SqliteStore("audit.db")

    e = await log.append(event_type="payment.authorized",
                         event={"payment_id": "pay_1", "amount_microusd": 1500000, "decision": "ALLOW"},
                         actor="did:web:gateway")
    assert (await log.verify_chain()).valid

Run as a service::

    from algovoi_audit_log import create_app, AuditLog, SqliteStore, bearer_token_auth
    app = create_app(AuditLog(secret_key=sk, public_key=pk, store=SqliteStore("audit.db")),
                     public_key=pk, auth_dependency=bearer_token_auth("tok"))

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_audit_log import signing
from algovoi_audit_log.app import create_app
from algovoi_audit_log.auth import bearer_token_auth
from algovoi_audit_log.log import AuditLog
from algovoi_audit_log.models import (
    AppendRequest,
    AppendResponse,
    VerifyChainResult,
    VerifyEntryRequest,
    VerifyEntryResult,
)
from algovoi_audit_log.store import AuditStore, InMemoryStore, SqliteStore
from algovoi_audit_log.verifier import verify_chain, verify_entry

__version__ = "0.1.0"

__all__ = [
    "AuditLog",
    "verify_entry",
    "verify_chain",
    "AuditStore",
    "InMemoryStore",
    "SqliteStore",
    "create_app",
    "bearer_token_auth",
    "signing",
    "AppendRequest",
    "AppendResponse",
    "VerifyEntryRequest",
    "VerifyEntryResult",
    "VerifyChainResult",
    "__version__",
]
