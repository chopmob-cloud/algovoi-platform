"""Run a standalone Agent Passport service.

    pip install -e .[serve]
    PASSPORT_ISSUER_TOKEN=my-secret python examples/run_service.py
    # then: uvicorn is started on http://127.0.0.1:8099

Generates a fresh Falcon keypair on each run (for a real deployment, load a persistent key).
"""
from __future__ import annotations

import os

import uvicorn

from algovoi_agent_passport import PassportIssuer, SqliteStore, bearer_token_auth, create_app, signing

pk, sk = signing.generate_keypair()
issuer = PassportIssuer(
    secret_key=sk, public_key=pk,
    store=SqliteStore(os.environ.get("PASSPORT_DB", "passports.db")),
    issuer_did=os.environ.get("PASSPORT_ISSUER_DID", "did:web:issuer.example.com"),
)
app = create_app(
    issuer, public_key=pk,
    auth_dependency=bearer_token_auth(os.environ.get("PASSPORT_ISSUER_TOKEN", "change-me")),
)

if __name__ == "__main__":
    print(f"Agent Passport service — issuer kid: {issuer.kid}")
    uvicorn.run(app, host="127.0.0.1", port=8099)
