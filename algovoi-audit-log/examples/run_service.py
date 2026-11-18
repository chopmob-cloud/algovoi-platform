"""
Run the Verifiable Audit Log service locally.

    pip install -e ".[serve]"
    python -c "import base64; from algovoi_audit_log import signing; pk,sk=signing.generate_keypair(); print('PK',base64.b64encode(pk).decode()); print('SK',base64.b64encode(sk).decode())"
    export AUDITLOG_FALCON_SK_B64=...  AUDITLOG_FALCON_PK_B64=...
    export AUDITLOG_API_TOKEN=dev-token        # optional; gates /append
    python examples/run_service.py
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_audit_log import AuditLog, SqliteStore, bearer_token_auth, create_app, signing


def _keys() -> tuple[bytes, bytes]:
    sk, pk = os.environ.get("AUDITLOG_FALCON_SK_B64"), os.environ.get("AUDITLOG_FALCON_PK_B64")
    if sk and pk:
        return base64.b64decode(pk), base64.b64decode(sk)
    print("No AUDITLOG_FALCON_*_B64 set — generating an ephemeral keypair (dev only).")
    pk_, sk_ = signing.generate_keypair()
    print("AUDITLOG_FALCON_PK_B64=", signing.public_key_b64(pk_))
    return pk_, sk_


def main() -> None:
    pk, sk = _keys()
    log = AuditLog(secret_key=sk, public_key=pk,
                   store=SqliteStore(os.environ.get("AUDITLOG_DB", "audit_log.db")),
                   issuer_did=os.environ.get("AUDITLOG_ISSUER_DID", "did:web:issuer.example.com"))
    app = create_app(log, public_key=pk, auth_dependency=bearer_token_auth(os.environ.get("AUDITLOG_API_TOKEN")))
    uvicorn.run(app, host=os.environ.get("AUDITLOG_HOST", "127.0.0.1"), port=int(os.environ.get("AUDITLOG_PORT", "8087")))


if __name__ == "__main__":
    main()
