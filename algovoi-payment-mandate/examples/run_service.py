"""
Run the Payment Mandate service locally.

    pip install -e ".[serve]"
    # generate a Falcon keypair once and export it:
    python -c "import base64; from algovoi_payment_mandate import signing; pk,sk=signing.generate_keypair(); print('MANDATE_FALCON_PK_B64=',base64.b64encode(pk).decode()); print('MANDATE_FALCON_SK_B64=',base64.b64encode(sk).decode())"
    export MANDATE_FALCON_SK_B64=...  MANDATE_FALCON_PK_B64=...
    export MANDATE_API_TOKEN=dev-token        # optional; omit to disable write auth
    python examples/run_service.py
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_payment_mandate import MandateIssuer, SqliteStore, bearer_token_auth, create_app, signing


def _load_keys() -> tuple[bytes, bytes]:
    sk_b64 = os.environ.get("MANDATE_FALCON_SK_B64")
    pk_b64 = os.environ.get("MANDATE_FALCON_PK_B64")
    if sk_b64 and pk_b64:
        return base64.b64decode(pk_b64), base64.b64decode(sk_b64)
    print("No MANDATE_FALCON_*_B64 set — generating an ephemeral keypair (dev only).")
    pk, sk = signing.generate_keypair()
    print("MANDATE_FALCON_PK_B64=", signing.public_key_b64(pk))
    return pk, sk


def main() -> None:
    pk, sk = _load_keys()
    issuer = MandateIssuer(
        secret_key=sk, public_key=pk,
        store=SqliteStore(os.environ.get("MANDATE_DB", "mandates.db")),
        issuer_did=os.environ.get("MANDATE_ISSUER_DID", "did:web:issuer.example.com"))
    app = create_app(issuer, public_key=pk, auth_dependency=bearer_token_auth(os.environ.get("MANDATE_API_TOKEN")))
    uvicorn.run(app, host=os.environ.get("MANDATE_HOST", "127.0.0.1"), port=int(os.environ.get("MANDATE_PORT", "8082")))


if __name__ == "__main__":
    main()
