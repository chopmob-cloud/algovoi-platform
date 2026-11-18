"""
Run the Proofs service locally.

    pip install -e ".[serve]"
    # generate a Falcon keypair once:
    python -c "from algovoi_proofs import signing,base64=__import__('base64'); pk,sk=signing.generate_keypair(); print('PK',base64.b64encode(pk).decode()); print('SK',base64.b64encode(sk).decode())"
    export PROOFS_FALCON_SK_B64=...   PROOFS_FALCON_PK_B64=...
    export PROOFS_PROVER_URL=http://127.0.0.1:8091
    export PROOFS_API_TOKEN=dev-token        # optional; omit to disable issue auth
    python examples/run_service.py
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_proofs import create_app, signing


def _load_keys() -> tuple[bytes, bytes]:
    sk_b64 = os.environ.get("PROOFS_FALCON_SK_B64")
    pk_b64 = os.environ.get("PROOFS_FALCON_PK_B64")
    if sk_b64 and pk_b64:
        return base64.b64decode(pk_b64), base64.b64decode(sk_b64)
    print("No PROOFS_FALCON_*_B64 set — generating an ephemeral keypair (dev only).")
    pk, sk = signing.generate_keypair()
    print("PK_B64=", signing.public_key_b64(pk))
    return pk, sk


def main() -> None:
    pk, sk = _load_keys()
    app = create_app(
        secret_key=sk,
        public_key=pk,
        prover_url=os.environ.get("PROOFS_PROVER_URL", "http://127.0.0.1:8091"),
        issuer_did=os.environ.get("PROOFS_ISSUER_DID", "did:web:issuer.example.com"),
        api_token=os.environ.get("PROOFS_API_TOKEN"),
    )
    uvicorn.run(app, host=os.environ.get("PROOFS_HOST", "127.0.0.1"), port=int(os.environ.get("PROOFS_PORT", "8081")))


if __name__ == "__main__":
    main()
