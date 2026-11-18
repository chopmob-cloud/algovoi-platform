"""
Run the Compliance Gate service locally.

    pip install -e ".[serve]"
    # generate a Falcon keypair once:
    python -c "import base64; from algovoi_compliance_gate import signing; pk,sk=signing.generate_keypair(); print('PK',base64.b64encode(pk).decode()); print('SK',base64.b64encode(sk).decode())"
    export GATE_FALCON_SK_B64=...  GATE_FALCON_PK_B64=...
    export GATE_API_TOKEN=dev-token        # optional; gates /screen
    python examples/run_service.py

Swap ``AllowAllScreener`` for your own ``Screener`` implementation over your sanctions/PEP provider.
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_compliance_gate import (
    AllowAllScreener,
    ComplianceGate,
    bearer_token_auth,
    create_app,
    signing,
)


def _keys() -> tuple[bytes, bytes]:
    sk, pk = os.environ.get("GATE_FALCON_SK_B64"), os.environ.get("GATE_FALCON_PK_B64")
    if sk and pk:
        return base64.b64decode(pk), base64.b64decode(sk)
    print("No GATE_FALCON_*_B64 set — generating an ephemeral keypair (dev only).")
    pk_, sk_ = signing.generate_keypair()
    print("GATE_FALCON_PK_B64=", signing.public_key_b64(pk_))
    return pk_, sk_


def main() -> None:
    pk, sk = _keys()
    gate = ComplianceGate(secret_key=sk, public_key=pk, screener=AllowAllScreener(),
                          gate_did=os.environ.get("GATE_DID", "did:web:compliance.example.com"))
    app = create_app(gate, public_key=pk, auth_dependency=bearer_token_auth(os.environ.get("GATE_API_TOKEN")))
    uvicorn.run(app, host=os.environ.get("GATE_HOST", "127.0.0.1"), port=int(os.environ.get("GATE_PORT", "8086")))


if __name__ == "__main__":
    main()
