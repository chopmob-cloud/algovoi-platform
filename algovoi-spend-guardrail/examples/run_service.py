"""
Run the Spend Guardrail service locally.

The guardrail composes the authorization stack: it needs the **Agent Passport** issuer public key,
a **Payment Mandate** issuer (authority key + store), and its own **decision** Falcon key.

    pip install -e ".[serve]"
    export GUARDRAIL_PASSPORT_PK_B64=...     # the Agent Passport issuer PUBLIC key
    export GUARDRAIL_MANDATE_SK_B64=... GUARDRAIL_MANDATE_PK_B64=...   # mandate authority key
    export GUARDRAIL_DECISION_SK_B64=... GUARDRAIL_DECISION_PK_B64=... # guardrail's own key
    export GUARDRAIL_API_TOKEN=dev-token     # optional; gates /authorize
    python examples/run_service.py
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_payment_mandate import MandateIssuer, SqliteStore

from algovoi_spend_guardrail import Policy, SpendGuardrail, bearer_token_auth, create_app, signing


def _kp(sk_env: str, pk_env: str, label: str):
    sk, pk = os.environ.get(sk_env), os.environ.get(pk_env)
    if sk and pk:
        return base64.b64decode(pk), base64.b64decode(sk)
    print(f"No {pk_env}/{sk_env} set — generating an ephemeral {label} key (dev only).")
    return signing.generate_keypair()


def main() -> None:
    ppk_b64 = os.environ.get("GUARDRAIL_PASSPORT_PK_B64")
    passport_pk = base64.b64decode(ppk_b64) if ppk_b64 else _kp("_", "_", "passport")[0]

    mpk, msk = _kp("GUARDRAIL_MANDATE_SK_B64", "GUARDRAIL_MANDATE_PK_B64", "mandate authority")
    gpk, gsk = _kp("GUARDRAIL_DECISION_SK_B64", "GUARDRAIL_DECISION_PK_B64", "decision")

    mandate_issuer = MandateIssuer(secret_key=msk, public_key=mpk,
                                   store=SqliteStore(os.environ.get("GUARDRAIL_MANDATE_DB", "mandates.db")))
    guardrail = SpendGuardrail(
        passport_public_key=passport_pk, mandate_issuer=mandate_issuer,
        decision_secret_key=gsk, decision_public_key=gpk,
        policy=Policy(max_amount_per_tx=int(os.environ.get("GUARDRAIL_MAX_PER_TX", "25000000"))),
        guardrail_did=os.environ.get("GUARDRAIL_DID", "did:web:guardrail.example.com"))

    app = create_app(guardrail, decision_public_key=gpk,
                     auth_dependency=bearer_token_auth(os.environ.get("GUARDRAIL_API_TOKEN")))
    uvicorn.run(app, host=os.environ.get("GUARDRAIL_HOST", "127.0.0.1"),
                port=int(os.environ.get("GUARDRAIL_PORT", "8085")))


if __name__ == "__main__":
    main()
