"""Run the Compliance Gate as an HTTP service (console script / uvicorn target).

Ships the env-driven wiring from ``examples/run_service.py``, made production-safe:
the Falcon-1024 signing key is **bootstrapped once and persisted** to a 0600 key
file so decision receipts stay verifiable across restarts (an ephemeral key would
change the gate's signing identity on every boot). When the CCC_HUB_* env vars are
set, the gate self-registers with the Compliance Command Center on startup so it
shows up in the console's live service-health panel.

Run it::

    algovoi-compliance-gate-serve          # console script (pip install '...[serve]')
    # or
    uvicorn algovoi_compliance_gate.serve:app

Configuration (environment):
    GATE_KEY_FILE          Falcon signing key json           (default ./compliance-gate-key.json,
                           bootstrapped 0600 on first run)
    GATE_FALCON_PK_B64 / GATE_FALCON_SK_B64
                           explicit Falcon-1024 keypair (overrides the key file)
    GATE_API_TOKEN         bearer token for /screen          (unset = open on loopback only;
                           REQUIRED for a non-loopback bind)
    GATE_DID               gate DID stamped into verdicts    (default did:web:compliance.example.com)
    GATE_HOST/PORT         bind for the console script        (default 127.0.0.1:8086, loopback)
    GATE_ALLOW_ALL_SCREENER  set to 1 to run the DEV allow-all screener (never in production)
    GATE_DENY_LIST / GATE_REFER_LIST  comma-separated addresses for a self-contained list screener
    CCC_HUB_URL / CCC_HUB_TOKEN / CCC_HUB_NAME / CCC_HUB_SELF_URL
                           set these and the gate self-registers with the Command Center

SECURITY: this target FAILS CLOSED. It refuses to start without a screener (an allow-all screener would
sign a compliant ALLOW verdict for sanctioned addresses — set GATE_ALLOW_ALL_SCREENER=1 only for dev, or
provide GATE_DENY_LIST/GATE_REFER_LIST, or wire your own ``Screener`` over your sanctions/PEP provider in a
custom entrypoint) and refuses a non-loopback bind without GATE_API_TOKEN.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os

from algovoi_compliance_gate import (
    AllowAllScreener,
    ComplianceGate,
    bearer_token_auth,
    create_app,
    hub_client,
    signing,
)


def _key_file() -> str:
    return os.environ.get("GATE_KEY_FILE", "./compliance-gate-key.json")


def _load_or_bootstrap_keys() -> tuple[bytes, bytes]:
    """Return (pk, sk). Explicit env keys win; otherwise load the persisted key
    file, or bootstrap one (0600) on first run."""
    pk_b64, sk_b64 = os.environ.get("GATE_FALCON_PK_B64"), os.environ.get("GATE_FALCON_SK_B64")
    if pk_b64 and sk_b64:
        return base64.b64decode(pk_b64), base64.b64decode(sk_b64)
    path = _key_file()
    if os.path.exists(path):
        d = json.load(open(path, encoding="utf-8"))
        return base64.b64decode(d["pk"]), base64.b64decode(d["sk"])
    pk, sk = signing.generate_keypair()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"pk": base64.b64encode(pk).decode(), "sk": base64.b64encode(sk).decode()}, fh)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return pk, sk


def _build_screener():
    """Choose the screener for the shipped serve target — FAIL CLOSED.

    SECURITY (2026-08-19): the console script previously hard-wired ``AllowAllScreener``, so a shipped
    Compliance Gate signed a compliant ALLOW verdict for EVERY address, including sanctioned ones. An
    allow-all screener is dev-only and now requires an explicit opt-in; a self-contained deployment can
    instead supply deny/refer lists via env. With neither, the service REFUSES to start rather than
    silently screening nothing.
    """
    if os.environ.get("GATE_ALLOW_ALL_SCREENER", "").strip().lower() in ("1", "true", "yes"):
        return AllowAllScreener()
    deny = {a.strip() for a in os.environ.get("GATE_DENY_LIST", "").split(",") if a.strip()}
    refer = {a.strip() for a in os.environ.get("GATE_REFER_LIST", "").split(",") if a.strip()}
    if deny or refer:
        from algovoi_compliance_gate.screener import DenylistScreener
        return DenylistScreener(deny=deny, refer=refer)
    raise RuntimeError(
        "refusing to start the Compliance Gate without a screener: an allow-all screener would sign "
        "compliant ALLOW verdicts for sanctioned addresses. Set GATE_ALLOW_ALL_SCREENER=1 for local dev, "
        "supply GATE_DENY_LIST/GATE_REFER_LIST for a self-contained list screener, or wire your own "
        "Screener over your sanctions/PEP provider in a custom entrypoint.")


def build_app():
    pk, sk = _load_or_bootstrap_keys()
    gate = ComplianceGate(secret_key=sk, public_key=pk, screener=_build_screener(),
                          gate_did=os.environ.get("GATE_DID", "did:web:compliance.example.com"))
    token = os.environ.get("GATE_API_TOKEN") or None
    host = os.environ.get("GATE_HOST", "127.0.0.1")
    # SECURITY (2026-08-19): never expose the screening endpoint unauthenticated on a public bind.
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            "refusing to bind the Compliance Gate to a non-loopback address without GATE_API_TOKEN "
            "(the /screen endpoint would be open to anyone)")
    app = create_app(gate, public_key=pk,
                     auth_dependency=bearer_token_auth(token),
                     title="AlgoVoi Compliance Gate")

    @app.on_event("startup")
    async def _register_with_command_center() -> None:
        # best-effort, off the event loop (urllib is blocking) — never blocks or fails boot
        await asyncio.to_thread(hub_client.register_from_env)

    return app


def __getattr__(name: str):
    # Lazy ``app`` so ``uvicorn algovoi_compliance_gate.serve:app`` still works, while merely importing
    # this module (e.g. for tests or tooling) does NOT eagerly build/boot the gate.
    if name == "app":
        return build_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def main() -> None:
    """Console entry point — serve the Compliance Gate (``algovoi-compliance-gate-serve``)."""
    import uvicorn
    application = build_app()
    uvicorn.run(application, host=os.environ.get("GATE_HOST", "127.0.0.1"),
                port=int(os.environ.get("GATE_PORT", "8086")))


if __name__ == "__main__":
    main()
