"""
Run the AlgoVoi Sanctions Monitor appliance. Env-driven.

    MONITOR_FALCON_SK_B64 / MONITOR_FALCON_PK_B64   Falcon-1024 signing keypair (delta receipts).
                                                    Ephemeral if unset (dev only).
    MONITOR_MLKEM_PK_B64 / MONITOR_MLKEM_SK_B64     ML-KEM-1024 keypair for PQC at-rest encryption of the
                                                    watchlist. REQUIRED -- fail-closed (an ephemeral key
                                                    would make the persisted watchlist unreadable on restart).
    MONITOR_DB                                       SQLite path (default /app/data/monitor.db -- mount a volume!)
    MONITOR_API_TOKEN                                bearer for the loopback API (open if unset)
    MONITOR_SWEEP_INTERVAL_SECONDS                   sweep cadence (default 86400 = daily)
    SCREEN_URL / SCREEN_TOKEN                         your screening endpoint (HTTPScreener); AllowAll if unset (dev)
    MONITOR_DID / MONITOR_HOST / MONITOR_PORT

Generate the ML-KEM keypair once:
    python -c "import base64; from algovoi_sanctions_monitor.encryption import generate_mlkem_keypair as g; pk,sk=g(); print('PK',base64.b64encode(pk).decode()); print('SK',base64.b64encode(sk).decode())"
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_sanctions_monitor import signing
from algovoi_sanctions_monitor.http_screener import HTTPScreener
from algovoi_sanctions_monitor.screener import AllowAllScreener
from algovoi_sanctions_monitor.service import MonitorService, create_app


def _falcon_keys() -> tuple[bytes, bytes]:
    sk, pk = os.environ.get("MONITOR_FALCON_SK_B64"), os.environ.get("MONITOR_FALCON_PK_B64")
    if sk and pk:
        return base64.b64decode(pk), base64.b64decode(sk)
    print("No MONITOR_FALCON_*_B64 set -- generating an ephemeral signing keypair (dev only).")
    pk_, sk_ = signing.generate_keypair()
    print("MONITOR_FALCON_PK_B64=", signing.public_key_b64(pk_))
    return pk_, sk_


def _mlkem_keys() -> tuple[bytes, bytes]:
    pk, sk = os.environ.get("MONITOR_MLKEM_PK_B64"), os.environ.get("MONITOR_MLKEM_SK_B64")
    if pk and sk:
        return base64.b64decode(pk), base64.b64decode(sk)
    raise SystemExit(
        "MONITOR_MLKEM_PK_B64 + MONITOR_MLKEM_SK_B64 are required (PQC at-rest encryption, fail-closed). "
        "Generate: python -c \"import base64; from algovoi_sanctions_monitor.encryption import "
        "generate_mlkem_keypair as g; pk,sk=g(); print(base64.b64encode(pk).decode()); "
        "print(base64.b64encode(sk).decode())\""
    )


def _screener():
    url = os.environ.get("SCREEN_URL")
    if url:
        return HTTPScreener(url=url, token=os.environ.get("SCREEN_TOKEN"))
    print("No SCREEN_URL set -- using AllowAllScreener (dev only).")
    return AllowAllScreener()


def main() -> None:
    pk, sk = _falcon_keys()
    mpk, msk = _mlkem_keys()
    service = MonitorService(
        secret_key=sk, public_key=pk, screener=_screener(),
        mlkem_public_key=mpk, mlkem_secret_key=msk,
        db_path=os.environ.get("MONITOR_DB", "/app/data/monitor.db"),
        monitor_did=os.environ.get("MONITOR_DID", "did:web:monitor.algovoi.example"),
    )
    # SECURITY (2026-08-20): this is the container entrypoint (see Dockerfile CMD). Mirror serve.py's
    # fail-closed bind guard — MONITOR_API_TOKEN is "unset = open", so a non-loopback (0.0.0.0) bind
    # without a token would serve the watchlist/deltas/DELETE endpoints to anyone. Refuse it.
    host = os.environ.get("MONITOR_HOST", "0.0.0.0")
    token = os.environ.get("MONITOR_API_TOKEN") or None
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            "refusing to bind the Sanctions Monitor to a non-loopback address without MONITOR_API_TOKEN "
            "(the watchlist/deltas endpoints and DELETE /v1/watch would be open to anyone). Set "
            "MONITOR_API_TOKEN, or bind MONITOR_HOST=127.0.0.1 behind a reverse proxy.")
    app = create_app(
        service,
        api_token=token,
        sweep_interval_secs=int(os.environ.get("MONITOR_SWEEP_INTERVAL_SECONDS", "86400")),
    )
    uvicorn.run(app, host=host, port=int(os.environ.get("MONITOR_PORT", "8088")))


if __name__ == "__main__":
    main()
