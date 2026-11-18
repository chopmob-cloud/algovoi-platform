"""Run the Sanctions Monitor appliance as an HTTP service (console script / uvicorn target).

Ships the env-driven wiring from ``examples/run_service.py``, made production-safe:
the Falcon-1024 signing key and the ML-KEM-1024 at-rest key are **bootstrapped once
and persisted** to a 0600 key file. The ML-KEM key is what encrypts the watchlist at
rest — if it changed on each restart (an ephemeral key), the persisted watchlist would
be permanently unreadable. So we load-or-create rather than fail-closed or regenerate.

Run it::

    algovoi-sanctions-monitor-serve        # console script (pip install '...[serve]')
    # or
    uvicorn algovoi_sanctions_monitor.serve:app

Configuration (environment):
    MONITOR_DB             SQLite path (mount a volume!)      (default ./monitor.db)
    MONITOR_KEY_FILE       Falcon + ML-KEM key json          (default <db dir>/monitor-key.json,
                           bootstrapped 0600 on first run)
    MONITOR_FALCON_PK_B64 / MONITOR_FALCON_SK_B64
                           explicit Falcon-1024 keypair (overrides the key file)
    MONITOR_MLKEM_PK_B64 / MONITOR_MLKEM_SK_B64
                           explicit ML-KEM-1024 at-rest keypair (overrides the key file)
    MONITOR_API_TOKEN      bearer for the loopback API        (unset = open; set in production)
    MONITOR_SWEEP_INTERVAL_SECONDS   sweep cadence            (default 86400 = daily)
    SCREEN_URL / SCREEN_TOKEN        your screening endpoint (HTTPScreener); AllowAll if unset (dev)
    MONITOR_DID / MONITOR_HOST / MONITOR_PORT   (host/port default 0.0.0.0:8088)
"""
from __future__ import annotations

import base64
import json
import os

from algovoi_sanctions_monitor import signing
from algovoi_sanctions_monitor.encryption import generate_mlkem_keypair
from algovoi_sanctions_monitor.http_screener import HTTPScreener
from algovoi_sanctions_monitor.screener import AllowAllScreener
from algovoi_sanctions_monitor.service import MonitorService, create_app


def _db_path() -> str:
    return os.environ.get("MONITOR_DB", "./monitor.db")


def _key_file() -> str:
    if os.environ.get("MONITOR_KEY_FILE"):
        return os.environ["MONITOR_KEY_FILE"]
    return os.path.join(os.path.dirname(_db_path()) or ".", "monitor-key.json")


def _load_or_bootstrap_keys() -> tuple[bytes, bytes, bytes, bytes]:
    """Return (falcon_pk, falcon_sk, kem_pk, kem_sk). Explicit env keys win; otherwise
    load the persisted key file, or bootstrap one (0600) on first run."""
    fpk_b64, fsk_b64 = os.environ.get("MONITOR_FALCON_PK_B64"), os.environ.get("MONITOR_FALCON_SK_B64")
    kpk_b64, ksk_b64 = os.environ.get("MONITOR_MLKEM_PK_B64"), os.environ.get("MONITOR_MLKEM_SK_B64")
    if fpk_b64 and fsk_b64 and kpk_b64 and ksk_b64:
        return (base64.b64decode(fpk_b64), base64.b64decode(fsk_b64),
                base64.b64decode(kpk_b64), base64.b64decode(ksk_b64))
    path = _key_file()
    if os.path.exists(path):
        d = json.load(open(path, encoding="utf-8"))
        return (base64.b64decode(d["pk"]), base64.b64decode(d["sk"]),
                base64.b64decode(d["kem_pk"]), base64.b64decode(d["kem_sk"]))
    fpk, fsk = signing.generate_keypair()
    kpk, ksk = generate_mlkem_keypair()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"pk": base64.b64encode(fpk).decode(), "sk": base64.b64encode(fsk).decode(),
                   "kem_pk": base64.b64encode(kpk).decode(), "kem_sk": base64.b64encode(ksk).decode()}, fh)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return fpk, fsk, kpk, ksk


def _screener():
    """Choose the screener for the shipped serve target — FAIL CLOSED.

    SECURITY (2026-08-19): a sanctions monitor that silently defaults to an allow-all screener baselines
    every listed address as ALLOW and can even emit a Falcon-signed "cleared" delta for a sanctioned party.
    An allow-all screener is dev-only and requires an explicit opt-in; otherwise wire an HTTP screener via
    SCREEN_URL, or a self-contained deny/refer list, or the service refuses to start.
    """
    url = os.environ.get("SCREEN_URL")
    if url:
        return HTTPScreener(url=url, token=os.environ.get("SCREEN_TOKEN"))
    deny = {a.strip() for a in os.environ.get("SCREEN_DENY_LIST", "").split(",") if a.strip()}
    refer = {a.strip() for a in os.environ.get("SCREEN_REFER_LIST", "").split(",") if a.strip()}
    if deny or refer:
        from algovoi_sanctions_monitor.screener import DenylistScreener
        return DenylistScreener(deny=deny, refer=refer)
    if os.environ.get("MONITOR_ALLOW_INSECURE_SCREENER", "").strip().lower() in ("1", "true", "yes"):
        return AllowAllScreener()
    raise RuntimeError(
        "refusing to start the Sanctions Monitor without a screener: an allow-all screener would clear "
        "every sanctioned address. Set SCREEN_URL (+ SCREEN_TOKEN) for a real screening feed, supply "
        "SCREEN_DENY_LIST/SCREEN_REFER_LIST for a self-contained list, or MONITOR_ALLOW_INSECURE_SCREENER=1 "
        "for local dev only.")


def build_app():
    fpk, fsk, kpk, ksk = _load_or_bootstrap_keys()
    token = os.environ.get("MONITOR_API_TOKEN") or None
    host = os.environ.get("MONITOR_HOST", "127.0.0.1")
    # SECURITY (2026-08-19): the watchlist/deltas disclose sanctions verdicts and DELETE /v1/watch removes
    # monitoring — never expose them unauthenticated on a public bind.
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            "refusing to bind the Sanctions Monitor to a non-loopback address without MONITOR_API_TOKEN "
            "(the watchlist/deltas endpoints and DELETE /v1/watch would be open to anyone)")
    service = MonitorService(
        secret_key=fsk, public_key=fpk, screener=_screener(),
        mlkem_public_key=kpk, mlkem_secret_key=ksk,
        db_path=_db_path(),
        monitor_did=os.environ.get("MONITOR_DID", "did:web:monitor.algovoi.example"),
    )
    return create_app(
        service,
        api_token=token,
        sweep_interval_secs=int(os.environ.get("MONITOR_SWEEP_INTERVAL_SECONDS", "86400")),
    )


def __getattr__(name: str):
    # Lazy ``app`` so ``uvicorn algovoi_sanctions_monitor.serve:app`` works while merely importing this
    # module (tests/tooling) does NOT eagerly build/boot the service (or crash on the fail-closed guards).
    if name == "app":
        return build_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def main() -> None:
    """Console entry point — serve the Sanctions Monitor (``algovoi-sanctions-monitor-serve``)."""
    import uvicorn
    application = build_app()
    uvicorn.run(application, host=os.environ.get("MONITOR_HOST", "127.0.0.1"),
                port=int(os.environ.get("MONITOR_PORT", "8088")))


if __name__ == "__main__":
    main()
