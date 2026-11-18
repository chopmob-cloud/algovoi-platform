"""Run Records Vault as an HTTP service that self-registers with the Command Center.

A thin layer over the archive HTTP service: it builds ``algovoi_doc_archive.create_app``
from environment configuration and adds one thing on top — a startup hook that
self-registers this service with the Compliance Command Center (when the CCC_HUB_*
env vars are set), so the vault shows up live in the console's "Live service health"
panel. The doc-archive engine (the base) is untouched; this composes a layer on it.

Run it::

    algovoi-records-vault-serve            # console script (pip install '...[serve]')
    # or
    uvicorn algovoi_records_vault.serve:app

Configuration (environment):
    RV_ARCHIVE_DIR        storage directory                 (default ./records-vault-archive)
    RV_ARCHIVE_KEY_FILE   Falcon-1024 signing key json      (default <dir>/archive-key.json,
                          bootstrapped 0600 on first run)
    RV_ARCHIVE_TOKEN      bearer token for notarize/retrieve (unset = open; set in production)
    RV_ARCHIVE_AES_KEY_B64  optional base64 32-byte AES-256-GCM at-rest key (encrypt at rest)
    RV_SERVE_HOST/PORT    bind for the console script        (default 0.0.0.0:8000)
    CCC_HUB_URL / CCC_HUB_TOKEN / CCC_HUB_NAME / CCC_HUB_SELF_URL
                          set these and the vault self-registers with the Command Center

Production deployments that wire the archive (keys, hybrid-PQC encryption, custody)
in their own image entrypoint can keep doing so and just call
``hub_client.register_from_env()`` on boot — this module is the reference wiring.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os

from algovoi_doc_archive import Archive, AesGcmEncryptor, LocalFsBackend, bearer_token_auth, signing

from algovoi_records_vault import hub_client


def _signing_keys() -> tuple[bytes, bytes]:
    """Load the archive's Falcon-1024 keypair, or bootstrap and persist one (0600)."""
    path = os.environ.get("RV_ARCHIVE_KEY_FILE") or os.path.join(_archive_dir(), "archive-key.json")
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


def _archive_dir() -> str:
    return os.environ.get("RV_ARCHIVE_DIR", "./records-vault-archive")


def _encryptor():
    """Optional AES-256-GCM at-rest encryption when RV_ARCHIVE_AES_KEY_B64 is set."""
    b64 = os.environ.get("RV_ARCHIVE_AES_KEY_B64", "").strip()
    if not b64:
        return None
    return AesGcmEncryptor(base64.b64decode(b64))


def build_app():
    """Build the archive HTTP service and bolt on Command Center self-registration."""
    pk, sk = _signing_keys()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(_archive_dir()),
                      encryptor=_encryptor())
    app = create_app_for(archive, pk)

    @app.on_event("startup")
    async def _register_with_command_center() -> None:
        # best-effort, off the event loop (urllib is blocking) — never blocks or fails boot
        await asyncio.to_thread(hub_client.register_from_env)

    return app


def create_app_for(archive, public_key: bytes):
    from algovoi_doc_archive import create_app
    return create_app(archive, public_key=public_key,
                      auth_dependency=bearer_token_auth(os.environ.get("RV_ARCHIVE_TOKEN")),
                      title="AlgoVoi Records Vault")


app = build_app()


def main() -> None:
    """Console entry point — serve Records Vault (``algovoi-records-vault-serve``)."""
    import uvicorn
    # SECURITY (2026-08-20): default to loopback, and refuse a non-loopback (public) bind unless a bearer
    # token is configured — RV_ARCHIVE_TOKEN is "unset = open", so a 0.0.0.0 default would otherwise expose
    # the custody / notarize / retrieve API to anyone on the network.
    host = os.environ.get("RV_SERVE_HOST", "127.0.0.1")
    token = os.environ.get("RV_ARCHIVE_TOKEN") or None
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            "refusing to bind Records Vault to a non-loopback address without RV_ARCHIVE_TOKEN "
            "(the custody / notarize / retrieve endpoints would be open to anyone). Set RV_ARCHIVE_TOKEN "
            "for a public bind, or keep the default loopback host.")
    uvicorn.run(app, host=host, port=int(os.environ.get("RV_SERVE_PORT", "8000")))


if __name__ == "__main__":
    main()
