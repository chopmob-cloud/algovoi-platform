"""
Recovery Vault appliance — local HTTP API over the encrypted key repository.

Designed to run as a sealed, client-deployed appliance bound to loopback (or behind the client's own
mTLS). Every call is bearer-authenticated. Secrets (shares, exported keys) cross this API only on the
client's own host.

Environment:
  VAULT_PATH            path to the vault file (created on first start if absent)
  VAULT_UNLOCK_SECRET   secret used to derive the at-rest key (from KMS/TPM/secret manager)
  VAULT_API_TOKEN       bearer token required on every /v1 call
  VAULT_BIND            bind address (default 127.0.0.1)
  VAULT_PORT            port (default 8077)
"""
from __future__ import annotations

import hmac
import os

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from algovoi_recovery_vault.licensing import require_license
from algovoi_recovery_vault.vault import Vault, VaultError


def _env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"{name} is required")
    return val


def _open_vault() -> Vault:
    require_license()  # fail-closed: Recovery Vault needs an active AlgoVoi suite licence to operate
    path = _env("VAULT_PATH")
    secret = _env("VAULT_UNLOCK_SECRET").encode("utf-8")
    if not os.path.exists(path):
        return Vault.create(path, secret)
    return Vault.open(path, secret)


async def _auth(request: Request) -> None:
    expected = _env("VAULT_API_TOKEN")
    header = request.headers.get("authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


class GenerateArchiveBody(BaseModel):
    name: str
    auto_split: bool = True        # default policy: emit recovery shares on archive creation
    threshold_k: int = 2
    total_n: int = 3


class SplitBody(BaseModel):
    threshold_k: int
    total_n: int
    include_algovoi_support: bool | None = None


class RecoverBody(BaseModel):
    shares: list[str]


class AccessBody(BaseModel):
    enabled: bool


class KeyCreateBody(BaseModel):
    name: str
    kind: str = "signing-falcon"      # "signing-falcon" -> generate; else import via secret_b64
    secret_b64: str | None = None     # provide to import an existing key
    public_b64: str | None = None
    auto_split: bool = True
    threshold_k: int = 2
    total_n: int = 3


def create_app() -> FastAPI:
    require_license()  # fail-closed at startup: no active suite licence -> the service refuses to boot
    app = FastAPI(title="AlgoVoi Recovery Vault", version="0.1.2")

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    @app.get("/v1/status", dependencies=[Depends(_auth)])
    async def status() -> dict:
        return _open_vault().status()

    @app.post("/v1/archives", dependencies=[Depends(_auth)])
    async def generate_archive(body: GenerateArchiveBody) -> dict:
        try:
            return _open_vault().generate_archive(
                body.name, auto_split=body.auto_split,
                threshold_k=body.threshold_k, total_n=body.total_n,
            )
        except VaultError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.post("/v1/archives/{name}/split", dependencies=[Depends(_auth)])
    async def split(name: str, body: SplitBody) -> dict:
        try:
            env, shares = _open_vault().split(
                name, threshold_k=body.threshold_k, total_n=body.total_n,
                include_algovoi_support=body.include_algovoi_support,
            )
        except VaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"envelope": env, "shares": shares}

    @app.post("/v1/archives/{name}/resplit", dependencies=[Depends(_auth)])
    async def resplit(name: str, body: SplitBody) -> dict:
        try:
            env, shares = _open_vault().resplit(
                name, threshold_k=body.threshold_k, total_n=body.total_n,
                include_algovoi_support=body.include_algovoi_support,
            )
        except VaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"envelope": env, "shares": shares}

    @app.post("/v1/archives/{name}/recover", dependencies=[Depends(_auth)])
    async def recover(name: str, body: RecoverBody) -> dict:
        try:
            return _open_vault().recover(name, shares=body.shares)
        except VaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:  # engine RecoveryError -> 400
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/v1/archives/{name}/envelope", dependencies=[Depends(_auth)])
    async def envelope(name: str) -> dict:
        env = _open_vault().get_envelope(name)
        if env is None:
            raise HTTPException(status_code=404, detail="no envelope for this archive")
        return env

    @app.get("/v1/archives/{name}/secret", dependencies=[Depends(_auth)])
    async def secret(name: str) -> dict:
        """Export the stored master secret to feed the Archive SDK (loopback + bearer only)."""
        from algovoi_doc_archive import signing
        try:
            v = _open_vault()
            return {
                "name": name,
                "archive_sk_b64": signing.b64u_encode(v.export_archive_secret(name)),
                "archive_pub_b64": v._record(name)["archive_pub_b64"],
            }
        except VaultError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.post("/v1/access", dependencies=[Depends(_auth)])
    async def access(body: AccessBody) -> dict:
        v = _open_vault()
        v.set_algovoi_access(body.enabled)
        return {"algovoi_access": v.algovoi_access_enabled()}

    # --- generic protected keys (any Substrate PQC key) ----------------------
    @app.post("/v1/keys", dependencies=[Depends(_auth)])
    async def create_key(body: KeyCreateBody) -> dict:
        from algovoi_doc_archive import signing
        v = _open_vault()
        try:
            if body.secret_b64:                       # import an existing key
                v.import_key(body.name, secret=signing.b64u_decode(body.secret_b64),
                             kind=(body.kind or "generic"), public_b64=body.public_b64)
                out = {"name": body.name, "kind": body.kind or "generic"}
                if body.auto_split:
                    env, shares = v.split_key(body.name, threshold_k=body.threshold_k, total_n=body.total_n)
                    out["envelope"], out["shares"] = env, shares
                return out
            return v.generate_signing_key(body.name, auto_split=body.auto_split,
                                          threshold_k=body.threshold_k, total_n=body.total_n)
        except VaultError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.post("/v1/keys/{name}/split", dependencies=[Depends(_auth)])
    async def split_key(name: str, body: SplitBody) -> dict:
        try:
            env, shares = _open_vault().split_key(name, threshold_k=body.threshold_k, total_n=body.total_n,
                                                  include_algovoi_support=body.include_algovoi_support)
        except VaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"envelope": env, "shares": shares}

    @app.post("/v1/keys/{name}/recover", dependencies=[Depends(_auth)])
    async def recover_key(name: str, body: RecoverBody) -> dict:
        try:
            return _open_vault().recover_key(name, shares=body.shares)
        except VaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/v1/keys/{name}/secret", dependencies=[Depends(_auth)])
    async def key_secret(name: str) -> dict:
        from algovoi_doc_archive import signing
        try:
            v = _open_vault()
            rec = v._key_record(name)
            return {"name": name, "kind": rec["kind"],
                    "secret_b64": signing.b64u_encode(v.export_key(name)), "public_b64": rec.get("public_b64")}
        except VaultError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    return app


def _resolve_bind_host() -> str:
    """Resolve the bind host, FAILING CLOSED on an unguarded non-loopback bind.

    SECURITY (2026-08-19): the /v1/*/secret endpoints export PLAINTEXT ML-KEM master secrets and Falcon
    signing keys. This appliance is loopback/mTLS-only by design; refuse a non-loopback bind unless the
    operator explicitly opts in (and must front it with a TLS terminator). Backstops a deployment that
    overrides VAULT_BIND (the container default is now loopback).
    """
    host = os.environ.get("VAULT_BIND", "127.0.0.1")
    if (host not in ("127.0.0.1", "localhost", "::1")
            and os.environ.get("VAULT_ALLOW_REMOTE", "").strip().lower() not in ("1", "true", "yes")):
        raise RuntimeError(
            f"refusing to bind the Recovery Vault to non-loopback {host!r} (the /v1/*/secret endpoints "
            f"export plaintext keys). Keep it on loopback behind mTLS, or set VAULT_ALLOW_REMOTE=1 to opt "
            f"in explicitly with a TLS terminator in front.")
    return host


def main() -> None:  # pragma: no cover
    import uvicorn

    # Factory launch: uvicorn builds the app by calling create_app(), which enforces the licence at
    # boot (fail-closed). Importing this module has no side effect, so it stays importable for tests
    # and tooling without a licence. The gate still fires the moment the service actually starts.
    uvicorn.run(
        "algovoi_recovery_vault.service:create_app",
        factory=True,
        host=_resolve_bind_host(),
        port=int(os.environ.get("VAULT_PORT", "8077")),
    )


if __name__ == "__main__":  # pragma: no cover
    main()
