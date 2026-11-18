"""Run the Verifiable Archive as an HTTP service (console script / uvicorn target).

Ships the env-driven wiring that ``examples/run_service.py`` demonstrated, but
production-safe: signing and ML-KEM at-rest keys are **bootstrapped once and
persisted** to a 0600 key file, so they survive restarts. An ephemeral key would
change the archive's signing identity on every boot and make previously-encrypted
documents unreadable, so we never silently regenerate — we load-or-create.

Run it::

    algovoi-doc-archive-serve              # console script (pip install '...[serve]')
    # or
    uvicorn algovoi_doc_archive.serve:app     # ASGI import; REQUIRES ARCHIVE_API_TOKEN

Configuration (environment):
    ARCHIVE_ROOT           storage directory                 (default ./archive-data)
    ARCHIVE_KEY_FILE       Falcon + ML-KEM key json          (default <root>/archive-key.json,
                           bootstrapped 0600 on first run)
    ARCHIVE_FALCON_PK_B64 / ARCHIVE_FALCON_SK_B64
                           explicit Falcon-1024 signing keypair (overrides the key file)
    ARCHIVE_KEM_PK_B64 / ARCHIVE_KEM_SK_B64
                           explicit ML-KEM-1024 at-rest keypair (overrides the key file)
    ARCHIVE_API_TOKEN      bearer token for write/retrieve   (unset = open on loopback; REQUIRED for public bind)
    ARCHIVE_ISSUER_DID     issuer DID stamped into receipts  (default did:web:issuer.example.com)
    ARCHIVE_HOST/PORT      bind for the console script        (default 127.0.0.1:8083, loopback)
"""
from __future__ import annotations

import base64
import json
import os
import secrets

from algovoi_doc_archive import (
    Archive,
    HybridPqcEncryptor,
    LocalFsBackend,
    signing,
)
from algovoi_doc_archive.encryption import generate_mlkem_keypair

# ``create_app`` and ``bearer_token_auth`` pull in FastAPI, which lives in the optional ``serve``
# extra rather than the base install, because the engine is usable as a pure library. Importing them
# at module scope made this module unimportable without the extra — and because the console script
# is declared unconditionally in pyproject.toml, a base install produced a working-looking
# ``algovoi-doc-archive-serve`` command that died on a raw ModuleNotFoundError with no hint about
# what to install. They are imported lazily in build_app(), and main() turns the ImportError into an
# instruction.
_SERVE_EXTRA_HINT = (
    "the HTTP service layer needs the 'serve' extra: pip install 'algovoi-doc-archive[serve]'")


def _service_layer():
    """Return (create_app, bearer_token_auth), or raise with an actionable message."""
    try:
        from algovoi_doc_archive import bearer_token_auth, create_app
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised by the base-install test
        missing = exc.name or "a dependency"
        raise ModuleNotFoundError(
            f"cannot start the archive service: {missing} is not installed. {_SERVE_EXTRA_HINT}"
        ) from exc
    return create_app, bearer_token_auth



def _archive_root() -> str:
    return os.environ.get("ARCHIVE_ROOT", "./archive-data")


def _key_file() -> str:
    return os.environ.get("ARCHIVE_KEY_FILE") or os.path.join(_archive_root(), "archive-key.json")


def _load_or_bootstrap_keys() -> tuple[bytes, bytes, bytes, bytes]:
    """Return (falcon_pk, falcon_sk, kem_pk, kem_sk). Explicit env keys win; otherwise
    load the persisted key file, or bootstrap one (0600) on first run."""
    fpk_b64, fsk_b64 = os.environ.get("ARCHIVE_FALCON_PK_B64"), os.environ.get("ARCHIVE_FALCON_SK_B64")
    kpk_b64, ksk_b64 = os.environ.get("ARCHIVE_KEM_PK_B64"), os.environ.get("ARCHIVE_KEM_SK_B64")
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
    # SECURITY (2026-11-14): the secret key material must never exist on disk with looser permissions,
    # not even briefly. Writing then chmod'ing leaves a TOCTOU window in which the file is created with
    # the process umask (typically 0644) and is world-readable. os.open with mode 0o600 and O_EXCL
    # creates it at the final permission atomically. The temp name carries the pid so two processes
    # bootstrapping the same root cannot collide on it, and a FileExistsError is retried with a fresh
    # name rather than deleting a file another process may own.
    payload = json.dumps({"pk": base64.b64encode(fpk).decode(), "sk": base64.b64encode(fsk).decode(),
                          "kem_pk": base64.b64encode(kpk).decode(),
                          "kem_sk": base64.b64encode(ksk).decode()}).encode()
    fd: int | None = None
    tmp_path: str | None = None
    for _ in range(8):
        candidate = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            tmp_path = candidate
            break
        except FileExistsError:
            continue
    if fd is None or tmp_path is None:
        raise RuntimeError("could not create a unique temporary key file")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        os.replace(tmp_path, path)               # atomic; permissions travel with the inode
    except BaseException:
        try:
            os.unlink(tmp_path)                  # only ever our own uniquely-named temp
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)                    # belt and braces on filesystems that ignore create mode
    except OSError:
        pass
    return fpk, fsk, kpk, ksk


def build_app(host: str | None = None):
    fpk, fsk, kpk, ksk = _load_or_bootstrap_keys()
    token = os.environ.get("ARCHIVE_API_TOKEN") or None
    # SECURITY (2026-11-14): the guard must reason about the ACTUAL bind address, not just the env var.
    # `uvicorn algovoi_doc_archive.serve:app --host 0.0.0.0` never sets ARCHIVE_HOST, so a check that
    # only read the env var was bypassed by the most obvious way of exposing the service. main() passes
    # the host it is about to bind; a caller that binds some other way must pass it too, and the
    # ASGI-level default stays loopback-only.
    env_host = os.environ.get("ARCHIVE_HOST", "127.0.0.1")
    bind_host = host if host is not None else env_host
    # The /v1/archive/retrieve endpoint DECRYPTS and returns stored documents, so it must never be
    # exposed unauthenticated on a public bind.
    if bind_host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            f"refusing to expose the archive on {bind_host!r} without ARCHIVE_API_TOKEN "
            "(the retrieve endpoint decrypts and returns stored documents)")
    archive = Archive(secret_key=fsk, public_key=fpk,
                      storage=LocalFsBackend(_archive_root()),
                      encryptor=HybridPqcEncryptor(kpk, ksk),
                      issuer_did=os.environ.get("ARCHIVE_ISSUER_DID", "did:web:issuer.example.com"))
    create_app, bearer_token_auth = _service_layer()
    return create_app(archive, public_key=fpk,
                      auth_dependency=bearer_token_auth(token),
                      title="AlgoVoi Verifiable Archive")


def __getattr__(name: str):
    # Lazy ``app`` so importing this module (tests/tooling) does not eagerly build/boot or hit the guards.
    #
    # SECURITY (2026-11-14): this path CANNOT see the address an ASGI server binds. `uvicorn
    # algovoi_doc_archive.serve:app --host 0.0.0.0` sets no environment variable we can read, so a guard
    # here would only ever inspect ARCHIVE_HOST and be bypassed by the CLI flag. Rather than offer false
    # assurance, the ASGI import path REQUIRES an explicit token: with ARCHIVE_API_TOKEN set the archive
    # is authenticated wherever it ends up bound, and without it the import fails for every bind rather
    # than silently serving a decrypting endpoint. The console script (``algovoi-doc-archive-serve``) is
    # the supported entry point because it knows its bind address and enforces the loopback/token rule
    # precisely; see main().
    if name == "app":
        if not os.environ.get("ARCHIVE_API_TOKEN"):
            raise RuntimeError(
                "refusing to build the ASGI app without ARCHIVE_API_TOKEN. Importing "
                "algovoi_doc_archive.serve:app gives no control over the bind address (an ASGI server's "
                "--host is invisible here), so an unauthenticated app could be exposed publicly. Set "
                "ARCHIVE_API_TOKEN, or run the console script algovoi-doc-archive-serve, which enforces "
                "the loopback rule against the address it actually binds.")
        return build_app(host=os.environ.get("ARCHIVE_HOST"))
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def main() -> None:
    """Console entry point — serve the archive (``algovoi-doc-archive-serve``)."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"cannot start the archive service: {exc.name or 'a dependency'} is not installed. "
            f"{_SERVE_EXTRA_HINT}") from exc
    host = os.environ.get("ARCHIVE_HOST", "127.0.0.1")
    # pass the host through so the bind guard checks the address actually being bound
    uvicorn.run(build_app(host=host), host=host,
                port=int(os.environ.get("ARCHIVE_PORT", "8083")))


if __name__ == "__main__":
    main()
