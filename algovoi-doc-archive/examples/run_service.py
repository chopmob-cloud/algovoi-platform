"""
Run the Verifiable Archive service locally (local filesystem backend).

    pip install -e ".[serve]"
    # generate keys once:
    python -c "import base64; from algovoi_doc_archive import signing; pk,sk=signing.generate_keypair(); print('ARCHIVE_FALCON_PK_B64=',base64.b64encode(pk).decode()); print('ARCHIVE_FALCON_SK_B64=',base64.b64encode(sk).decode())"
    python -c "import base64; from algovoi_doc_archive.encryption import generate_mlkem_keypair as g; pk,sk=g(); print('ARCHIVE_KEM_PK_B64=',base64.b64encode(pk).decode()); print('ARCHIVE_KEM_SK_B64=',base64.b64encode(sk).decode())"
    export ARCHIVE_FALCON_SK_B64=... ARCHIVE_FALCON_PK_B64=...
    export ARCHIVE_KEM_PK_B64=...    ARCHIVE_KEM_SK_B64=...
    export ARCHIVE_API_TOKEN=dev-token        # optional; omit to disable write auth
    python examples/run_service.py
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_doc_archive import (
    Archive,
    HybridPqcEncryptor,
    LocalFsBackend,
    bearer_token_auth,
    create_app,
    signing,
)
from algovoi_doc_archive.encryption import generate_mlkem_keypair


def _falcon() -> tuple[bytes, bytes]:
    sk, pk = os.environ.get("ARCHIVE_FALCON_SK_B64"), os.environ.get("ARCHIVE_FALCON_PK_B64")
    if sk and pk:
        return base64.b64decode(pk), base64.b64decode(sk)
    print("No ARCHIVE_FALCON_*_B64 set — generating an ephemeral signing key (dev only).")
    return signing.generate_keypair()


def _kem():
    pk, sk = os.environ.get("ARCHIVE_KEM_PK_B64"), os.environ.get("ARCHIVE_KEM_SK_B64")
    if pk and sk:
        return HybridPqcEncryptor(base64.b64decode(pk), base64.b64decode(sk))
    print("No ARCHIVE_KEM_*_B64 set — generating an ephemeral ML-KEM key (dev only).")
    kpk, ksk = generate_mlkem_keypair()
    return HybridPqcEncryptor(kpk, ksk)


def main() -> None:
    pk, sk = _falcon()
    archive = Archive(secret_key=sk, public_key=pk,
                      storage=LocalFsBackend(os.environ.get("ARCHIVE_ROOT", "./archive-data")),
                      encryptor=_kem(), issuer_did=os.environ.get("ARCHIVE_ISSUER_DID", "did:web:issuer.example.com"))
    app = create_app(archive, public_key=pk, auth_dependency=bearer_token_auth(os.environ.get("ARCHIVE_API_TOKEN")))
    uvicorn.run(app, host=os.environ.get("ARCHIVE_HOST", "127.0.0.1"), port=int(os.environ.get("ARCHIVE_PORT", "8083")))


if __name__ == "__main__":
    main()
