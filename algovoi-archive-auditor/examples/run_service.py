"""
Run the Archive Auditor over an existing archive (local filesystem backend).

    pip install -e ".[serve]"
    export ARCHIVE_PUBLIC_KEY_B64=...        # the archive's Falcon PUBLIC key (verify only)
    export AUDITOR_FALCON_SK_B64=... AUDITOR_FALCON_PK_B64=...   # the auditor's own signing key
    export ARCHIVE_ROOT=./archive-data       # the SAME directory the archive writes to
    export AUDITOR_API_TOKEN=dev-token       # optional; gates attest / evidence-pack
    python examples/run_service.py
"""
from __future__ import annotations

import base64
import os

import uvicorn

from algovoi_doc_archive import LocalFsBackend, signing

from algovoi_archive_auditor import Auditor, RetentionPolicy, bearer_token_auth, create_app


def main() -> None:
    apk_b64 = os.environ.get("ARCHIVE_PUBLIC_KEY_B64")
    if not apk_b64:
        raise SystemExit("set ARCHIVE_PUBLIC_KEY_B64 to the archive's Falcon public key")
    archive_pk = base64.b64decode(apk_b64)

    rsk_b64, rpk_b64 = os.environ.get("AUDITOR_FALCON_SK_B64"), os.environ.get("AUDITOR_FALCON_PK_B64")
    if rsk_b64 and rpk_b64:
        rpk, rsk = base64.b64decode(rpk_b64), base64.b64decode(rsk_b64)
    else:
        print("No AUDITOR_FALCON_*_B64 set — generating an ephemeral auditor key (dev only).")
        rpk, rsk = signing.generate_keypair()
        print("AUDITOR_FALCON_PK_B64=", signing.public_key_b64(rpk))

    days = int(os.environ.get("RETENTION_DEFAULT_DAYS", "2557"))  # ~7 years
    auditor = Auditor(
        archive_public_key=archive_pk,
        storage=LocalFsBackend(os.environ.get("ARCHIVE_ROOT", "./archive-data")),
        report_secret_key=rsk, report_public_key=rpk,
        retention_policy=RetentionPolicy(default_days=days),
        auditor_did=os.environ.get("AUDITOR_DID", "did:web:auditor.example.com"))

    app = create_app(auditor, auth_dependency=bearer_token_auth(os.environ.get("AUDITOR_API_TOKEN")))
    uvicorn.run(app, host=os.environ.get("AUDITOR_HOST", "127.0.0.1"), port=int(os.environ.get("AUDITOR_PORT", "8084")))


if __name__ == "__main__":
    main()
