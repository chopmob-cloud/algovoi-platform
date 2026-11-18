"""
algovoi-doc-archive — Verifiable Archive: tamper-evident, post-quantum document archiving (standalone).

Every document is content-addressed, **encrypted at rest** (ML-KEM-1024 + AES-256-GCM, or symmetric
AES-256-GCM — the same method whatever the backend), and recorded as a **Falcon-1024-signed** entry
in an append-only, hash-linked chain that anyone can verify offline. This package ships the engine
plus a **local filesystem** backend; the S3 / S3-compatible backend is ``algovoi-doc-archive-s3``.

Embed::

    from algovoi_doc_archive import Archive, LocalFsBackend, HybridPqcEncryptor, signing
    from algovoi_doc_archive.encryption import generate_mlkem_keypair

    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    arc = Archive(secret_key=sk, public_key=pk, storage=LocalFsBackend("./archive"),
                  encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    e = await arc.notarize(data=b"...contract bytes...", title="MSA v3", content_type="application/pdf")
    assert (await arc.verify_chain()).valid
    doc = await arc.retrieve(doc_hash=e["doc_hash"])      # decrypts + checks integrity

Run as a service::

    from algovoi_doc_archive import create_app, Archive, LocalFsBackend, bearer_token_auth
    app = create_app(Archive(secret_key=sk, public_key=pk, storage=LocalFsBackend("./archive"),
                             encryptor=enc), public_key=pk, auth_dependency=bearer_token_auth("tok"))
    # uvicorn module:app

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_doc_archive import encryption, signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.backend import LocalFsBackend, StorageBackend
from algovoi_doc_archive.encryption import (
    AesGcmEncryptor,
    Encryptor,
    HybridPqcEncryptor,
    generate_mlkem_keypair,
)
from algovoi_doc_archive.models import (
    NotarizeRequest,
    NotarizeResponse,
    VerifyChainResult,
    VerifyEntryRequest,
    VerifyEntryResult,
)
from algovoi_doc_archive.verifier import verify_chain, verify_entry
from algovoi_doc_archive import recovery
from algovoi_doc_archive.recovery import (
    RecoveryError,
    algovoi_share_mnemonic,
    recover_from_shares,
    restore_encryptor,
    split_recovery,
    verify_envelope,
)

__version__ = "0.1.1"


# The web layer (FastAPI) is an optional, lazily-imported surface: ``create_app`` and
# ``bearer_token_auth`` pull FastAPI only when actually accessed, so embedding the engine as a
# library (notarize / verify / recovery) never requires the web framework. PEP 562 module getattr.
def __getattr__(name: str):
    if name == "create_app":
        from algovoi_doc_archive.app import create_app
        return create_app
    if name == "bearer_token_auth":
        from algovoi_doc_archive.auth import bearer_token_auth
        return bearer_token_auth
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Archive",
    "verify_entry",
    "verify_chain",
    "StorageBackend",
    "LocalFsBackend",
    "Encryptor",
    "AesGcmEncryptor",
    "HybridPqcEncryptor",
    "generate_mlkem_keypair",
    "create_app",
    "bearer_token_auth",
    "signing",
    "encryption",
    "recovery",
    "RecoveryError",
    "split_recovery",
    "recover_from_shares",
    "algovoi_share_mnemonic",
    "verify_envelope",
    "restore_encryptor",
    "NotarizeRequest",
    "NotarizeResponse",
    "VerifyEntryRequest",
    "VerifyEntryResult",
    "VerifyChainResult",
    "__version__",
]
