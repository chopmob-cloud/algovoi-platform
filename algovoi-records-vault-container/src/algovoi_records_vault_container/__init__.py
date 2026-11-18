"""algovoi-records-vault-container — sealed, portable, post-quantum encrypted records containers (.acv).

Create a single movable, encrypted container from a set of Records Vault documents (sealed with
ML-KEM-1024 to a named recipient, AES-256-GCM content, Falcon-1024-signed header), open it offline with
the bundled ``acv_unseal.py`` extractor, and create/revoke containers from the Compliance Command Center
via an offline, Falcon-signed revocation list.
"""
from algovoi_records_vault_container.container import (
    MAGIC,
    open_container,
    read_header,
    recover_container,
    recover_via_escrow,
    safe_name,
    seal_container,
    seal_from_archive,
)
from algovoi_records_vault_container.crl import build_crl, is_revoked, verify_crl
from algovoi_records_vault_container.registry import ContainerRegistry

__version__ = "0.2.4"

__all__ = [
    "MAGIC",
    "seal_container",
    "seal_from_archive",
    "open_container",
    "recover_container",
    "recover_via_escrow",
    "read_header",
    "safe_name",
    "build_crl",
    "verify_crl",
    "is_revoked",
    "ContainerRegistry",
    "__version__",
]
