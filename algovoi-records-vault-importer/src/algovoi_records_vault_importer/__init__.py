"""algovoi-records-vault-importer - switchable volume importer add-on for AlgoVoi Records Vault.

Import existing document estates into the PQC Verifiable Archive, choosing the signing strategy per run:

  * ``strategy="falcon"`` - one Falcon-1024 signature **per document** (maximum granularity: each record
    is its own signed, independently revocable archive entry).
  * ``strategy="merkle"`` - one Falcon-1024 signature **per batch** (volume: throughput bounded by hashing
    and IO, not signing; ~300x faster), with an offline inclusion proof per document.

Both support bridge (hash-only) and store (encrypt + store) modes, idempotent/resumable, with parallel
filesystem hashing. Commercial add-on to Records Vault; runtime-licensed, fail-closed.
"""
__version__ = "0.3.1"

from algovoi_records_vault_importer.importer import (
    STRATEGIES,
    ImportResult,
    compact_proof,
    import_records,
    import_records_fs,
    verify_document_in_batch,
)
from algovoi_records_vault_importer import merkle
from algovoi_records_vault_importer.watcher import watch

__all__ = [
    "import_records",
    "import_records_fs",
    "watch",
    "ImportResult",
    "STRATEGIES",
    "verify_document_in_batch",
    "compact_proof",
    "merkle",
    "__version__",
]
