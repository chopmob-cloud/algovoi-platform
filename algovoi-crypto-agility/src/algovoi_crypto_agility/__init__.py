"""
algovoi-crypto-agility — migrate a signing + encryption estate classical -> post-quantum WITH PROVABLE
CONTINUITY.

Classify your keys against the post-quantum transition, hybrid-sign during the transition window, and
re-attest legacy-signed artifacts forward under **Falcon-1024** so past evidence stays trustable after a
quantum-vulnerable key is retired. Re-wrap encrypted-at-rest data to **ML-KEM-1024**. Every migration
emits a signed, content-addressed attestation that binds into the Substrate 2 chain and verifies offline.

Embed::

    from algovoi_crypto_agility import CryptoAgility, classify, verify_legacy_ed25519, verify_migration_attestation, signing

    pk, sk = signing.generate_keypair()                       # the NEW post-quantum authority key
    ca = CryptoAgility(secret_key=sk, public_key=pk, authority_did="did:web:acme")

    classify("Ed25519").quantum_vulnerable        # True
    classify("ML-KEM-1024").quantum_vulnerable    # False

    # verify a legacy Ed25519 signature, then re-attest the artifact forward under PQC:
    ok = verify_legacy_ed25519(message=b"...", signature=legacy_sig, public_key=legacy_pk)
    out = ca.migrate_signature(content_hash="sha256:...", legacy_alg="Ed25519",
                               legacy_kid="old-1", legacy_signature_verified=ok)
    assert verify_migration_attestation(out["attestation_envelope"], pk).verified

Commercial product -- AlgoVoi Commercial Licence v1.0. Included free for every Substrate 2 customer.
"""
from __future__ import annotations

from algovoi_crypto_agility import licensing, signing
from algovoi_crypto_agility.agility import (
    CryptoAgility,
    CryptoAgilityError,
    classify,
    verify_legacy_ed25519,
)
from algovoi_crypto_agility.encryption import HybridPqcEncryptor, generate_mlkem_keypair
from algovoi_crypto_agility.models import (
    Classification,
    InventorySummary,
    KeyRecord,
    VerifyResult,
)
from algovoi_crypto_agility.verifier import (
    verify_hybrid_envelope,
    verify_migration_attestation,
)

__version__ = "0.1.1"

__all__ = [
    "CryptoAgility",
    "CryptoAgilityError",
    "classify",
    "verify_legacy_ed25519",
    "verify_migration_attestation",
    "verify_hybrid_envelope",
    "Classification",
    "KeyRecord",
    "InventorySummary",
    "VerifyResult",
    "generate_mlkem_keypair",
    "HybridPqcEncryptor",
    "signing",
    "licensing",
    "__version__",
]
