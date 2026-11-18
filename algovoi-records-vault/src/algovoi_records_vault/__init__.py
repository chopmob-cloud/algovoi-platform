"""algovoi-records-vault — regulated-records preservation on the PQC Verifiable Archive.

A commercial layer over ``algovoi-doc-archive``: bring existing records (filesystem, object store,
database, legacy system) into a tamper-evident, post-quantum, offline-verifiable archive, with a
signed migration manifest reconciling the source against the chain. No cryptography is reimplemented;
all signing / ML-KEM / JCS / chain logic is reused from the base engine.

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_records_vault.sources import S3Source, SqliteBlobSource
from algovoi_records_vault.vault import (
    ChainIntegrityError,
    MalformedEntryError,
    RecordsVault,
    _VaultStream,
    ensure_chain_valid,
    verify_stream,
)
from algovoi_records_vault.principals import Principal
from algovoi_records_vault.timestamp import (
    NoopTsaClient,
    RequestTsaClient,
    Timestamper,
    TimestampError,
    TsaClient,
    build_timestamp_request,
    is_trusted_timestamp,
    parse_timestamp_response,
    verify_timestamp_binding,
)
from algovoi_records_vault.access_log import AccessLog
from algovoi_records_vault.legal_hold import HoldActive, LegalHoldRegistry, RetentionPolicy
from algovoi_records_vault.gdpr_bridge import LegalHoldBridge, bridge_from_env
from algovoi_records_vault.keyring import (
    Keyring, make_rotation_proof, verify_rotation_proof, verify_key_chain,
)
from algovoi_records_vault.consent import ConsentLedger, terms_hash, verify_consent
from algovoi_records_vault.custody import (
    CustodyLog, make_custody_attestation, verify_custody_attestation,
)
from algovoi_records_vault.editions import EDITIONS, Edition, edition, HEALTH, LEGAL
from algovoi_records_vault.acl import ACLRegistry
from algovoi_records_vault.redaction import (
    RedactionLedger, redact, doc_hash, verify_derivation,
    seal_fields, unseal_field, crypto_shred,
)
from algovoi_records_vault.migrate import (
    FsSource,
    MigrationResult,
    Source,
    SourceRecord,
    detect_drift,
    migrate,
    reconcile,
    sign_manifest,
    verify_manifest,
)

__all__ = [
    "RecordsVault",
    "_VaultStream",
    "verify_stream",
    "ensure_chain_valid",
    "ChainIntegrityError",
    "MalformedEntryError",
    "Principal",
    # F1 timestamping
    "Timestamper",
    "TsaClient",
    "NoopTsaClient",
    "RequestTsaClient",
    "TimestampError",
    "build_timestamp_request",
    "parse_timestamp_response",
    "verify_timestamp_binding",
    "is_trusted_timestamp",
    # F3 access log
    "AccessLog",
    # F2 legal hold
    "LegalHoldRegistry",
    "RetentionPolicy",
    "HoldActive",
    "LegalHoldBridge",
    "bridge_from_env",
    # F7 key archival + rotation proof
    "Keyring",
    "make_rotation_proof",
    "verify_rotation_proof",
    "verify_key_chain",
    # F5 consent receipts
    "ConsentLedger",
    "terms_hash",
    "verify_consent",
    # F6 custody manifest
    "CustodyLog",
    "make_custody_attestation",
    "verify_custody_attestation",
    # editions
    "Edition",
    "EDITIONS",
    "edition",
    "HEALTH",
    "LEGAL",
    # F8 fine-grained ACL
    "ACLRegistry",
    # F4 redaction + crypto-shred
    "RedactionLedger",
    "redact",
    "doc_hash",
    "verify_derivation",
    "seal_fields",
    "unseal_field",
    "crypto_shred",
    # migration on-ramp
    "SqliteBlobSource",
    "S3Source",
    "FsSource",
    "Source",
    "SourceRecord",
    "MigrationResult",
    "migrate",
    "reconcile",
    "sign_manifest",
    "verify_manifest",
    "detect_drift",
]

__version__ = "0.5.1"
