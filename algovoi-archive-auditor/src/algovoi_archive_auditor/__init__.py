"""
algovoi-archive-auditor — reporting & auditing for the AlgoVoi Verifiable Archive.

Runs **read-only** over the same storage backend (local or S3) and produces:
- **signed audit reports** (Falcon-1024) — the chain verified, summarised, attestable;
- **continuous integrity attestations** — chained "still intact as of T" proofs;
- **retention / compliance reports** — records over/within a retention policy;
- **records inventory**; and
- portable **evidence packs** (entries + a signed manifest + the archive public key).

It owns the cryptographic-audit part and **exports** to existing tools — SIEM (JSON-lines / syslog /
CEF), observability (Prometheus → Grafana), and GRC/BI (CSV) — instead of reinventing dashboards.

Usage::

    from algovoi_doc_archive import signing
    from algovoi_doc_archive_s3 import S3Backend          # or LocalFsBackend
    from algovoi_archive_auditor import Auditor, RetentionPolicy, create_app

    rpk, rsk = signing.generate_keypair()                 # the auditor's own attestation key
    auditor = Auditor(archive_public_key=archive_pk, storage=backend,
                      report_secret_key=rsk, report_public_key=rpk,
                      retention_policy=RetentionPolicy(default_days=2557))   # ~7 years
    report = await auditor.audit_report()                 # signed, offline-verifiable
    app = create_app(auditor)                             # serves /v1/audit/* + /metrics

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_doc_archive import bearer_token_auth, signing

from algovoi_archive_auditor import exporters
from algovoi_archive_auditor.app import create_app
from algovoi_archive_auditor.auditor import Auditor
from algovoi_archive_auditor.models import AttestRequest, EvidencePackRequest, RetentionPolicyIn
from algovoi_archive_auditor.retention import RetentionPolicy

__version__ = "0.1.1"

__all__ = [
    "Auditor",
    "RetentionPolicy",
    "create_app",
    "exporters",
    "bearer_token_auth",
    "signing",
    "RetentionPolicyIn",
    "AttestRequest",
    "EvidencePackRequest",
    "__version__",
]
