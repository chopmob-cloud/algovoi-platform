"""AlgoVoi Mandate Auditor Suite.

Build and verify self-contained retention-chain audit reports for payment mandate charge histories.
Any party holding an audit export can verify the chain offline with no AlgoVoi infrastructure.
"""
from __future__ import annotations

from algovoi_mandate_auditor.audit import (
    AuditRecord,
    AuditReport,
    build_audit_report,
    verify_audit_report,
)

__all__ = [
    "AuditRecord",
    "AuditReport",
    "build_audit_report",
    "verify_audit_report",
]
__version__ = "0.1.1"
