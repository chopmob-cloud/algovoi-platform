"""Mandate Auditor Suite — core library.

Builds and verifies self-contained retention-chain audit reports from a MandateStore.

An AuditReport is a snapshot of every authorized charge for one mandate, ordered by
chain_seq, with each record carrying its receipt_hash and chain_ref.  Any party holding
the report can verify its integrity offline by recomputing every chain_ref from local
data — no AlgoVoi infrastructure, registry lookup, or network access required.

Regulatory coverage: MiCA Art. 68(9), DORA Art. 17, AMLR Art. 77.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from algovoi_payment_mandate.issuer import _receipt_hash as _mandate_receipt_hash
from algovoi_payment_mandate.store import MandateStore
from algovoi_retention_chain import verify_chain_link, verify_chain_sequence

from algovoi_mandate_auditor import licensing


class AuditRecord(BaseModel):
    """One authorized charge in the mandate's retention chain."""
    chain_seq: int
    chain_ref: str
    receipt_hash: str
    charge_id: str
    amount: int
    asset: str
    period_key: str
    ts: str


class AuditReport(BaseModel):
    """Self-contained audit report for a mandate's full authorized-charge history.

    Verify offline: ``verify_audit_report(report)`` — returns True only if every
    chain_ref is consistent with its receipt_hash and the preceding record's receipt_hash.
    No AlgoVoi infrastructure required.
    """
    mandate_id: str
    kid: str
    issuer_id: str          # f"mandate:{mandate_id}"
    generated_at: str       # ISO8601 UTC
    record_count: int
    records: list[AuditRecord]


async def build_audit_report(store: MandateStore, *, kid: str, mandate_id: str, generated_at: str) -> AuditReport:
    """Build an AuditReport from the store's charge ledger for one mandate.

    Args:
        store: The MandateStore that backs the payment-mandate issuer.
        kid: The mandate authority key-id (hex prefix of the public key hash).
        mandate_id: UUID of the mandate to audit.
        generated_at: ISO8601 UTC timestamp to stamp on the report (caller supplies
            so the report is deterministic — use datetime.now(UTC).isoformat()).

    Returns:
        AuditReport with records ordered by ascending chain_seq.
    """
    licensing.require_license()
    rows = await store.list_chain_records(kid=kid, mandate_id=mandate_id)
    records = [
        AuditRecord(
            chain_seq=int(r["chain_seq"]),
            chain_ref=r["chain_ref"],
            receipt_hash=r["receipt_hash"],
            charge_id=r["charge_id"],
            amount=int(r["amount"]),
            asset=r.get("asset") or "",
            period_key=r["period_key"],
            ts=r["ts"],
        )
        for r in rows
    ]
    issuer_id = f"mandate:{mandate_id}"
    return AuditReport(
        mandate_id=mandate_id,
        kid=kid,
        issuer_id=issuer_id,
        generated_at=generated_at,
        record_count=len(records),
        records=records,
    )


def verify_audit_report(report: AuditReport) -> tuple[bool, str | None]:
    """Verify the retention chain in an AuditReport.

    Recomputes every chain_ref from local data and checks sequence ordering.
    No network or external state required.

    Returns:
        (True, None) if the chain is valid.
        (False, reason) if any link fails — reason names the first failing chain_seq.
    """
    # SECURITY (2026-08-19): the displayed record_count must equal the actual number of records, so a
    # report cannot understate/overstate its own size. (report-level metadata like `kid`/`generated_at`
    # is bound by the report-level reseal signature over the whole report bytes, not by this chain check.)
    if report.record_count != len(report.records):
        return False, "record_count_mismatch"

    if not report.records:
        return True, None

    # SECURITY (2026-08-19): bind the DISPLAYED fields to the receipt_hash. The chain only commits to
    # each record's receipt_hash, so recomputing chain_refs alone leaves amount/asset/charge_id/period_key/
    # ts free to be edited in the report while the chain still "verifies" (a tampered amount showed a green
    # check). Recompute each receipt_hash from the displayed fields using payment-mandate's own preimage
    # (single source of truth) and reject any record whose displayed values do not hash to its receipt_hash.
    for r in report.records:
        expected = _mandate_receipt_hash(
            report.mandate_id, r.charge_id, r.amount, r.asset, r.period_key, r.ts)
        if expected != r.receipt_hash:
            return False, f"receipt_hash_mismatch@chain_seq={r.chain_seq}"

    chain_dicts: list[dict[str, Any]] = [
        {
            "chain_ref": r.chain_ref,
            "prev_receipt_hash": "" if r.chain_seq == 0 else report.records[i - 1].receipt_hash,
            "receipt_hash": r.receipt_hash,
            "chain_seq": r.chain_seq,
            "issuer_id": report.issuer_id,
        }
        for i, r in enumerate(report.records)
    ]

    ok = verify_chain_sequence(chain_dicts)
    if not ok:
        # Find the first failing link to give a useful reason.
        for rec in chain_dicts:
            if not verify_chain_link(
                chain_ref=rec["chain_ref"],
                prev_receipt_hash=rec["prev_receipt_hash"],
                receipt_hash=rec["receipt_hash"],
                chain_seq=rec["chain_seq"],
                issuer_id=rec["issuer_id"],
            ):
                return False, f"chain_seq={rec['chain_seq']}"
        return False, "sequence_gap_or_ordering"
    return True, None
