"""
The Archive Auditor: read-only verification, signed reports, attestations, retention, evidence packs.

Runs over the same ``StorageBackend`` as the archive (local or S3), reusing the core's read-only
``Archive`` view and chain verifier. The auditor signs its own outputs with a **separate** Falcon
key (the attestation key), so a report's provenance is distinct from the archive's.
"""
from __future__ import annotations

from algovoi_archive_auditor import licensing

from datetime import datetime, timezone

from algovoi_doc_archive import signing, verify_chain
from algovoi_doc_archive.archive import Archive

from algovoi_archive_auditor.retention import RetentionPolicy


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class Auditor:
    def __init__(
        self,
        *,
        archive_public_key: bytes,
        storage,
        report_secret_key: bytes | None = None,
        report_public_key: bytes | None = None,
        retention_policy: RetentionPolicy | None = None,
        auditor_did: str = "did:web:auditor.example.com",
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        self.apk = archive_public_key
        self.storage = storage
        self.rsk = report_secret_key
        self.rpk = report_public_key
        self.policy = retention_policy
        self.auditor_did = auditor_did
        self.archive_kid = signing.kid_for(archive_public_key)
        self.kid = signing.kid_for(report_public_key) if report_public_key else None
        self._reader = Archive(public_key=archive_public_key, storage=storage)  # read-only

    async def _payloads(self) -> tuple[list[str], list[dict]]:
        receipts = await self._reader.list_entries()
        payloads = []
        for r in receipts:
            p, _, _ = signing.open_envelope(r)
            payloads.append(p)
        return receipts, payloads

    def _sign(self, payload: dict) -> str | None:
        if self.rsk and self.rpk:
            payload["auditor_kid"] = self.kid
            return signing.make_envelope(payload, self.rsk, self.rpk)
        return None

    async def verify(self):
        return await self._reader.verify_chain()

    async def inventory(self) -> list[dict]:
        _, payloads = await self._payloads()
        return [{
            "seq": p.get("seq"), "entry_id": p.get("entry_id"), "doc_hash": p.get("doc_hash"),
            "title": p.get("title"), "content_type": p.get("content_type"), "doc_size": p.get("doc_size"),
            "stored": p.get("stored"), "enc_alg": p.get("enc_alg"), "archived_at": p.get("archived_at"),
        } for p in payloads]

    async def audit_report(self, *, sign: bool = True) -> dict:
        receipts, payloads = await self._payloads()
        chain = verify_chain(receipts, self.apk)
        totals: dict[str, int] = {}
        bytes_total = 0
        archived = [p["archived_at"] for p in payloads if p.get("archived_at")]
        for p in payloads:
            ct = p.get("content_type") or "unknown"
            totals[ct] = totals.get(ct, 0) + 1
            if p.get("doc_size"):
                bytes_total += int(p["doc_size"])
        report = {
            "type": "archive_audit_report", "version": "1", "archive_kid": self.archive_kid,
            "entries": len(payloads), "chain_valid": chain.valid, "broken_at": chain.broken_at,
            "reason": chain.reason, "head_receipt_hash": chain.head_receipt_hash,
            "period_start": min(archived) if archived else None,
            "period_end": max(archived) if archived else None,
            "totals_by_content_type": totals, "bytes_stored_total": bytes_total,
            "auditor_did": self.auditor_did, "generated_at": _iso(_now()),
        }
        envelope = self._sign(report) if sign else None
        return {"report": report, "report_envelope": envelope}

    async def retention_report(self, policy: RetentionPolicy | None = None) -> dict:
        policy = policy or self.policy
        if policy is None:
            raise ValueError("no retention policy provided")
        _, payloads = await self._payloads()
        items, over, within = [], 0, 0
        for p in payloads:
            status, retain_until = policy.evaluate(archived_at=p.get("archived_at"),
                                                   content_type=p.get("content_type"))
            over += status == "over"
            within += status == "within"
            items.append({"seq": p.get("seq"), "doc_hash": p.get("doc_hash"), "title": p.get("title"),
                          "content_type": p.get("content_type"), "archived_at": p.get("archived_at"),
                          "retain_until": retain_until, "status": status})
        return {"over_retention": over, "within_retention": within, "total": len(payloads),
                "items": items, "generated_at": _iso(_now())}

    async def attest(self, *, prev_attestation_hash: str | None = None, sign: bool = True) -> dict:
        receipts, payloads = await self._payloads()
        chain = verify_chain(receipts, self.apk)
        att = {
            "type": "archive_integrity_attestation", "version": "1", "archive_kid": self.archive_kid,
            "entries": len(payloads), "chain_valid": chain.valid, "broken_at": chain.broken_at,
            "head_receipt_hash": chain.head_receipt_hash, "prev_attestation_hash": prev_attestation_hash,
            "auditor_did": self.auditor_did, "attested_at": _iso(_now()),
        }
        envelope = self._sign(att) if sign else None
        return {"attestation": att, "attestation_envelope": envelope,
                "attestation_hash": signing.payload_hash(att) if envelope else None}

    async def evidence_pack(self, *, seqs: list[int] | None = None, sign: bool = True) -> dict:
        receipts, payloads = await self._payloads()
        chain = verify_chain(receipts, self.apk)
        sel = [(r, p) for r, p in zip(receipts, payloads)
               if seqs is None or p.get("seq") in set(seqs)]
        manifest = {
            "type": "archive_evidence_pack_manifest", "version": "1", "archive_kid": self.archive_kid,
            "entry_count": len(sel), "entry_seqs": [p.get("seq") for _, p in sel],
            "entry_hashes": [signing.payload_hash(p) for _, p in sel],
            "head_receipt_hash": chain.head_receipt_hash, "chain_valid": chain.valid,
            "auditor_did": self.auditor_did, "generated_at": _iso(_now()),
        }
        envelope = self._sign(manifest) if sign else None
        return {
            "archive_kid": self.archive_kid, "archive_public_key_b64": signing.public_key_b64(self.apk),
            "manifest": manifest, "manifest_envelope": envelope,
            "entries": [r for r, _ in sel], "generated_at": _iso(_now()),
        }

    async def siem_events(self) -> list[dict]:
        out = await self.audit_report(sign=False)
        r = out["report"]
        return [{
            "event": "archive.audit", "archive_kid": self.archive_kid,
            "result": "valid" if r["chain_valid"] else "broken", "entries": r["entries"],
            "head": r["head_receipt_hash"], "broken_at": r["broken_at"], "ts": r["generated_at"],
        }]

    async def metrics_inputs(self) -> dict:
        receipts, payloads = await self._payloads()
        chain = verify_chain(receipts, self.apk)
        bytes_total = sum(int(p["doc_size"]) for p in payloads if p.get("doc_size"))
        return {
            "archive_kid": self.archive_kid, "chain_valid": chain.valid, "entries": len(payloads),
            "broken_at": chain.broken_at, "bytes_stored": bytes_total,
            "last_verified_epoch": int(_now().timestamp()),
        }
