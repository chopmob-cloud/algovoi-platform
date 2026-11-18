"""The Verifiable Audit Log engine: append an event → content-address → sign → link to the chain."""
from __future__ import annotations

from algovoi_audit_log import licensing

from datetime import datetime, timezone
from uuid import uuid4

from algovoi_audit_log import signing
from algovoi_audit_log.models import VerifyChainResult
from algovoi_audit_log.store import AuditStore
from algovoi_audit_log.verifier import verify_chain as _verify_chain


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditLog:
    """Append-only, tamper-evident, post-quantum event log over a pluggable store.

    Each entry binds an event's content hash into a Falcon-1024-signed receipt that links to the
    previous entry (``prev_entry_hash``), forming an offline-verifiable chain. The event itself is
    recorded inline in the entry (no separate blob store). ``append`` assumes a single writer.
    """

    def __init__(
        self,
        *,
        public_key: bytes,
        store: AuditStore,
        secret_key: bytes | None = None,
        issuer_did: str = "did:web:issuer.example.com",
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        # secret_key is optional: omit it for a read-only / verify view.
        self.sk = secret_key
        self.pk = public_key
        self.store = store
        self.issuer_did = issuer_did
        self.kid = signing.kid_for(public_key)

    async def head(self) -> dict:
        return await self.store.head()

    async def append(self, *, event_type: str, event: dict, actor: str | None = None) -> dict:
        if self.sk is None:
            raise RuntimeError("AuditLog is read-only (constructed without secret_key); cannot append")
        head = await self.store.head()
        seq, prev = head["seq_count"], head["last_entry_hash"]
        now = datetime.now(timezone.utc).replace(microsecond=0)
        eid = str(uuid4())
        event_hash = signing.payload_hash(event)
        payload = {
            "type": "audit_event", "version": "1", "seq": seq, "event_id": eid, "event_type": event_type,
            "event": event, "event_hash": event_hash, "actor": actor, "prev_entry_hash": prev,
            "issuer_did": self.issuer_did, "kid": self.kid, "recorded_at": _iso(now),
        }
        receipt = signing.make_envelope(payload, self.sk, self.pk)
        await self.store.insert({
            "seq": seq, "event_id": eid, "event_type": event_type, "envelope": receipt,
            "entry_hash": signing.payload_hash(payload), "recorded_at": _iso(now)})
        return {"seq": seq, "event_id": eid, "event_type": event_type, "event_hash": event_hash,
                "prev_entry_hash": prev, "receipt": receipt, "kid": self.kid, "recorded_at": _iso(now)}

    async def get_entry(self, seq: int) -> str | None:
        r = await self.store.get(seq)
        return r["envelope"] if r else None

    async def list_entries(self) -> list[str]:
        head = await self.store.head()
        out: list[str] = []
        for i in range(head["seq_count"]):
            r = await self.store.get(i)
            if r is None:
                break
            out.append(r["envelope"])
        return out

    async def verify_chain(self, *, expected_head: dict | None = None) -> VerifyChainResult:
        """Verify the whole chain and detect truncation/holes.

        A dropped *interior* entry is caught here: the persisted ``seq_count`` will exceed the length
        of a contiguous scan from ``seq 0`` (``list_entries`` would instead silently stop at the hole).
        A dropped *trailing* entry moves the store head with it, so it can only be caught against an
        out-of-band anchor: pass ``expected_head`` (a prior :meth:`head` you pinned,
        ``{seq_count, last_entry_hash}``) and any removed tail is rejected. With no anchor, the chain is
        checked against the store's own head (which still catches a tampered head row or an interior gap).
        """
        store_head = await self.store.head()
        # Contiguous scan from seq 0 — surface a hole as a missing entry instead of skipping past it.
        receipts: list[str] = []
        i = 0
        while True:
            r = await self.store.get(i)
            if r is None:
                break
            receipts.append(r["envelope"])
            i += 1
        if int(store_head.get("seq_count") or 0) != len(receipts):
            # The store reports more entries than a contiguous read from 0 can reach: an interior
            # entry has been removed (the tail after the hole is orphaned).
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="missing_entry")
        anchor = expected_head or {"seq_count": store_head.get("seq_count"),
                                   "last_entry_hash": store_head.get("last_entry_hash")}
        return _verify_chain(receipts, self.pk, expected_head=anchor)
