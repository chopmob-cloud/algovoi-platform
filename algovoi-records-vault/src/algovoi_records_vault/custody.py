"""F6 — Falcon-signed custody manifest (legal: chain of custody + custodian handoff).

For evidence, *who held the records, unbroken, from creation to court* is itself a question you must
answer. This module records a ``custody/`` :class:`_VaultStream` of signed custody manifests: a
**batch attestation** (the current custodian attests a shipped batch — ``batch_range``, ``batch_hash``,
optionally cross-signed by the custodian's own Falcon key) and a **handoff** (custody passes to a new
custodian, naming the prior one). Each handoff names ``prev_custodian_did``, so the chain is a
multi-decade, offline-provable record of unbroken custody — no gap a spoliation argument can exploit.
"""
from __future__ import annotations

from datetime import datetime, timezone

import substrate2

from algovoi_doc_archive import signing

from algovoi_records_vault.principals import Principal, principal_fields
from algovoi_records_vault.vault import _VaultStream


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


_ATTEST_KEYS = ("custodian_did", "custodian_kid", "batch_range", "batch_hash", "attested_at")


def make_custody_attestation(*, custodian_did: str, batch_range: dict, batch_hash: str,
                             custodian_secret_key: bytes, custodian_public_key: bytes,
                             attested_at: str | None = None) -> dict:
    """A custodian's own-key Falcon signature over a batch binding (proves *that custodian* attested)."""
    b = {
        "custodian_did": custodian_did,
        "custodian_kid": signing.kid_for(custodian_public_key),
        "batch_range": batch_range,
        "batch_hash": batch_hash,
        "attested_at": attested_at or _now(),
    }
    sig = signing.sign_bytes(custodian_secret_key, substrate2.canonicalize_bytes(b))
    return {**b, "custodian_pubkey_b64": signing.public_key_b64(custodian_public_key),
            "custodian_sig": signing.b64u_encode(sig)}


def verify_custody_attestation(att: dict) -> bool:
    """Offline: the custodian-key signature is valid and its kid matches the embedded key. Never raises."""
    try:
        b = {k: att[k] for k in _ATTEST_KEYS}
        pk = signing.load_key_b64(att["custodian_pubkey_b64"])
        if signing.kid_for(pk) != att["custodian_kid"]:
            return False
        return signing.verify_bytes(pk, substrate2.canonicalize_bytes(b), signing.b64u_decode(att["custodian_sig"]))
    except Exception:  # noqa: BLE001
        return False


class CustodyLog:
    """Append-only ``custody/`` stream of signed batch attestations + custodian handoffs."""

    def __init__(self, *, stream: _VaultStream) -> None:
        self._stream = stream

    async def current_custodian(self) -> str | None:
        cur: str | None = None
        for p in await self._stream.list_payloads():
            if p.get("custody_event") == "handoff":
                cur = p.get("custodian_did")
            elif p.get("custody_event") == "attest" and cur is None:
                cur = p.get("custodian_did")
        return cur

    async def attest_batch(self, *, custodian_did: str, batch_range: dict, batch_hash: str,
                           reason: str = "", custodian_keys: tuple[bytes, bytes] | None = None,
                           principal: Principal | None = None) -> dict:
        """Attest a shipped batch under the current custodian. Pass ``custodian_keys=(pk, sk)`` to add
        the custodian's own Falcon counter-signature over the batch binding."""
        fields: dict = {
            "custody_event": "attest",
            "custodian_did": custodian_did,
            "batch_range": batch_range,
            "batch_hash": batch_hash,
            "reason": reason,
            "attested_at": _now(),
            **principal_fields(principal),
        }
        if custodian_keys is not None:
            pk, sk = custodian_keys
            att = make_custody_attestation(custodian_did=custodian_did, batch_range=batch_range,
                                           batch_hash=batch_hash, custodian_secret_key=sk,
                                           custodian_public_key=pk, attested_at=fields["attested_at"])
            fields["custodian_attestation"] = att
        return await self._stream.append(fields)

    async def handoff(self, *, to_custodian_did: str, reason: str,
                      principal: Principal | None = None) -> dict:
        """Pass custody to a new custodian, naming the prior one — the provable handoff link."""
        prev = await self.current_custodian()
        fields = {
            "custody_event": "handoff",
            "custodian_did": to_custodian_did,
            "prev_custodian_did": prev,
            "reason": reason,
            "handed_off_at": _now(),
            **principal_fields(principal),
        }
        return await self._stream.append(fields)

    async def custodians(self) -> list[str]:
        """The ordered custodian lineage (each distinct custodian as custody passed)."""
        out: list[str] = []
        for p in await self._stream.list_payloads():
            did = p.get("custodian_did")
            if did and (not out or out[-1] != did):
                out.append(did)
        return out

    async def manifests(self) -> list[dict]:
        return await self._stream.list_payloads()

    async def verify_custody(self) -> tuple[bool, str]:
        """Verify the signed chain, then handoff continuity + every custodian signature.

        The signed ``custody/`` chain is verified first — a tampered, reordered, or truncated entry
        fails here before any continuity verdict is computed (parity with the other evidence verifiers).
        """
        chain = await self._stream.verify_chain()
        if not chain.valid:
            return False, f"custody chain failed verification: {chain.reason} (broken_at={chain.broken_at})"
        payloads = await self._stream.list_payloads()
        cur: str | None = None
        for i, p in enumerate(payloads):
            if p.get("custody_event") == "handoff":
                if cur is not None and p.get("prev_custodian_did") != cur:
                    return False, f"custody_gap@{i} (expected prev={cur}, got {p.get('prev_custodian_did')})"
                cur = p.get("custodian_did")
            elif p.get("custody_event") == "attest":
                if cur is None:
                    cur = p.get("custodian_did")
                att = p.get("custodian_attestation")
                if att is not None and not verify_custody_attestation(att):
                    return False, f"bad_custodian_signature@{i}"
        return True, f"custody intact, current={cur}"

    async def verify_chain(self):
        """Offline integrity of the custody stream (the signed-entry chain)."""
        return await self._stream.verify_chain()
