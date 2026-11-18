"""Passport issuance and lifecycle (issue, revoke, status, CRL)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from algovoi_agent_passport import licensing, refs, signing
from algovoi_agent_passport.event_ledger import EventLedger, make_signed_envelope
from algovoi_agent_passport.store import PassportStore
from algovoi_agent_passport.verifier import _is_expired


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class PassportIssuer:
    """Issues Falcon-1024-signed agent passports and manages their lifecycle against a store.

    The signing key is injected (never read from any infrastructure). ``kid = sha256(pk)[:16]``.
    """

    def __init__(
        self,
        *,
        secret_key: bytes,
        public_key: bytes,
        store: PassportStore,
        issuer_did: str = "did:web:issuer.example.com",
        mldsa_secret_key: bytes | None = None,
        mldsa_public_key: bytes | None = None,
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence → refuse to operate
        self.sk = secret_key
        self.pk = public_key
        self.store = store
        self.issuer_did = issuer_did
        self.kid = signing.kid_for(public_key)
        # Optional hybrid co-signing key (Falcon + ML-DSA-65): when set, credentials AND the event chain
        # carry both signatures.
        self.mldsa_sk = mldsa_secret_key
        self.mldsa_pk = mldsa_public_key
        # Tamper-evident, CCC-exportable chain of issue/revoke events, signed with the issuer key.
        self.events = EventLedger(secret_key, public_key, mldsa_secret_key, mldsa_public_key)

    def export_pack(self, out_dir: str) -> str:
        """Write the signed passport event chain as a CCC-ingestable evidence pack."""
        return self.events.export_pack(out_dir)

    def _passport_ref(self, *, agent_did, scopes, issued_at, expires_at) -> str:
        return refs.passport_ref_from_payload({
            "agent_did": agent_did, "issuer_did": self.issuer_did,
            "scopes": scopes, "issued_at": issued_at, "expires_at": expires_at})

    async def issue(
        self,
        *,
        agent_did: str,
        scopes: list[str] | None = None,
        spend_limit_microusd: int | None = None,
        spend_window: str | None = None,
        ttl_secs: int = 2_592_000,
        tenant_id: str = "",
    ) -> dict:
        pid = str(uuid4())
        now = datetime.now(timezone.utc).replace(microsecond=0)
        exp = now + timedelta(seconds=ttl_secs)
        payload = {
            "type": "agent_passport", "version": "1", "passport_id": pid, "agent_did": agent_did,
            "scopes": scopes or [], "spend_limit_microusd": spend_limit_microusd,
            "spend_window": spend_window, "issuer_did": self.issuer_did, "kid": self.kid,
            "issued_at": _iso(now), "expires_at": _iso(exp),
        }
        # Hybrid (Falcon + optional ML-DSA-65) credential signature.
        credential = make_signed_envelope(payload, self.sk, self.pk, self.mldsa_sk, self.mldsa_pk)
        await self.store.insert({
            "id": pid, "kid": self.kid, "agent_did": agent_did, "scopes": scopes or [],
            "spend_limit_microusd": spend_limit_microusd, "spend_window": spend_window,
            "issued_at": _iso(now), "expires_at": _iso(exp), "credential": credential,
            "revoked_at": None, "revoke_reason": None, "tenant_id": tenant_id,
        })
        # Record a signed, no-PII lifecycle event in the tamper-evident chain.
        self.events.append({
            "event": "issue", "passport_id": pid, "kid": self.kid,
            "passport_ref": self._passport_ref(agent_did=agent_did, scopes=scopes or [],
                                               issued_at=_iso(now), expires_at=_iso(exp)),
            "at": _iso(now),
        })
        return {"passport_id": pid, "credential": credential, "kid": self.kid,
                "expires_at": _iso(exp), "status_url": f"/v1/passport/status/{self.kid}/{pid}"}

    async def revoke(self, *, passport_id: str, reason: str | None = None) -> bool:
        ok = await self.store.revoke(passport_id=passport_id, reason=reason)
        if ok:
            rec = await self.store.get(kid=self.kid, passport_id=passport_id)
            pref = self._passport_ref(
                agent_did=(rec or {}).get("agent_did"), scopes=(rec or {}).get("scopes") or [],
                issued_at=(rec or {}).get("issued_at"), expires_at=(rec or {}).get("expires_at")
            ) if rec else None
            self.events.append({
                "event": "revoke", "passport_id": str(passport_id), "kid": self.kid,
                "passport_ref": pref, "reason": reason,
                "at": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        return ok

    async def status(self, *, kid: str, passport_id: str) -> str:
        rec = await self.store.get(kid=kid, passport_id=passport_id)
        if rec is None:
            return "unknown"
        if rec.get("revoked_at") is not None:
            return "revoked"
        if _is_expired(rec.get("expires_at")):
            return "expired"
        return "active"

    async def list_revoked(self, *, kid: str) -> list[str]:
        return await self.store.list_revoked(kid=kid)
