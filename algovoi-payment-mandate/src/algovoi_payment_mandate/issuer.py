"""Mandate issuance, lifecycle, and the charge-authorization engine (per-period cap enforcement)."""
from __future__ import annotations

import hashlib

import rfc8785
from algovoi_payment_mandate import licensing

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from algovoi_payment_mandate import refs, signing
from algovoi_payment_mandate.charge_ledger import ChargeLedger, make_signed_envelope
from algovoi_payment_mandate.models import ChargeAuthorizationResult
from algovoi_payment_mandate.periods import period_key
from algovoi_payment_mandate.store import MandateStore
from algovoi_payment_mandate.verifier import _is_expired, verify_mandate
from algovoi_retention_chain import retention_chain_ref


def _receipt_hash(mandate_id: str, charge_id: str, amount: int, asset: str, period_key_: str, ts: str) -> str:
    """SHA-256(JCS({amount, asset, charge_id, mandate_id, period_key, ts})) — the receipt preimage."""
    payload = {
        "amount": amount,
        "asset": asset,
        "charge_id": charge_id,
        "mandate_id": str(mandate_id),
        "period_key": period_key_,
        "ts": ts,
    }
    return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class MandateIssuer:
    """Issues Falcon-1024-signed payment mandates, manages their lifecycle, and authorizes charges.

    The signing key is injected (never read from any infrastructure). ``kid = sha256(pk)[:16]``.
    A mandate authorizes the ``payee`` to charge the ``payer`` up to ``max_amount`` per ``period``;
    :meth:`authorize_charge` checks each pull against that cap using the store's charge ledger.
    """

    def __init__(
        self,
        *,
        secret_key: bytes,
        public_key: bytes,
        store: MandateStore,
        issuer_did: str = "did:web:issuer.example.com",
        mldsa_secret_key: bytes | None = None,
        mldsa_public_key: bytes | None = None,
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        self.sk = secret_key
        self.pk = public_key
        self.store = store
        self.issuer_did = issuer_did
        self.kid = signing.kid_for(public_key)
        # Optional hybrid co-signing key (Falcon + ML-DSA-65): when set, mandates AND the charge chain
        # carry both signatures.
        self.mldsa_sk = mldsa_secret_key
        self.mldsa_pk = mldsa_public_key
        # Tamper-evident, CCC-exportable chain of authorized charges, signed with the authority key.
        self.charges = ChargeLedger(secret_key, public_key, mldsa_secret_key, mldsa_public_key)

    def export_pack(self, out_dir: str) -> str:
        """Write the signed authorized-charge chain as a CCC-ingestable evidence pack."""
        return self.charges.export_pack(out_dir)

    async def issue(
        self,
        *,
        payer: str,
        payee: str,
        max_amount: int,
        asset: str = "USDC",
        chain: str = "*",
        period: str = "month",
        max_per_charge: int | None = None,
        scope: list[str] | None = None,
        ttl_secs: int = 31_536_000,
    ) -> dict:
        mid = str(uuid4())
        now = datetime.now(timezone.utc).replace(microsecond=0)
        exp = now + timedelta(seconds=ttl_secs)
        payload = {
            "type": "payment_mandate", "version": "1", "mandate_id": mid,
            "payer": payer, "payee": payee, "asset": asset, "chain": chain,
            "max_amount": max_amount, "period": period, "max_per_charge": max_per_charge,
            "scope": scope or [], "issuer_did": self.issuer_did, "kid": self.kid,
            "issued_at": _iso(now), "expires_at": _iso(exp),
        }
        mandate = make_signed_envelope(payload, self.sk, self.pk, self.mldsa_sk, self.mldsa_pk)
        await self.store.insert({
            "id": mid, "kid": self.kid, "payer": payer, "payee": payee, "asset": asset, "chain": chain,
            "max_amount": max_amount, "period": period, "max_per_charge": max_per_charge, "scope": scope or [],
            "issued_at": _iso(now), "expires_at": _iso(exp), "mandate": mandate,
            "revoked_at": None, "revoke_reason": None,
        })
        return {"mandate_id": mid, "mandate": mandate, "kid": self.kid, "expires_at": _iso(exp),
                "status_url": f"/v1/mandates/status/{self.kid}/{mid}"}

    async def revoke(self, *, mandate_id: str, reason: str | None = None) -> bool:
        return await self.store.revoke(mandate_id=mandate_id, reason=reason)

    async def status(self, *, kid: str, mandate_id: str) -> str:
        rec = await self.store.get(kid=kid, mandate_id=mandate_id)
        if rec is None:
            return "unknown"
        if rec.get("revoked_at") is not None:
            return "revoked"
        if _is_expired(rec.get("expires_at")):
            return "expired"
        return "active"

    async def list_revoked(self, *, kid: str) -> list[str]:
        return await self.store.list_revoked(kid=kid)

    async def authorize_charge(
        self,
        *,
        mandate: str,
        charge_id: str,
        amount: int,
        payee: str | None = None,
        asset: str | None = None,
        at: str | None = None,
        strict: bool = False,
    ) -> ChargeAuthorizationResult:
        """Authorize (or decline) a single charge against a mandate.

        Validates the mandate (signature/expiry/revocation), enforces payee/asset/per-charge limits,
        and the **per-period cap** via the store ledger. Idempotent on ``charge_id`` — re-presenting
        the same id returns the original decision and never double-counts. ``strict`` fails the charge
        closed if the revocation store is unreachable (``decline_reason='REVOCATION_UNAVAILABLE'``).
        """
        verdict = await verify_mandate(mandate, self.pk, store=self.store, strict=strict)
        if not verdict.verified:
            return ChargeAuthorizationResult(
                authorized=False, kid=verdict.kid, charge_id=charge_id, amount=amount,
                decline_reason=verdict.error_code or "INVALID_MANDATE")

        payload, _, _env_kid = signing.open_envelope(mandate)
        # SECURITY (Codex-confirmed CRITICAL 2026-08-19): verify_mandate above verified the
        # mandate against self.pk and now enforces envelope/payload kid == kid_for(self.pk),
        # so the trusted kid is self.kid. NEVER key the spend-cap ledger on the unsigned
        # envelope kid (flipping it opened a fresh, empty cap namespace).
        kid = self.kid
        mid = str(payload.get("mandate_id"))
        m_payee, m_asset, m_period = payload.get("payee"), payload.get("asset"), payload.get("period")
        max_amount = int(payload.get("max_amount") or 0)
        max_per_charge = payload.get("max_per_charge")

        # Idempotency: a previously-seen charge_id returns its original decision.
        prior = await self.store.get_charge(kid=kid, mandate_id=mid, charge_id=charge_id)
        if prior is not None:
            total = await self.store.period_total(kid=kid, mandate_id=mid, period_key=prior["period_key"])
            authed = bool(prior["authorized"])
            return ChargeAuthorizationResult(
                authorized=authed, mandate_id=mid, kid=kid, charge_id=charge_id,
                amount=int(prior["amount"]), asset=prior.get("asset"), period=m_period,
                period_key=prior["period_key"], period_total_after=total,
                remaining_this_period=max(0, max_amount - total) if authed else None,
                idempotent=True, decline_reason=None if authed else "PRIOR_DECLINE")

        # SECURITY (Codex-confirmed HIGH 2026-08-19): the charged party must NOT choose the
        # accounting-period bucket. Bucket (and timestamp receipts) by SERVER time only. `at`
        # is advisory metadata and is NEVER used for the period key or the receipt ts, so a
        # caller cannot send each charge with a distinct future/past `at` to land every charge
        # in its own empty bucket and evade the per-period cap.
        when = datetime.now(timezone.utc)
        pkey = period_key(m_period, when)

        def _decline(reason: str, total: int | None = None) -> ChargeAuthorizationResult:
            return ChargeAuthorizationResult(
                authorized=False, mandate_id=mid, kid=kid, charge_id=charge_id, amount=amount,
                asset=asset or m_asset, period=m_period, period_key=pkey,
                period_total_after=total, remaining_this_period=(max(0, max_amount - total) if total is not None else None),
                decline_reason=reason)

        if amount <= 0:
            return _decline("INVALID_AMOUNT")
        if payee is not None and m_payee is not None and payee != m_payee:
            return _decline("PAYEE_MISMATCH")
        if asset is not None and m_asset is not None and asset != m_asset:
            return _decline("ASSET_MISMATCH")
        if max_per_charge is not None and amount > int(max_per_charge):
            return _decline("PER_CHARGE_CAP_EXCEEDED")

        total = await self.store.period_total(kid=kid, mandate_id=mid, period_key=pkey)
        if total + amount > max_amount:
            # Record the decline (authorized=False → excluded from period totals) for idempotency.
            await self.store.record_charge({
                "kid": kid, "mandate_id": mid, "charge_id": charge_id, "amount": amount,
                "asset": asset or m_asset, "period_key": pkey, "authorized": False, "ts": _iso(when)})
            return _decline("PERIOD_CAP_EXCEEDED", total=total)

        # Compute the retention chain ref for this authorized charge.
        effective_asset = asset or m_asset or ""
        ts_str = _iso(when)
        rh = _receipt_hash(mid, charge_id, amount, effective_asset, pkey, ts_str)
        last = await self.store.get_last_chain_record(kid=kid, mandate_id=mid)
        next_seq = 0 if last is None else int(last["chain_seq"]) + 1
        prev_rh = "" if last is None else last["receipt_hash"]
        cref = retention_chain_ref(
            prev_receipt_hash=prev_rh,
            receipt_hash=rh,
            chain_seq=next_seq,
            issuer_id=f"mandate:{mid}",
        )

        await self.store.record_charge({
            "kid": kid, "mandate_id": mid, "charge_id": charge_id, "amount": amount,
            "asset": effective_asset, "period_key": pkey, "authorized": True, "ts": ts_str,
            "chain_seq": next_seq, "chain_ref": cref, "receipt_hash": rh})
        # Signed, no-PII charge event in the tamper-evident CCC-exportable chain (amount as decimal string).
        self.charges.append({
            "event": "charge", "mandate_id": mid, "kid": kid, "charge_id": charge_id,
            "mandate_ref": refs.mandate_ref_from_payload(payload, revocation_state="active"),
            "amount_minor": str(amount), "asset": effective_asset, "period": m_period,
            "period_key": pkey, "chain_ref": cref, "at": ts_str,
        })
        new_total = total + amount
        return ChargeAuthorizationResult(
            authorized=True, mandate_id=mid, kid=kid, charge_id=charge_id, amount=amount,
            asset=effective_asset, period=m_period, period_key=pkey,
            period_total_after=new_total, remaining_this_period=max(0, max_amount - new_total),
            chain_seq=next_seq, chain_ref=cref)
