"""F5 — consent receipts (health: HIPAA authorization + GDPR lawful basis).

Regulated processing of a person's records needs a provable answer to "did they consent, to what, and
is it still valid?". This module records signed **consent receipts** in a ``consent/``
:class:`_VaultStream`: a grant pins the *exact* terms (``terms_hash``), the authorised uses, and an
optional expiry; a revocation is a **new linked entry** (append-only — consent history is never
rewritten, so you can prove both that consent was given and, later, withdrawn). ``is_authorized`` and
``verify_consent`` answer offline, from the signed chain alone.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

import substrate2

from algovoi_records_vault.principals import Principal, principal_fields
from algovoi_records_vault.vault import _VaultStream, ensure_chain_valid

_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_FMT)


def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.strptime(iso, _FMT).replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        try:
            return datetime.fromisoformat(iso).astimezone(timezone.utc)
        except Exception:  # noqa: BLE001
            return None


def _not_expired(expires_at: str | None, now: datetime) -> bool:
    """Fail-closed expiry test. An *absent* expiry never expires; a *present but unparseable* expiry
    is treated as already expired — a corrupt ``expires_at`` must never silently keep consent valid.
    """
    if not expires_at:
        return True
    exp = _parse(expires_at)
    if exp is None:
        return False
    return now < exp


def terms_hash(terms) -> str:
    """Pin the exact terms consented to: SHA-256 of the canonical bytes (JCS for dicts, UTF-8 for text)."""
    raw = substrate2.canonicalize_bytes(terms) if isinstance(terms, (dict, list)) else str(terms).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class ConsentLedger:
    """Append-only ledger of signed consent grants + revocations over the ``consent/`` stream."""

    def __init__(self, *, stream: _VaultStream) -> None:
        self._stream = stream

    async def grant(self, *, subject_ref: str, terms, authorized_uses: list[str],
                    expires_at: str | None = None, principal: Principal | None = None,
                    consent_id: str | None = None) -> dict:
        """Record a consent grant. ``terms`` (text or dict) is hashed; ``authorized_uses`` scopes it."""
        if expires_at is not None and _parse(expires_at) is None:
            raise ValueError(
                f"expires_at must be ISO-8601 UTC (e.g. 2026-01-02T03:04:05Z); got {expires_at!r}")
        if not subject_ref or not str(subject_ref).strip():
            raise ValueError("subject_ref must be a non-empty subject identifier")
        if terms is None:
            raise ValueError("terms is required (the exact consent terms to pin)")
        # a bare string would silently become a list of characters — require an actual sequence
        if isinstance(authorized_uses, str) or not isinstance(authorized_uses, (list, tuple)):
            raise ValueError("authorized_uses must be a list/tuple of use strings, not a bare string")
        cid = consent_id or str(uuid4())
        fields = {
            "consent_event": "grant",
            "consent_id": cid,
            "subject_ref": subject_ref,
            "terms_hash": terms_hash(terms),
            "authorized_uses": list(authorized_uses),
            "granted_at": _iso(_now()),
            "expires_at": expires_at,
            "status": "active",
            **principal_fields(principal),
        }
        rec = await self._stream.append(fields)
        return {**rec, "consent_id": cid}

    async def revoke(self, *, consent_id: str, reason: str = "",
                     principal: Principal | None = None) -> dict:
        """Withdraw a consent — a new linked entry (the grant is preserved for the audit trail)."""
        if consent_id not in await self._grants():
            raise ValueError(f"unknown consent_id {consent_id!r}")
        fields = {
            "consent_event": "revoke",
            "consent_id": consent_id,
            "reason": reason,
            "revoked_at": _iso(_now()),
            **{f"revoked_{k}": v for k, v in principal_fields(principal).items()},
        }
        return await self._stream.append(fields)

    async def _grants(self) -> dict[str, dict]:
        return {p["consent_id"]: p for p in await self._stream.list_payloads()
                if p.get("consent_event") == "grant"}

    async def _revoked(self) -> set[str]:
        return {p["consent_id"] for p in await self._stream.list_payloads()
                if p.get("consent_event") == "revoke"}

    async def status(self, consent_id: str, *, now: datetime | None = None,
                     verify: bool = True) -> str:
        """``active`` | ``expired`` | ``revoked`` | ``unknown`` for a consent, as of ``now``.

        ``verify`` (default ``True``) first verifies the ``consent/`` signed chain and raises
        :class:`ChainIntegrityError` if it was tampered with.
        """
        if verify:
            await ensure_chain_valid(self._stream, "consent")
        grants = await self._grants()
        g = grants.get(consent_id)
        if g is None:
            return "unknown"
        if consent_id in await self._revoked():
            return "revoked"
        now = (now or _now()).astimezone(timezone.utc)
        if not _not_expired(g.get("expires_at"), now):
            return "expired"
        return "active"

    async def is_authorized(self, *, subject_ref: str, use: str,
                            now: datetime | None = None, verify: bool = True) -> bool:
        """Is there a currently-active consent for ``subject_ref`` covering ``use``?

        ``verify`` (default ``True``) first verifies the ``consent/`` signed chain and raises
        :class:`ChainIntegrityError` if it was tampered with — authorization is never returned from an
        unverifiable chain. Pass ``verify=False`` only after verifying once for a batch.
        """
        if verify:
            await ensure_chain_valid(self._stream, "consent")
        now = (now or _now()).astimezone(timezone.utc)
        revoked = await self._revoked()
        for cid, g in (await self._grants()).items():
            if g.get("subject_ref") != subject_ref:
                continue
            if cid in revoked:
                continue
            if not _not_expired(g.get("expires_at"), now):
                continue
            uses = g.get("authorized_uses") or []
            if use in uses or "*" in uses:
                return True
        return False

    async def receipts(self) -> list[dict]:
        return await self._stream.list_payloads()

    async def verify_chain(self):
        """Offline integrity of the consent ledger — proves no grant/revocation was edited or removed."""
        return await self._stream.verify_chain()


def verify_consent(receipt: dict, terms) -> bool:
    """Offline: does a consent receipt's ``terms_hash`` match the terms presented to the subject?"""
    return receipt.get("terms_hash") == terms_hash(terms)
