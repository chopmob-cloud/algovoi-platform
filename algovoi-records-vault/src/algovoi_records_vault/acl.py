"""F8 — principal binding + fine-grained access control.

Bearer-token auth answers "is this a valid caller?" but not "may *this* principal do *this* action on
*this* record/matter?". This module records signed access grants in an ``acl/`` :class:`_VaultStream`
— ``(principal, resource, actions)`` with optional expiry — and answers :meth:`ACLRegistry.check`
offline from the signed chain. ``resource`` is a ``doc_hash``, a ``matter_id``, or ``"*"`` (all);
``actions`` are e.g. ``read`` / ``notarize`` / ``hold`` / ``release`` (or ``"*"``). Grants and
revocations are append-only, so *who could do what, when* is itself tamper-evident evidence — and a
denial can be logged against the read-access log (F3).
"""
from __future__ import annotations

from datetime import datetime, timezone

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
    is treated as already expired — a corrupt ``expires_at`` must never silently grant access forever.
    """
    if not expires_at:
        return True
    exp = _parse(expires_at)
    if exp is None:
        return False
    return now < exp


class ACLRegistry:
    """Append-only ``acl/`` stream of access grants + revocations, with an offline check."""

    def __init__(self, *, stream: _VaultStream) -> None:
        self._stream = stream

    async def grant(self, *, principal_did: str, resource: str, actions: list[str],
                    granted_by: str, expires_at: str | None = None,
                    principal: Principal | None = None) -> dict:
        """Grant ``principal_did`` the given ``actions`` on ``resource`` (doc_hash | matter_id | ``*``)."""
        if expires_at is not None and _parse(expires_at) is None:
            raise ValueError(
                f"expires_at must be ISO-8601 UTC (e.g. 2026-01-02T03:04:05Z); got {expires_at!r}")
        fields = {
            "acl_event": "grant",
            "principal_did": principal_did,
            "resource": resource,
            "actions": list(actions),
            "granted_by": granted_by,
            "granted_at": _iso(_now()),
            "expires_at": expires_at,
            **{f"by_{k}": v for k, v in principal_fields(principal).items()},
        }
        return await self._stream.append(fields)

    async def revoke(self, *, principal_did: str, resource: str, reason: str = "",
                     revoked_by: str = "", principal: Principal | None = None) -> dict:
        """Revoke a principal's grant on a resource — append-only (the grant stays in the trail)."""
        fields = {
            "acl_event": "revoke",
            "principal_did": principal_did,
            "resource": resource,
            "reason": reason,
            "revoked_by": revoked_by,
            "revoked_at": _iso(_now()),
            **{f"by_{k}": v for k, v in principal_fields(principal).items()},
        }
        return await self._stream.append(fields)

    async def _active(self) -> dict[tuple[str, str], dict]:
        """Fold the stream into ``{(principal_did, resource): grant}`` (revoke removes the pair)."""
        active: dict[tuple[str, str], dict] = {}
        for p in await self._stream.list_payloads():
            key = (p.get("principal_did"), p.get("resource"))
            if p.get("acl_event") == "grant":
                active[key] = p
            elif p.get("acl_event") == "revoke":
                active.pop(key, None)
        return active

    async def check(self, *, principal_did: str, resource: str, action: str,
                    now: datetime | None = None, verify: bool = True) -> bool:
        """Is ``principal_did`` allowed ``action`` on ``resource`` right now?

        A grant matches if it covers the resource (exact or ``"*"``) and the action (in ``actions`` or
        ``"*"``), is not revoked, and is not expired.

        ``verify`` (default ``True``) first verifies the ``acl/`` signed chain and raises
        :class:`ChainIntegrityError` if it was tampered with — an access decision is never returned
        from an unverifiable chain. Pass ``verify=False`` only in a hot path that already verified the
        chain once for a batch of checks.
        """
        if verify:
            await ensure_chain_valid(self._stream, "acl")
        now = (now or _now()).astimezone(timezone.utc)
        active = await self._active()
        for res in (resource, "*"):
            g = active.get((principal_did, res))
            if g is None:
                continue
            if not _not_expired(g.get("expires_at"), now):
                continue
            acts = g.get("actions") or []
            if action in acts or "*" in acts:
                return True
        return False

    async def active_grants(self) -> list[dict]:
        return list((await self._active()).values())

    async def entries(self) -> list[dict]:
        return await self._stream.list_payloads()

    async def verify_chain(self):
        """Offline integrity of the ACL stream — proves no grant/revocation was edited or removed."""
        return await self._stream.verify_chain()
