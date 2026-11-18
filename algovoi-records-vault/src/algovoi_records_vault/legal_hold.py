"""F2 — legal hold / e-discovery hold (litigation hold that overrides retention disposal).

When litigation or an investigation is reasonably anticipated, the duty to preserve relevant records
overrides any routine retention/disposal schedule. This is the AML-hold pattern from
``control_plane/app/routers/compliance.py`` (set / release, ``*_set_by`` / ``*_set_at``,
release-blocked-until-retention) generalised to archive records and recorded as signed evidence.

Each hold action — ``set`` then later ``release`` — is appended to the signed ``holds/`` stream
(append-only: a release never erases the set, it supersedes it). :meth:`LegalHoldRegistry.is_held`
folds the stream into the currently-active holds and tests a record against each hold's matter query;
:func:`RetentionPolicy.is_disposable` then treats *held* as **never disposable**, so a held record
cannot be purged even after its retention window elapses. A hold's *release* is itself blocked until
the matter's preservation window passes, mirroring the AML 5-year floor.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from algovoi_records_vault.principals import Principal, principal_fields
from algovoi_records_vault.vault import _VaultStream, ensure_chain_valid

_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.strptime(iso, _FMT).replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        # tolerate offset-style ISO ("+00:00") that migrate metadata may carry
        try:
            return datetime.fromisoformat(iso).astimezone(timezone.utc)
        except Exception:  # noqa: BLE001
            return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_FMT)


def _matches(query: dict, record: dict) -> bool:
    """Does ``record`` fall within a hold's matter ``query``? All specified criteria must match.

    Supported criteria (any subset; an empty query matches every record — a full custodial hold):
      * ``subject_ref``   — exact match against the record's ``subject_ref``
      * ``content_type``  — exact match against the record's ``content_type``
      * ``doc_hash``      — exact match against the record's ``doc_hash``
      * ``date_range``    — ``{"from": iso, "to": iso}`` (either bound optional), inclusive, tested
                            against the record's ``archived_at`` / ``recorded_at`` / ``date``.
    """
    if "subject_ref" in query and query["subject_ref"] != record.get("subject_ref"):
        return False
    if "content_type" in query and query["content_type"] != record.get("content_type"):
        return False
    if "doc_hash" in query and query["doc_hash"] != record.get("doc_hash"):
        return False
    dr = query.get("date_range")
    if dr:
        rec_t = _parse(record.get("archived_at") or record.get("recorded_at") or record.get("date"))
        if rec_t is not None:
            lo, hi = _parse(dr.get("from")), _parse(dr.get("to"))
            if lo and rec_t < lo:
                return False
            if hi and rec_t > hi:
                return False
        # rec_t is None: the record's date cannot be determined. Fail closed — an undated (or
        # garbage-dated) record must NOT escape a litigation hold, so the date criterion is treated
        # as satisfied (any other specified criteria above still apply).
    return True


@dataclass
class RetentionPolicy:
    """A routine disposal schedule. A legal hold overrides it: held records are never disposable."""

    retention_days: int

    def disposable_at(self, record: dict) -> datetime | None:
        t = _parse(record.get("archived_at") or record.get("recorded_at") or record.get("date"))
        return None if t is None else t + timedelta(days=self.retention_days)

    def is_disposable(self, record: dict, *, now: datetime, held: bool) -> bool:
        """``True`` only if the retention window has elapsed AND no legal hold applies."""
        if held:
            return False
        due = self.disposable_at(record)
        return due is not None and now.astimezone(timezone.utc) >= due


class HoldActive(RuntimeError):
    """Raised when an operation is illegal given current hold state (e.g. early release)."""


class LegalHoldRegistry:
    """Append-only registry of legal holds over the signed ``holds/`` stream."""

    def __init__(self, *, stream: _VaultStream, retention: RetentionPolicy | None = None,
                 bridge=None) -> None:
        self._stream = stream
        self.retention = retention
        # optional, duck-typed GDPR-gate bridge (push_hold/release_hold). Best-effort mirror onto the
        # control_plane payment-ledger gate; the signed holds chain remains the system-of-record.
        self._bridge = bridge

    async def _mirror(self, action: str, *, matter_id: str, query: dict, reason: str,
                      preservation_until: str | None = None) -> None:
        if self._bridge is None:
            return
        try:
            import asyncio
            if action == "set":
                await asyncio.to_thread(self._bridge.push_hold, matter_id=matter_id, query=query,
                                        reason=reason, preservation_until=preservation_until)
            else:
                await asyncio.to_thread(self._bridge.release_hold, matter_id=matter_id, query=query,
                                        reason=reason)
        except Exception:  # noqa: BLE001 — never let a gate-mirror failure break the signed write
            pass

    async def place_hold(self, *, matter_id: str, query: dict, reason: str,
                         principal: Principal | None = None,
                         preservation_days: int | None = None) -> dict:
        """Place (or re-affirm) a hold on a matter. ``query`` scopes which records it covers.

        ``preservation_days`` sets a floor before the hold may be released (defaults to the registry's
        retention window if one is configured, else no floor).
        """
        if not matter_id:
            raise ValueError("matter_id is required")
        if preservation_days is not None and preservation_days < 0:
            raise ValueError(f"preservation_days must be >= 0; got {preservation_days!r}")
        _dr = (query or {}).get("date_range") if isinstance(query, dict) else None
        if _dr:
            for _b in ("from", "to"):
                if _dr.get(_b) is not None and _parse(_dr[_b]) is None:
                    raise ValueError(
                        f"date_range.{_b} must be ISO-8601 UTC (e.g. 2026-01-02T03:04:05Z); "
                        f"got {_dr[_b]!r}")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        floor = preservation_days if preservation_days is not None else (
            self.retention.retention_days if self.retention else None)
        release_blocked_until = _iso(now + timedelta(days=floor)) if floor is not None else None
        fields = {
            "action": "set",
            "matter_id": matter_id,
            "query": query or {},
            "reason": reason,
            "hold_set_at": _iso(now),
            "release_blocked_until": release_blocked_until,
            **{f"set_{k}": v for k, v in principal_fields(principal).items()},
        }
        rec = await self._stream.append(fields)
        await self._mirror("set", matter_id=matter_id, query=query or {}, reason=reason,
                           preservation_until=release_blocked_until)
        return rec

    async def release_hold(self, *, matter_id: str, reason: str,
                           principal: Principal | None = None,
                           now: datetime | None = None) -> dict:
        """Release a hold. Refused if no hold is active, or before its preservation floor elapses."""
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
        active = await self._active_map()
        held = active.get(matter_id)
        if held is None:
            raise HoldActive(f"no active hold on matter {matter_id!r} to release")
        raw_floor = held.get("release_blocked_until")
        if raw_floor is not None:
            blocked_until = _parse(raw_floor)
            if blocked_until is None:
                # Fail closed: an unparseable preservation floor must not permit early release.
                raise HoldActive(
                    f"legal hold on {matter_id!r} has an unparseable release_blocked_until "
                    f"({raw_floor!r}); refusing release (fail-closed)")
            if now < blocked_until:
                raise HoldActive(
                    f"legal hold on {matter_id!r} cannot be released until "
                    f"{raw_floor} (preservation window)")
        fields = {
            "action": "release",
            "matter_id": matter_id,
            "reason": reason,
            "hold_released_at": _iso(now),
            "original_hold_reason": held.get("reason"),
            **{f"released_{k}": v for k, v in principal_fields(principal).items()},
        }
        rec = await self._stream.append(fields)
        await self._mirror("release", matter_id=matter_id, query=held.get("query") or {}, reason=reason)
        return rec

    async def _active_map(self) -> dict[str, dict]:
        """Fold the append-only stream into ``{matter_id: active set-payload}`` (last action wins)."""
        active: dict[str, dict] = {}
        for p in await self._stream.list_payloads():
            mid = p.get("matter_id")
            if not mid:
                continue
            if p.get("action") == "set":
                active[mid] = p
            elif p.get("action") == "release":
                active.pop(mid, None)
        return active

    async def active_holds(self) -> list[dict]:
        """The currently-active hold set-records, one per held matter."""
        return list((await self._active_map()).values())

    async def is_held(self, record: dict, *, verify: bool = True) -> bool:
        """Is ``record`` covered by any currently-active legal hold?

        ``verify`` (default ``True``) first verifies the ``holds/`` signed chain and raises
        :class:`ChainIntegrityError` if it was tampered with — a preservation decision is never
        returned from an unverifiable chain. Pass ``verify=False`` only in a bulk sweep that already
        verified the chain once.
        """
        if verify:
            await ensure_chain_valid(self._stream, "holds")
        for hold in (await self._active_map()).values():
            if _matches(hold.get("query") or {}, record):
                return True
        return False

    async def is_disposable(self, record: dict, *, now: datetime | None = None,
                            verify: bool = True) -> bool:
        """Retention + hold disposal decision. Requires a configured :class:`RetentionPolicy`."""
        if self.retention is None:
            raise RuntimeError("is_disposable needs a RetentionPolicy (construct holds(retention_days=…))")
        now = now or datetime.now(timezone.utc)
        return self.retention.is_disposable(
            record, now=now, held=await self.is_held(record, verify=verify))

    async def verify_chain(self):
        """Offline integrity of the holds stream — proves the hold history was not edited."""
        return await self._stream.verify_chain()
