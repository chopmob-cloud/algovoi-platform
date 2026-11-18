"""Retention policy evaluation for compliance reporting."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _parse(iso: str) -> datetime:
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class RetentionPolicy:
    """Maps a record to a retention period. ``by_content_type`` overrides ``default_days`` per type.

    Status meanings: ``within`` = still inside the required retention window (must keep);
    ``over`` = retention elapsed (eligible for disposal); ``no_policy`` = no rule for this type.
    """

    def __init__(self, *, default_days: int | None = None, by_content_type: dict[str, int] | None = None) -> None:
        self.default_days = default_days
        self.by_content_type = by_content_type or {}

    def retain_days(self, content_type: str | None) -> int | None:
        return self.by_content_type.get(content_type or "", self.default_days)

    def evaluate(self, *, archived_at: str | None, content_type: str | None,
                 now: datetime | None = None) -> tuple[str, str | None]:
        days = self.retain_days(content_type)
        if days is None:
            return "no_policy", None
        if not archived_at:
            return "unknown", None
        try:
            start = _parse(archived_at)
        except Exception:  # noqa: BLE001
            return "unknown", None
        retain_until = start + timedelta(days=days)
        now = now or datetime.now(timezone.utc)
        return ("over" if now >= retain_until else "within"), _iso(retain_until)
