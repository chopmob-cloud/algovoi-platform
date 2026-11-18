"""Billing-period helpers for per-period cap accounting."""
from __future__ import annotations

from datetime import datetime, timezone

VALID_PERIODS = {"once", "day", "week", "month", "year"}


def period_key(period: str, dt: datetime) -> str:
    """A stable bucket key for ``dt`` under ``period`` (UTC). Charges in the same bucket share a cap."""
    d = dt.astimezone(timezone.utc)
    if period == "once":
        return "once"
    if period == "day":
        return d.strftime("%Y-%m-%d")
    if period == "week":
        y, w, _ = d.isocalendar()
        return f"{y}-W{w:02d}"
    if period == "year":
        return d.strftime("%Y")
    return d.strftime("%Y-%m")  # month (default)
