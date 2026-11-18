"""
Continuous sanctions monitoring engine.

Point-in-time screening tells you a counterparty is clean today. Designations change. This engine keeps
a watchlist of subjects, re-screens them on every sweep (driven by your sanctions-data refresh), and
emits a Falcon-1024-signed **delta receipt** the moment a subject's verdict changes -- clean to hit,
hit to cleared, escalation, de-escalation. Receipts are content-addressed (`subject_ref =
sha256(network:address)`) and carry **no PII**. The engine is screener-agnostic: bring your own.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from algovoi_sanctions_monitor import licensing, signing
from algovoi_sanctions_monitor.models import WatchRecord, WatchStatus
from algovoi_sanctions_monitor.screener import Screener

_SEVERITY = {"ALLOW": 0, "REFER": 1, "DENY": 2}


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _transition(prior: str, new: str) -> str:
    p, n = _SEVERITY.get(prior, 0), _SEVERITY.get(new, 0)
    if p == 0 and n > 0:
        return "newly_hit"
    if n == 0 and p > 0:
        return "cleared"
    if n > p:
        return "escalated"
    if n < p:
        return "de-escalated"
    return "unchanged"


def subject_ref(network: str, address: str) -> str:
    """Content-addressed subject id -- the only reference to a subject that appears in a receipt."""
    return "sha256:" + hashlib.sha256(f"{network}:{address}".encode()).hexdigest()


class SanctionsMonitor:
    """Stateful continuous-monitoring engine: watch subjects, sweep, sign the deltas.

    The injected Falcon-1024 keypair signs delta receipts. The injected screener is *your* sanctions
    source (same interface as Compliance Gate). Migration evidence binds into the Substrate 2 chain
    (`canon_version: jcs-rfc8785-v1`) and verifies offline.
    """

    def __init__(self, *, secret_key: bytes, public_key: bytes, screener: Screener,
                 monitor_did: str = "did:web:monitor.example") -> None:
        licensing.require_license()        # fail-closed: no valid AlgoVoi suite licence -> refuse
        self.sk = secret_key
        self.pk = public_key
        self.screener = screener
        self.monitor_did = monitor_did
        self.kid = signing.kid_for(public_key)
        self._watch: dict[str, WatchRecord] = {}
        # SECURITY (2026-08-19): sweep health so a DEAD/stale screening feed is VISIBLE rather than
        # silently freezing verdicts. A subject whose screen throws is skipped (verdict not flipped), but
        # that must surface — a monitor that has stopped screening is a compliance failure.
        self._last_sweep: dict = {"at_ms": 0, "screened": 0, "failed": 0, "watched": 0}

    # ---- watchlist management -----------------------------------------------------
    def watch(self, *, network: str, address: str, note: str = "") -> str:
        """Add a subject to the watchlist. Returns its `subject_ref`. Idempotent."""
        ref = subject_ref(network, address)
        if ref not in self._watch:
            self._watch[ref] = WatchRecord(subject_ref=ref, network=network, address=address,
                                           first_watched_ms=_now_ms(), note=note)
        return ref

    def unwatch(self, subject_ref_: str) -> bool:
        return self._watch.pop(subject_ref_, None) is not None

    def hydrate(self, records: list[tuple[str, str, str | None, int]]) -> None:
        """Rebuild the in-memory watchlist from a persistent store: each record is
        ``(network, address, last_result, first_watched_ms)``. Lets the appliance restore state on boot
        so sweeps detect changes against the persisted baseline."""
        for network, address, last_result, first_watched_ms in records:
            ref = subject_ref(network, address)
            self._watch[ref] = WatchRecord(subject_ref=ref, network=network, address=address,
                                           first_watched_ms=first_watched_ms, last_result=last_result)

    def watchlist(self) -> list[dict]:
        """No-PII status snapshot of every watched subject."""
        return [WatchStatus(subject_ref=r.subject_ref, last_result=r.last_result,
                            last_screened_ms=r.last_screened_ms,
                            first_watched_ms=r.first_watched_ms).model_dump() for r in self._watch.values()]

    # ---- the sweep (re-screen + sign deltas) --------------------------------------
    async def sweep(self, *, run_id: str | None = None) -> list[dict]:
        """Re-screen every watched subject; return a signed delta receipt for each verdict CHANGE.

        The first sweep of a subject establishes its baseline (no receipt). Subsequent sweeps emit a
        receipt only when the verdict changes -- that change, signed and timestamped, is the
        ongoing-monitoring evidence an MLRO or regulator wants.
        """
        run_id = run_id or uuid.uuid4().hex
        now = _now_ms()
        deltas: list[dict] = []
        screened = 0
        failed = 0
        for rec in self._watch.values():
            try:
                sr = await self.screener.screen(network=rec.network, address=rec.address)
            except Exception:  # noqa: BLE001 -- transient screener failure: skip, do not flip the verdict
                failed += 1
                continue       # or emit a spurious delta; the subject is re-tried next sweep
            screened += 1
            prior, new = rec.last_result, sr.result
            if prior is not None and new != prior:
                receipt: dict = {
                    "canon_version": "jcs-rfc8785-v1",
                    "kind": "sanctions-monitor-delta",
                    "subject_ref": rec.subject_ref,
                    "prior_result": prior,
                    "new_result": new,
                    "transition": _transition(prior, new),
                    "screen_provider_did": sr.provider_did,
                    "reasons": sr.reasons or None,
                    "monitor_did": self.monitor_did,
                    "monitor_run_id": run_id,
                    "screen_timestamp_ms": now,
                    "first_watched_ms": rec.first_watched_ms,
                }
                envelope = signing.make_envelope(receipt, self.sk, self.pk)
                deltas.append({
                    "subject_ref": rec.subject_ref,
                    "transition": receipt["transition"],
                    "receipt": receipt,
                    "receipt_envelope": envelope,
                    "receipt_hash": signing.payload_hash(receipt),
                })
            rec.last_result = new
            rec.last_screened_ms = now
        self._last_sweep = {"at_ms": now, "screened": screened, "failed": failed,
                            "watched": len(self._watch)}
        return deltas

    def sweep_health(self) -> dict:
        """Screening-feed health so a dead/stale feed is visible. ``degraded`` is True when the last
        sweep had ANY screener failures (or watched subjects but screened none — a fully dead feed);
        ``stale_subjects`` counts subjects never/too-long-ago successfully screened."""
        ls = self._last_sweep
        degraded = ls["failed"] > 0 or (ls["watched"] > 0 and ls["screened"] == 0)
        stale = sum(1 for r in self._watch.values() if r.last_screened_ms is None)
        return {**ls, "degraded": degraded, "unscreened_subjects": stale}
