"""
The continuous-monitor appliance: the engine + the PQC-at-rest store + a daily sweep loop + a loopback
API. Deploy one container with the SQLite DB on a persistent volume; it monitors the watchlist and emits
signed delta receipts on every status change.
"""
from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timezone

from pydantic import BaseModel

from algovoi_sanctions_monitor import signing
from algovoi_sanctions_monitor.encryption import HybridPqcEncryptor
from algovoi_sanctions_monitor.monitor import SanctionsMonitor
from algovoi_sanctions_monitor.screener import Screener
from algovoi_sanctions_monitor.store import WatchlistStore


class WatchReq(BaseModel):
    network: str
    address: str
    note: str = ""


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


class MonitorService:
    """Bridges the in-memory engine and the persistent PQC store."""

    def __init__(self, *, secret_key: bytes, public_key: bytes, screener: Screener,
                 mlkem_public_key: bytes, mlkem_secret_key: bytes, db_path: str,
                 monitor_did: str = "did:web:monitor.example") -> None:
        self.engine = SanctionsMonitor(secret_key=secret_key, public_key=public_key,
                                       screener=screener, monitor_did=monitor_did)
        self.store = WatchlistStore(db_path, HybridPqcEncryptor(mlkem_public_key, mlkem_secret_key))
        self.public_key = public_key
        self.kid = self.engine.kid
        # hydrate engine from the persisted store (restores baseline)
        self.engine.hydrate([(net, addr, last, fw) for _ref, net, addr, last, fw in self.store.subjects()])

    def watch(self, *, network: str, address: str, note: str = "") -> str:
        ref = self.engine.watch(network=network, address=address, note=note)
        fw = next((s["first_watched_ms"] for s in self.engine.watchlist() if s["subject_ref"] == ref), _now_ms())
        self.store.add(subject_ref=ref, network=network, address=address, first_watched_ms=fw, note=note)
        return ref

    def unwatch(self, subject_ref_: str) -> bool:
        self.engine.unwatch(subject_ref_)
        return self.store.remove(subject_ref_)

    async def sweep(self) -> list[dict]:
        deltas = await self.engine.sweep()
        now = _now_ms()
        for st in self.engine.watchlist():                          # persist updated verdicts (no PII)
            if st["last_result"] is not None:
                self.store.set_result(st["subject_ref"], st["last_result"], st["last_screened_ms"] or now)
        for d in deltas:                                            # log signed deltas
            self.store.log_delta(subject_ref=d["subject_ref"], transition=d["transition"],
                                 envelope=d["receipt_envelope"], receipt_hash=d["receipt_hash"], created_ms=now)
        return deltas

    def status(self) -> list[dict]:
        return self.store.status()

    def recent_deltas(self, limit: int = 100) -> list[dict]:
        return self.store.recent_deltas(limit)

    def count(self) -> int:
        return self.store.count()

    def sweep_health(self) -> dict:
        """Screening-feed health (delegates to the engine) so a dead/stale feed is visible via /healthz."""
        return self.engine.sweep_health()

    def verify_delta_chain(self, *, expected_head: dict | None = None) -> dict:
        """Verify the tamper-evident delta-receipt chain is intact and not truncated."""
        return self.store.verify_delta_chain(expected_head=expected_head)


async def _sweep_loop(service: MonitorService, interval_secs: int) -> None:
    while True:
        with contextlib.suppress(Exception):
            await service.sweep()                                   # fires immediately, then every interval
        await asyncio.sleep(interval_secs)


def create_app(service: MonitorService, *, api_token: str | None = None, sweep_interval_secs: int = 86_400):
    import hmac

    from fastapi import Depends, FastAPI, Header, HTTPException

    def auth(authorization: str = Header(default="")) -> None:
        # SECURITY (2026-08-19): constant-time compare so the token cannot be recovered by response timing.
        # (A falsy api_token is a no-op — the serve target only allows that on a loopback bind.)
        if api_token and not hmac.compare_digest(authorization, f"Bearer {api_token}"):
            raise HTTPException(status_code=401, detail="unauthorized")

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(_sweep_loop(service, sweep_interval_secs))
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="AlgoVoi Sanctions Monitor", lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict:
        # Surface screening-feed health: `degraded` flags a dead/stale feed so monitoring-stopped is visible.
        health = service.sweep_health()
        return {"ok": not health["degraded"], "watched": service.count(), "kid": service.kid,
                "feed": health}

    @app.get("/v1/pubkey")
    async def pubkey() -> dict:
        return {"kid": service.kid, "alg": "Falcon-1024",
                "public_key_b64": signing.public_key_b64(service.public_key)}

    @app.post("/v1/watch", dependencies=[Depends(auth)])
    async def watch(req: WatchReq) -> dict:
        return {"subject_ref": service.watch(network=req.network, address=req.address, note=req.note)}

    @app.delete("/v1/watch/{subject_ref}", dependencies=[Depends(auth)])
    async def unwatch(subject_ref: str) -> dict:
        return {"removed": service.unwatch(subject_ref)}

    @app.get("/v1/watchlist", dependencies=[Depends(auth)])
    async def watchlist() -> dict:
        return {"watchlist": service.status()}

    @app.post("/v1/sweep", dependencies=[Depends(auth)])
    async def sweep() -> dict:
        deltas = await service.sweep()
        return {"count": len(deltas), "deltas": deltas}

    @app.get("/v1/deltas", dependencies=[Depends(auth)])
    async def deltas(limit: int = 100) -> dict:
        return {"deltas": service.recent_deltas(limit)}

    return app
