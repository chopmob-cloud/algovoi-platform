"""Appliance end-to-end: watch -> baseline -> subject becomes sanctioned -> signed delta, via the API."""
from __future__ import annotations

from fastapi.testclient import TestClient

from algovoi_sanctions_monitor import DenylistScreener, signing, verify_monitor_receipt
from algovoi_sanctions_monitor.encryption import generate_mlkem_keypair
from algovoi_sanctions_monitor.service import MonitorService, create_app


def _service(tmp_path):
    pk, sk = signing.generate_keypair()
    mpk, msk = generate_mlkem_keypair()
    scr = DenylistScreener()
    svc = MonitorService(secret_key=sk, public_key=pk, screener=scr,
                         mlkem_public_key=mpk, mlkem_secret_key=msk,
                         db_path=str(tmp_path / "m.db"), monitor_did="did:web:acme")
    return pk, scr, svc


def test_appliance_watch_sweep_delta(tmp_path):
    pk, scr, svc = _service(tmp_path)
    app = create_app(svc, api_token="tok", sweep_interval_secs=10_000_000)   # long: scheduler won't interfere
    with TestClient(app) as c:
        H = {"Authorization": "Bearer tok"}
        ref = c.post("/v1/watch", json={"network": "base", "address": "0xBAD"}, headers=H).json()["subject_ref"]

        assert c.post("/v1/sweep", headers=H).json()["count"] == 0           # baseline, no delta

        scr.deny.add("0xBAD")                                                # becomes sanctioned
        out = c.post("/v1/sweep", headers=H).json()
        assert out["count"] == 1 and out["deltas"][0]["transition"] == "newly_hit"
        assert verify_monitor_receipt(out["deltas"][0]["receipt_envelope"], pk).verified

        wl = c.get("/v1/watchlist", headers=H).json()["watchlist"]
        assert wl[0]["subject_ref"] == ref and "address" not in wl[0] and wl[0]["last_result"] == "DENY"
        assert c.get("/v1/deltas", headers=H).json()["deltas"][0]["transition"] == "newly_hit"

        assert c.post("/v1/sweep").status_code == 401                        # auth required
        assert c.get("/healthz").json()["watched"] == 1


async def test_appliance_state_persists_across_restart(tmp_path):
    """Watchlist + baseline survive a 'restart' (new MonitorService on the same DB) -> no spurious deltas."""
    db = tmp_path / "m.db"
    pk, sk = signing.generate_keypair()
    mpk, msk = generate_mlkem_keypair()
    scr = DenylistScreener(deny={"0xBAD"})

    svc = MonitorService(secret_key=sk, public_key=pk, screener=scr, mlkem_public_key=mpk,
                         mlkem_secret_key=msk, db_path=str(db), monitor_did="did:web:acme")
    ref = svc.watch(network="base", address="0xBAD")
    await svc.sweep()                                                        # baseline DENY persisted
    svc.store.close()

    # restart: fresh service, same DB + keys -> hydrates baseline, no change -> no delta
    svc2 = MonitorService(secret_key=sk, public_key=pk, screener=scr, mlkem_public_key=mpk,
                          mlkem_secret_key=msk, db_path=str(db), monitor_did="did:web:acme")
    assert svc2.count() == 1 and svc2.status()[0]["subject_ref"] == ref
    assert await svc2.sweep() == []                                         # steady state after restart
