"""SIEM audit-forwarding: format correctness, off-by-default, backfill, and failure isolation."""
from __future__ import annotations

import time

from algovoi_command_center import siem


_P = {"seq": 7, "recorded_at": "2026-07-07T18:00:00Z", "principal": "alice", "role": "admin",
      "action": "login_2fa", "detail": "ok", "kid": "abcd", "entry_hash": "sha256:deadbeef",
      "epoch_ms": 1783}


def test_rfc5424_format():
    line = siem.format_rfc5424(_P)
    assert line.startswith("<110>1 ") and "2026-07-07T18:00:00Z" in line   # PRI 13*8+6, version 1
    assert 'seq="7"' in line and 'principal="alice"' in line and 'entry_hash="sha256:deadbeef"' in line
    assert f"algovoi@{siem._ENTERPRISE}" in line


def test_cef_format():
    line = siem.format_cef(_P)
    assert line.startswith("CEF:0|AlgoVoi|Compliance Command Center|")
    assert "|login_2fa|login_2fa|" in line
    assert "suser=alice" in line and "cs1=7" in line and "cs2=sha256:deadbeef" in line


def test_webhook_format():
    import json
    d = json.loads(siem.format_webhook(_P))
    assert d["seq"] == 7 and d["principal"] == "alice" and d["entry_hash"] == "sha256:deadbeef"


def test_off_by_default(monkeypatch):
    for v in ("COMMAND_CENTER_SIEM_SYSLOG", "COMMAND_CENTER_SIEM_WEBHOOK"):
        monkeypatch.delenv(v, raising=False)
    f = siem.Forwarder.from_env()
    assert not f.enabled
    f.emit(_P, "sha256:x")           # no-op, no sink
    assert f.status()["enabled"] is False


class _CapSink:
    name = "cap"

    def __init__(self, fail=False):
        self.events = []
        self.fail = fail

    def send(self, e):
        if self.fail:
            raise RuntimeError("sink down")
        self.events.append(e)


def _wait(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_worker_ships_and_tracks_seq(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMAND_CENTER_SIEM_STATE", str(tmp_path / "state.json"))
    sink = _CapSink()
    f = siem.Forwarder([sink])
    f.start()
    f.emit(_P, "sha256:deadbeef")
    assert _wait(lambda: f.status()["sent"] == 1)
    assert sink.events and sink.events[0]["seq"] == 7
    assert f.status()["last_forwarded_seq"] == 7
    f.stop()


def test_sink_failure_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMAND_CENTER_SIEM_STATE", str(tmp_path / "state.json"))
    f = siem.Forwarder([_CapSink(fail=True)])
    f.start()
    f.emit(_P, "sha256:deadbeef")
    assert _wait(lambda: bool(f.status()["last_error"]))
    assert "sink down" in f.status()["last_error"]
    f.stop()


def test_backfill_only_new(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMAND_CENTER_SIEM_STATE", str(tmp_path / "state.json"))
    f = siem.Forwarder([_CapSink()])
    f.last_forwarded = 5
    payloads = [{"seq": s, "action": "x", "principal": "p", "recorded_at": "2026-07-07T00:00:00Z"}
                for s in range(8)]
    n = f.backfill(payloads, [f"sha256:{s}" for s in range(8)])
    assert n == 2                     # only seq 6 and 7 are newer than 5


def test_audit_append_survives_forwarder_failure(tmp_path, monkeypatch):
    """A broken SIEM sink must never break the signed audit append."""
    monkeypatch.setenv("COMMAND_CENTER_SIEM_STATE", str(tmp_path / "state.json"))
    from algovoi_command_center.audit import ConsoleAuditLog, LocalSigner
    from pqcrypto.sign.falcon_1024 import generate_keypair
    pk, sk = generate_keypair()
    f = siem.Forwarder([_CapSink(fail=True)])
    f.start()
    log = ConsoleAuditLog(str(tmp_path / "audit.json"), LocalSigner(pk, sk), forwarder=f)
    p = log.append(action="login", principal="alice", role="admin")
    assert p["action"] == "login"
    ok, _ = log.verify()
    assert ok                          # chain intact despite the forwarder sink failing
    f.stop()
