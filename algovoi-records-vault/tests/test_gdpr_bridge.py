"""GDPR-bridge test (standalone, runnable): vault holds mirror onto the control_plane gate.

No network — uses a fake bridge to capture calls, and exercises the LegalHoldBridge body mapping with a
stubbed transport. Run: python algovoi-records-vault/tests/test_gdpr_bridge.py
"""
import asyncio
import os
import sys
import tempfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda: {"test": True}

from algovoi_records_vault import Principal, RecordsVault  # noqa: E402
from algovoi_records_vault.gdpr_bridge import LegalHoldBridge  # noqa: E402

PASS = 0
FAIL = 0


def check(label, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


class FakeBridge:
    """Duck-typed stand-in for LegalHoldBridge — records the mirror calls."""

    def __init__(self):
        self.calls = []

    def push_hold(self, *, matter_id, query, reason, preservation_until=None):
        self.calls.append(("set", matter_id, dict(query), reason, preservation_until))
        return {"ok": True}

    def release_hold(self, *, matter_id, query, reason):
        self.calls.append(("release", matter_id, dict(query), reason))
        return {"ok": True}


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-bridge-")
    pk, sk = signing.generate_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive)

    # --- registry mirrors place/release onto an injected bridge -----------------------------
    fb = FakeBridge()
    holds = vault.holds(retention_days=30, bridge=fb)
    q = {"subject_ref": "payer-1",
         "date_range": {"from": "2026-01-01T00:00:00Z", "to": "2026-12-31T00:00:00Z"}}
    await holds.place_hold(matter_id="MATTER-1", reason="litigation", query=q,
                           principal=Principal(did="did:web:law/counsel"))
    check("place_hold mirrors a 'set' to the bridge",
          len(fb.calls) == 1 and fb.calls[0][0] == "set" and fb.calls[0][1] == "MATTER-1")
    check("mirror carries the matter subject + scope",
          fb.calls[0][2]["subject_ref"] == "payer-1")

    # signed chain is still authoritative + intact
    check("holds chain still verifies after mirroring", (await holds.verify_chain()).valid)

    await holds.release_hold(matter_id="MATTER-1", reason="closed",
                             now=datetime(2031, 1, 1, tzinfo=timezone.utc))
    check("release_hold mirrors a 'release' to the bridge",
          any(c[0] == "release" and c[1] == "MATTER-1" for c in fb.calls))

    # a bridge failure must NOT break the signed write
    class BoomBridge:
        def push_hold(self, **k): raise RuntimeError("network down")
        def release_hold(self, **k): raise RuntimeError("network down")
    h2 = vault.holds(retention_days=30, bridge=BoomBridge())
    rec = await h2.place_hold(matter_id="M-BOOM", reason="r", query={"subject_ref": "p"})
    check("a failing bridge does not break the signed hold write", rec["seq"] >= 0
          and (await h2.is_held({"subject_ref": "p"})) is True)

    # --- LegalHoldBridge body mapping (stubbed transport) -----------------------------------
    b = LegalHoldBridge("http://cp.local", "admin-token")
    captured = {}
    b._post = lambda body: (captured.update(body) or {"affected_rows": 3})
    b.push_hold(matter_id="MATTER-2", query=q, reason="x", preservation_until="2030-01-01T00:00:00Z")
    check("bridge maps subject_ref + date scope + preservation into the POST body",
          captured.get("action") == "set" and captured.get("subject_ref") == "payer-1"
          and captured.get("date_from") == "2026-01-01T00:00:00Z"
          and captured.get("date_to") == "2026-12-31T00:00:00Z"
          and captured.get("preservation_until") == "2030-01-01T00:00:00Z")

    check("bridge is a no-op for a hold with no payer subject_ref",
          b.push_hold(matter_id="M3", query={}, reason="x") is None)

    disabled = LegalHoldBridge("http://cp.local", "")  # no token -> disabled
    check("disabled bridge (no token) is a no-op", disabled.enabled is False
          and disabled.push_hold(matter_id="M", query={"subject_ref": "s"}, reason="r") is None)

    # reconcile re-asserts every active hold idempotently
    recon = LegalHoldBridge("http://cp.local", "admin-token")
    pushed = []
    recon._post = lambda body: (pushed.append(body["matter_id"]) or {"affected_rows": 1})
    n = recon.reconcile([
        {"matter_id": "A", "query": {"subject_ref": "p1"}, "reason": "r"},
        {"matter_id": "B", "query": {"subject_ref": "p2"}, "reason": "r"},
        {"matter_id": "C", "query": {}, "reason": "r"},  # no subject -> skipped
    ])
    check("reconcile re-asserts only payer-subject holds", n == 2 and pushed == ["A", "B"])

    print(f"\n=== GDPR-BRIDGE RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
