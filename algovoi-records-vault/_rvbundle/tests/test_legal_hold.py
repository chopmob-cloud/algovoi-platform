"""F2 legal-hold test (standalone, runnable): set/release, query match, retention override, integrity.

Run: python algovoi-records-vault/tests/test_legal_hold.py
"""
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

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

from algovoi_records_vault import HoldActive, Principal, RecordsVault  # noqa: E402

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


def tamper(path):
    with open(path, "rb") as fh:
        outer = json.loads(signing.b64u_decode(fh.read().decode()))
    outer["payload"]["action"] = "release"   # try to forge a release
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(
            json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-hold-")
    pk, sk = signing.generate_keypair()
    # holds don't need an encryptor (no blob retrieval involved)
    archive = Archive(public_key=pk, secret_key=sk,
                      storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive)

    counsel = Principal(did="did:web:law.example/counsel", kid="bar-1", scopes=("legal:hold",))
    holds = vault.holds(retention_days=30)   # 30-day preservation floor + retention window

    # records under test (different subjects / dates / types)
    rec_in = {"subject_ref": "patient-42", "content_type": "application/dicom",
              "archived_at": "2026-03-01T00:00:00Z", "doc_hash": "sha256:" + "11" * 32}
    rec_other_subject = {**rec_in, "subject_ref": "patient-99"}
    rec_out_of_range = {**rec_in, "archived_at": "2020-01-01T00:00:00Z"}

    # nothing held initially
    check("no holds initially", (await holds.active_holds()) == [])
    check("is_held False before any hold", (await holds.is_held(rec_in)) is False)

    # place a matter hold scoped by subject + date range
    set_rec = await holds.place_hold(
        matter_id="MATTER-2026-007", reason="anticipated litigation; preserve patient-42",
        principal=counsel,
        query={"subject_ref": "patient-42",
               "date_range": {"from": "2026-01-01T00:00:00Z", "to": "2026-12-31T00:00:00Z"}})
    check("place_hold records who set it",
          set_rec["payload"]["set_principal_did"] == "did:web:law.example/counsel")
    check("place_hold computes a release_blocked_until floor",
          set_rec["payload"]["release_blocked_until"] is not None)

    check("matching record is held", (await holds.is_held(rec_in)) is True)
    check("different subject is NOT held", (await holds.is_held(rec_other_subject)) is False)
    check("out-of-date-range record is NOT held", (await holds.is_held(rec_out_of_range)) is False)
    check("one active hold listed", len(await holds.active_holds()) == 1)

    # retention override: even past the retention window, a held record is NOT disposable
    far_future = datetime(2030, 1, 1, tzinfo=timezone.utc)
    check("held record is NOT disposable even past retention",
          (await holds.is_disposable(rec_in, now=far_future)) is False)
    check("unheld record IS disposable past retention",
          (await holds.is_disposable(rec_other_subject, now=far_future)) is True)
    check("unheld record NOT disposable before retention",
          (await holds.is_disposable(rec_other_subject,
                                     now=datetime(2026, 3, 2, tzinfo=timezone.utc))) is False)

    # early release is blocked by the preservation floor
    blocked = False
    try:
        await holds.release_hold(matter_id="MATTER-2026-007", reason="settled early",
                                 principal=counsel, now=datetime.now(timezone.utc))
    except HoldActive:
        blocked = True
    check("release blocked before the preservation window elapses", blocked)

    # releasing a non-existent matter is refused
    try:
        await holds.release_hold(matter_id="NO-SUCH", reason="x", now=datetime(2031, 1, 1, tzinfo=timezone.utc))
        check("release of an inactive matter refused", False)
    except HoldActive:
        check("release of an inactive matter refused", True)

    # release after the window: append-only, hold becomes inactive
    rel = await holds.release_hold(matter_id="MATTER-2026-007", reason="matter closed",
                                   principal=counsel, now=datetime(2031, 1, 1, tzinfo=timezone.utc))
    check("release preserves the original hold reason",
          "patient-42" in (rel["payload"]["original_hold_reason"] or ""))
    check("after release the record is no longer held", (await holds.is_held(rec_in)) is False)
    check("after release no active holds", (await holds.active_holds()) == [])
    check("after release the record becomes disposable past retention",
          (await holds.is_disposable(rec_in, now=far_future)) is True)

    # the holds stream is append-only: set + release are both retained
    payloads = await holds._stream.list_payloads()
    check("holds stream retains both set and release (append-only)",
          [p["action"] for p in payloads] == ["set", "release"])

    # chain integrity + tamper evidence
    vr = await holds.verify_chain()
    check("holds chain verifies valid", vr.valid and vr.length == 2)
    tamper(os.path.join(tmp, "archive", "holds", "000000000000.json"))
    vr = await holds.verify_chain()
    check("forged hold action detected (chain invalid at index 0)",
          (not vr.valid) and vr.broken_at == 0)

    # empty-query hold = full custodial hold over everything
    tmp2 = tempfile.mkdtemp(prefix="rv-hold2-")
    a2 = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp2, "archive")))
    v2 = RecordsVault(archive=a2)
    h2 = v2.holds()
    await h2.place_hold(matter_id="ALL", reason="org-wide freeze", query={})
    check("empty-query hold holds an arbitrary record", (await h2.is_held(rec_in)) is True)

    print(f"\n=== LEGAL-HOLD RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
