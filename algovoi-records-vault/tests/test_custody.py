"""F6 custody-manifest test (standalone, runnable): batch attestation, custodian handoff, gap detection.

Run: python algovoi-records-vault/tests/test_custody.py
"""
import asyncio
import json
import os
import sys
import tempfile

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

from algovoi_records_vault import RecordsVault, make_custody_attestation, verify_custody_attestation  # noqa: E402

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
    outer["payload"]["prev_custodian_did"] = "did:web:imposter"
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-custody-")
    pk, sk = signing.generate_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive)
    cu = vault.custody()

    cust_a = "did:web:law.example/custodian-a"
    cust_b = "did:web:vendor.example/custodian-b"
    a_pk, a_sk = signing.generate_keypair()   # custodian A's own Falcon key

    # custodian A attests a batch, cross-signed with A's key
    await cu.attest_batch(custodian_did=cust_a, batch_range={"from": 0, "to": 99},
                          batch_hash="sha256:" + "aa" * 32, reason="initial intake",
                          custodian_keys=(a_pk, a_sk))
    check("current custodian is A after first attestation", (await cu.current_custodian()) == cust_a)

    # handoff A -> B (names the prior custodian)
    await cu.handoff(to_custodian_did=cust_b, reason="matter transferred to e-discovery vendor")
    check("custody handed off to B", (await cu.current_custodian()) == cust_b)

    await cu.attest_batch(custodian_did=cust_b, batch_range={"from": 100, "to": 149},
                          batch_hash="sha256:" + "bb" * 32, reason="vendor load")

    check("custodian lineage is A -> B", (await cu.custodians()) == [cust_a, cust_b])

    ok, detail = await cu.verify_custody()
    check("custody chain verifies intact (handoff continuity + signatures)",
          ok and cust_b in detail)

    # the custodian-key attestation verifies offline, and a tampered one fails
    att = make_custody_attestation(custodian_did=cust_a, batch_range={"from": 0, "to": 99},
                                   batch_hash="sha256:" + "aa" * 32,
                                   custodian_secret_key=a_sk, custodian_public_key=a_pk)
    check("custodian attestation verifies", verify_custody_attestation(att) is True)
    bad = {**att, "batch_hash": "sha256:" + "cc" * 32}
    check("altered batch_hash fails the custodian signature", verify_custody_attestation(bad) is False)

    # stream integrity + tamper-evidence (forge the handoff's prev custodian)
    vr = await cu.verify_chain()
    check("custody stream verifies valid", vr.valid and vr.length == 3)
    tamper(os.path.join(tmp, "archive", "custody", "000000000001.json"))
    vr = await cu.verify_chain()
    check("tampered custody handoff detected", (not vr.valid) and vr.broken_at == 1)
    # verify_custody now gates on the signed chain (parity with the other verifiers)
    ok_t, detail_t = await cu.verify_custody()
    check("verify_custody fails over a tampered signed chain",
          ok_t is False and "chain failed" in detail_t)

    print(f"\n=== CUSTODY RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
