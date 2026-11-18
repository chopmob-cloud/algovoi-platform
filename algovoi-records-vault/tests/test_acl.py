"""F8 fine-grained ACL test (standalone, runnable): grant/revoke, resource+action match, expiry.

Run: python algovoi-records-vault/tests/test_acl.py
"""
import asyncio
import json
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

from algovoi_records_vault import RecordsVault  # noqa: E402

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
    outer["payload"]["actions"] = ["*"]   # try to escalate the grant
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-acl-")
    pk, sk = signing.generate_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive)
    acl = vault.acl()

    dr = "did:web:clinic/dr-jones"
    nurse = "did:web:clinic/nurse-amy"
    doc = "sha256:" + "11" * 32

    await acl.grant(principal_did=dr, resource=doc, actions=["read", "notarize"], granted_by="admin")
    check("granted principal may read the resource", (await acl.check(principal_did=dr, resource=doc, action="read")) is True)
    check("granted principal may notarize", (await acl.check(principal_did=dr, resource=doc, action="notarize")) is True)
    check("granted principal may NOT do an ungranted action", (await acl.check(principal_did=dr, resource=doc, action="delete")) is False)
    check("ungranted principal is denied", (await acl.check(principal_did=nurse, resource=doc, action="read")) is False)
    check("granted principal denied on a different resource",
          (await acl.check(principal_did=dr, resource="sha256:" + "22" * 32, action="read")) is False)

    # wildcard resource + wildcard action
    await acl.grant(principal_did=nurse, resource="*", actions=["read"], granted_by="admin")
    check("wildcard-resource grant allows any resource",
          (await acl.check(principal_did=nurse, resource="sha256:" + "99" * 32, action="read")) is True)
    await acl.grant(principal_did="did:web:admin", resource="matter-7", actions=["*"], granted_by="admin")
    check("wildcard-action grant allows any action",
          (await acl.check(principal_did="did:web:admin", resource="matter-7", action="release")) is True)

    # expiry
    await acl.grant(principal_did="did:web:temp", resource=doc, actions=["read"],
                    granted_by="admin", expires_at="2020-01-01T00:00:00Z")
    check("expired grant denies",
          (await acl.check(principal_did="did:web:temp", resource=doc, action="read",
                           now=datetime(2026, 1, 1, tzinfo=timezone.utc))) is False)

    # revoke (append-only)
    await acl.revoke(principal_did=dr, resource=doc, reason="role change", revoked_by="admin")
    check("revoked principal is denied", (await acl.check(principal_did=dr, resource=doc, action="read")) is False)
    events = [p["acl_event"] for p in await acl.entries()]
    check("grant + revoke both retained (append-only)", events.count("grant") == 4 and events.count("revoke") == 1)

    # integrity + tamper-evidence
    vr = await acl.verify_chain()
    check("ACL stream verifies valid", vr.valid)
    tamper(os.path.join(tmp, "archive", "acl", "000000000000.json"))
    vr = await acl.verify_chain()
    check("tampered ACL grant detected", (not vr.valid) and vr.broken_at == 0)

    # ── fail-closed guarantees (Tier-1 audit fixes) ──────────────────────────────────────────
    from algovoi_records_vault.vault import ChainIntegrityError
    from algovoi_records_vault.acl import _not_expired

    # the acl/ chain is tampered above — a decision must now REFUSE, not return a benign boolean
    try:
        await acl.check(principal_did=nurse, resource="sha256:" + "99" * 32, action="read")
        check("check() over a tampered ACL chain raises ChainIntegrityError", False)
    except ChainIntegrityError:
        check("check() over a tampered ACL chain raises ChainIntegrityError", True)
    # …unless the caller opts out after verifying once (verify=False still folds the raw state)
    check("check(verify=False) still answers (opt-out path intact)",
          isinstance(await acl.check(principal_did=nurse, resource="sha256:" + "99" * 32,
                                     action="read", verify=False), bool))

    # write-time validation: a malformed expiry is rejected so it can never reach the decision path
    try:
        await acl.grant(principal_did="did:web:x", resource=doc, actions=["read"],
                        granted_by="admin", expires_at="not-a-date")
        check("grant() rejects a malformed expires_at", False)
    except ValueError:
        check("grant() rejects a malformed expires_at", True)

    # decision-time expiry is fail-closed: absent = valid, unparseable = treated as expired
    _n = datetime(2026, 1, 1, tzinfo=timezone.utc)
    check("_not_expired: absent expiry is not expired", _not_expired(None, _n) is True)
    check("_not_expired: malformed expiry fails closed (expired)", _not_expired("garbage", _n) is False)
    check("_not_expired: future expiry is not expired", _not_expired("2099-01-01T00:00:00Z", _n) is True)
    check("_not_expired: past expiry is expired", _not_expired("2020-01-01T00:00:00Z", _n) is False)

    print(f"\n=== ACL RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
