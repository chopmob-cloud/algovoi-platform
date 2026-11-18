"""F5 consent-receipt test (standalone, runnable): grant/revoke append-only, authorization, expiry.

Run: python algovoi-records-vault/tests/test_consent.py
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

from algovoi_records_vault import Principal, RecordsVault, verify_consent  # noqa: E402

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
    outer["payload"]["authorized_uses"] = ["*"]   # try to widen the granted scope
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-consent-")
    pk, sk = signing.generate_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive)
    cl = vault.consent()

    terms = {"doc": "HIPAA Authorization", "version": "1.0", "text": "I authorise use of my records."}
    g = await cl.grant(subject_ref="patient-1", terms=terms,
                       authorized_uses=["treatment", "payment"], expires_at="2099-01-01T00:00:00Z",
                       principal=Principal(did="did:web:patient/1"))
    cid = g["consent_id"]
    check("grant recorded with a consent_id", bool(cid))

    check("is_authorized TRUE for a granted use", (await cl.is_authorized(subject_ref="patient-1", use="treatment")) is True)
    check("is_authorized FALSE for a non-granted use", (await cl.is_authorized(subject_ref="patient-1", use="research")) is False)
    check("is_authorized FALSE for a different subject", (await cl.is_authorized(subject_ref="patient-2", use="treatment")) is False)

    receipt = g["payload"]
    check("verify_consent TRUE for the exact terms", verify_consent(receipt, terms) is True)
    check("verify_consent FALSE if the terms differ",
          verify_consent(receipt, {**terms, "version": "2.0"}) is False)

    check("status active before revocation", (await cl.status(cid)) == "active")

    # revoke — append-only (the grant is preserved)
    await cl.revoke(consent_id=cid, reason="patient withdrew")
    check("status revoked after revocation", (await cl.status(cid)) == "revoked")
    check("is_authorized FALSE after revocation", (await cl.is_authorized(subject_ref="patient-1", use="treatment")) is False)
    payloads = await cl.receipts()
    check("grant + revoke both retained (append-only)",
          [p["consent_event"] for p in payloads] == ["grant", "revoke"])

    # expiry
    g2 = await cl.grant(subject_ref="patient-9", terms="short consent",
                        authorized_uses=["treatment"], expires_at="2020-01-01T00:00:00Z")
    check("expired consent reports status expired",
          (await cl.status(g2["consent_id"], now=datetime(2026, 1, 1, tzinfo=timezone.utc))) == "expired")
    check("expired consent is not authorized",
          (await cl.is_authorized(subject_ref="patient-9", use="treatment",
                                  now=datetime(2026, 1, 1, tzinfo=timezone.utc))) is False)

    # revoking an unknown consent is refused
    try:
        await cl.revoke(consent_id="no-such")
        check("revoke of unknown consent refused", False)
    except ValueError:
        check("revoke of unknown consent refused", True)

    # chain integrity + tamper-evidence
    vr = await cl.verify_chain()
    check("consent ledger verifies valid", vr.valid)
    tamper(os.path.join(tmp, "archive", "consent", "000000000000.json"))
    vr = await cl.verify_chain()
    check("tampered consent grant detected", (not vr.valid) and vr.broken_at == 0)

    # ── fail-closed guarantees (Tier-1 audit fixes) ──────────────────────────────────────────
    from algovoi_records_vault.vault import ChainIntegrityError
    from algovoi_records_vault.consent import _not_expired

    # the consent/ chain is tampered above — authorization must now REFUSE, not return a benign bool
    try:
        await cl.is_authorized(subject_ref="patient-1", use="treatment")
        check("is_authorized over a tampered consent chain raises ChainIntegrityError", False)
    except ChainIntegrityError:
        check("is_authorized over a tampered consent chain raises ChainIntegrityError", True)
    try:
        await cl.status("anything")
        check("status() over a tampered consent chain raises ChainIntegrityError", False)
    except ChainIntegrityError:
        check("status() over a tampered consent chain raises ChainIntegrityError", True)

    # write-time validation: malformed expiry rejected
    try:
        await cl.grant(subject_ref="p", terms="t", authorized_uses=["x"], expires_at="nope")
        check("consent grant() rejects a malformed expires_at", False)
    except ValueError:
        check("consent grant() rejects a malformed expires_at", True)

    _n = datetime(2026, 1, 1, tzinfo=timezone.utc)
    check("consent _not_expired: malformed expiry fails closed", _not_expired("garbage", _n) is False)
    check("consent _not_expired: absent expiry valid", _not_expired(None, _n) is True)

    # ── tier-3 input hygiene (#3 identity, #4 consent) ───────────────────────────────────────
    try:
        Principal(did="")
        check("Principal rejects an empty did", False)
    except ValueError:
        check("Principal rejects an empty did", True)
    for label, kw in (
        ("empty subject_ref", dict(subject_ref="", terms="t", authorized_uses=["x"])),
        ("missing terms", dict(subject_ref="s", terms=None, authorized_uses=["x"])),
        ("bare-string authorized_uses", dict(subject_ref="s", terms="t", authorized_uses="treatment")),
    ):
        try:
            await cl.grant(**kw)
            check(f"consent grant rejects {label}", False)
        except ValueError:
            check(f"consent grant rejects {label}", True)

    print(f"\n=== CONSENT RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
