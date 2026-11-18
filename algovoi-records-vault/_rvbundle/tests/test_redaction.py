"""F4 redaction + crypto-shred test (standalone, runnable): redacted derivation, proof, field erasure.

Run: python algovoi-records-vault/tests/test_redaction.py
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

from algovoi_records_vault import (  # noqa: E402
    RecordsVault, crypto_shred, redact, seal_fields, unseal_field, verify_derivation,
)

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
    outer["payload"]["redacted_fields"] = []
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-redact-")
    pk, sk = signing.generate_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive)
    rl = vault.redaction()

    record = {"name": "Jane Roe", "ssn": "123-45-6789", "dob": "1980-02-02",
              "diagnosis": "ICD-10 J45", "note": "stable"}

    # plain redact (remove)
    red, done = redact(record, fields=["ssn", "dob"], method="remove")
    check("redact(remove) drops the tagged fields", "ssn" not in red and "dob" not in red and "diagnosis" in red)
    check("redact returns the list of redacted fields", set(done) == {"ssn", "dob"})

    # redact + signed derivation record
    redacted, rec = await rl.redact_record(original_data=record, fields=["ssn"], reason="disclosure",
                                            method="mask")
    check("redact_record masks the field", redacted["ssn"] == "[REDACTED]")
    check("derivation verifies against original + redacted", verify_derivation(rec["payload"], record, redacted) is True)
    check("derivation FAILS if the redacted copy was altered",
          verify_derivation(rec["payload"], record, {**redacted, "ssn": "123-45-6789"}) is False)

    # crypto-shred: seal fields under per-field keys, recover, then erase one key
    sealed, keymap = seal_fields(record, fields=["ssn", "dob"])
    check("sealed fields are replaced by ciphertext cells",
          isinstance(sealed["ssn"], dict) and sealed["ssn"].get("__sealed__") is True)
    check("a sealed field recovers byte-identically with its key",
          unseal_field(sealed, keymap, "ssn") == b"123-45-6789")

    shredded = crypto_shred(keymap, "ssn")
    check("crypto_shred drops the field key", shredded is True)
    raised = False
    try:
        unseal_field(sealed, keymap, "ssn")
    except KeyError:
        raised = True
    check("a crypto-shredded field is permanently unrecoverable", raised)
    check("an un-shredded sealed field still recovers", unseal_field(sealed, keymap, "dob") == b"1980-02-02")
    check("the ciphertext cell survives shredding (proof of existence)", sealed["ssn"].get("__sealed__") is True)

    # signed shred record
    await rl.record_shred(doc_hash_value="sha256:" + "11" * 32, field="ssn", reason="erasure request")
    events = [p["redaction_event"] for p in await rl.records()]
    check("redaction stream holds the redact + shred records", events == ["redact", "crypto_shred"])

    # integrity + tamper-evidence
    vr = await rl.verify_chain()
    check("redaction stream verifies valid", vr.valid)
    tamper(os.path.join(tmp, "archive", "redaction", "000000000000.json"))
    vr = await rl.verify_chain()
    check("tampered redaction record detected", (not vr.valid) and vr.broken_at == 0)

    print(f"\n=== REDACTION RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
