"""Editions test (standalone, runnable): Health/Legal presets + vault wiring of defaults.

Run: python algovoi-records-vault/tests/test_editions.py
"""
import asyncio
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

from algovoi_records_vault import EDITIONS, RecordsVault, edition  # noqa: E402

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


async def main() -> int:
    check("two editions registered (health, legal)", set(EDITIONS) == {"health", "legal"})

    h = edition("health")
    check("health: consent in the core flow, 7-year retention",
          h.consent_in_core_flow is True and h.retention_days == 7 * 365)
    check("health: default authorized uses include treatment", "treatment" in h.default_authorized_uses)

    legal_e = edition("LEGAL")  # case-insensitive lookup
    check("legal: custody in the core flow, consent not", legal_e.custody_in_core_flow is True
          and legal_e.consent_in_core_flow is False)

    try:
        edition("insurance")
        check("unknown edition raises", False)
    except ValueError:
        check("unknown edition raises", True)

    # vault wiring: an edition supplies the holds() retention default
    tmp = tempfile.mkdtemp(prefix="rv-ed-")
    pk, sk = signing.generate_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive, edition="health")
    check("vault carries the edition preset", vault.edition is not None and vault.edition.name == "health")
    holds = vault.holds()  # no explicit retention -> from edition
    check("holds() inherits the edition retention default (7y)",
          holds.retention is not None and holds.retention.retention_days == 7 * 365)

    # explicit override still wins
    holds2 = vault.holds(retention_days=30)
    check("explicit retention_days overrides the edition default", holds2.retention.retention_days == 30)

    print(f"\n=== EDITIONS RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
