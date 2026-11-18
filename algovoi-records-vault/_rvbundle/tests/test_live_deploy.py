"""Live-deployment test: migrate a chain, then run the REAL archive HTTP service over a socket and
verify the migrated chain end-to-end through HTTP (not in-process). Build -> deploy -> verify live.

Run: python algovoi-records-vault/tests/test_live_deploy.py
"""
import asyncio
import os
import sys
import tempfile
import threading
import time

# platform dir resolved from this file's location: <ROOT>/algovoi-records-vault/tests/
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing  # noqa: E402
licensing.require_license = lambda: {"test": True}

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from algovoi_doc_archive import create_app, signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.auth import bearer_token_auth  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_records_vault import FsSource, migrate  # noqa: E402

PORT = 8799
BASE = f"http://127.0.0.1:{PORT}"
PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def seed_records(n=4):
    d = tempfile.mkdtemp(prefix="legacy_live_")
    for i in range(n):
        with open(os.path.join(d, f"rec_{i}.txt"), "wb") as f:
            f.write(f"live-deploy migrated record {i}".encode())
    return d


async def do_migration(arc_dir):
    pk, sk = signing.generate_keypair()
    arc = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(arc_dir))
    res = await migrate(arc, FsSource(seed_records(4)), mode="bridge")
    return pk, res


def main():
    print("=== 1. migrate 4 records into an archive (bridge mode) ===")
    arc_dir = tempfile.mkdtemp(prefix="pqc_live_")
    pk, res = asyncio.run(do_migration(arc_dir))
    check("migration notarized 4 records", res.notarized == 4)

    print("=== 2. deploy the REAL archive service (uvicorn, read-only over the migrated chain) ===")
    app = create_app(
        Archive(public_key=pk, storage=LocalFsBackend(arc_dir)),  # read-only: no secret_key
        public_key=pk,
        auth_dependency=bearer_token_auth("live-tok"),
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    ready = False
    for _ in range(60):
        try:
            if httpx.get(f"{BASE}/health", timeout=1).status_code == 200:
                ready = True
                break
        except Exception:
            pass
        time.sleep(0.25)
    check("service is live (GET /health 200)", ready)

    try:
        print("=== 3. verify the migrated chain THROUGH the live HTTP service ===")
        vc = httpx.get(f"{BASE}/v1/archive/verify-chain", timeout=10).json()
        check("GET /v1/archive/verify-chain -> valid:true", vc.get("valid") is True)

        keys = httpx.get(f"{BASE}/.well-known/pqc-keys.json", timeout=10).json()
        served_kid = (keys.get("keys", [{}])[0].get("kid") if keys.get("keys") else keys.get("kid"))
        check("published pqc-keys kid matches our key", served_kid == signing.kid_for(pk))

        print("=== 4. fetch entry 0 over HTTP and verify its signature OFFLINE ===")
        e0 = httpx.get(f"{BASE}/v1/archive/entry/0", timeout=10)
        check("GET /v1/archive/entry/0 -> 200", e0.status_code == 200)
        body = e0.json()
        receipt_env = body.get("receipt") if isinstance(body, dict) else None
        if receipt_env:
            payload, sig, _kid = signing.open_envelope(receipt_env)
            check("entry-0 receipt verifies offline against the published key",
                  signing.verify_payload(payload, sig, pk) is True)
            check("entry-0 is a migrated record (metadata.migrated_from set)",
                  "migrated_from" in (payload.get("metadata") or {}))
        else:
            check("entry-0 carried a verifiable receipt", False)
    finally:
        server.should_exit = True
        time.sleep(0.5)

    print(f"\n=== LIVE-DEPLOY RESULT: {PASS} passed, {FAIL} failed ===")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
