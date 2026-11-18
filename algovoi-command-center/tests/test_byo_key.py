"""Phase-f test (standalone): the console signs its audit chain through a BYO-key Signer.

Uses the engine's WrappedKeySigner with a fake unwrap (stands in for AWS KMS / Vault / HSM), so no
real key service is needed — proves the console key can live in BYO custody behind the Signer interface.
Run: python tests/test_byo_key.py
"""
import os, sys, tempfile, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from algovoi_command_center import licensing as _lic  # noqa: E402
_lic.require_license = lambda: {"test": True}
sys.path.insert(0, os.path.join(os.path.dirname(ROOT), "algovoi-doc-archive", "src"))

PASS = FAIL = 0
def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")

def main():
    work = tempfile.mkdtemp(prefix="ccf-")
    from algovoi_doc_archive import signing
    from algovoi_doc_archive.signer import WrappedKeySigner
    from algovoi_command_center.audit import ConsoleAuditLog

    pk, sk = signing.generate_keypair()
    unwraps = {"n": 0}
    def fake_unwrap(wrapped):           # stands in for KMS/HSM Decrypt -> mutable key, zeroized after use
        unwraps["n"] += 1
        return bytearray(wrapped)
    byo = WrappedKeySigner(pk, sk, unwrap=fake_unwrap)   # 'wrapped' == sk for the test

    check("WrappedKeySigner satisfies the console Signer interface",
          hasattr(byo, "sign") and hasattr(byo, "public_key") and hasattr(byo, "kid"))

    log = ConsoleAuditLog(os.path.join(work, "audit.json"), byo)
    log.append(action="login", principal="admin", role="admin")
    log.append(action="export_auditor_pack", principal="admin", role="admin")
    ok, reason = log.verify()
    check("console audit chain signed via BYO-key verifies", ok)
    check("BYO unwrap was actually exercised at sign time", unwraps["n"] >= 2)

    # tamper -> must fail even under BYO custody
    import json, base64
    af = os.path.join(work, "audit.json"); arr = json.load(open(af))
    raw = json.loads(base64.urlsafe_b64decode(arr[0] + "==" * 2)); raw["payload"]["action"] = "FORGED"
    arr[0] = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
    json.dump(arr, open(af, "w"))
    check("tampered BYO-signed chain is detected", not ConsoleAuditLog(af, byo).verify()[0])

    # the app accepts an injected BYO signer (e.g. pkcs11 path)
    os.environ.update(COMMAND_CENTER_AUDIT_FILE=os.path.join(work, "app-audit.json"),
                      COMMAND_CENTER_USERS_FILE=os.path.join(work, "u.json"),
                      COMMAND_CENTER_SECRET="t", COMMAND_CENTER_ADMIN_USER="a", COMMAND_CENTER_ADMIN_PASS="p")
    from fastapi.testclient import TestClient
    from algovoi_command_center.app import create_app
    c = TestClient(create_app(signer=byo)); c.post("/login", data={"username": "a", "password": "p"})
    check("app runs with an injected BYO signer; /audit verifies", "audit chain verified" in c.get("/audit").text)

    shutil.rmtree(work, ignore_errors=True)
    print(f"\n=== PHASE-F (BYO-key custody) RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0

if __name__ == "__main__":
    raise SystemExit(main())
