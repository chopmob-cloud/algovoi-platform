"""Phase-d test (standalone, runnable): auth gate + RBAC + signed console audit chain.

Run: python tests/test_auth_rbac.py   (needs fastapi, httpx, python-multipart, pqcrypto, rfc8785)
"""
import base64
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from algovoi_command_center import licensing as _lic  # noqa: E402
_lic.require_license = lambda: {"test": True}

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def main():
    work = tempfile.mkdtemp(prefix="ccd-")
    os.environ.update(
        COMMAND_CENTER_INGEST_DIR=work, COMMAND_CENTER_ESTATE="test",
        COMMAND_CENTER_SECRET="test-secret", COMMAND_CENTER_ADMIN_USER="admin",
        COMMAND_CENTER_ADMIN_PASS="s3cret!",
        COMMAND_CENTER_USERS_FILE=os.path.join(work, "users.json"),
        COMMAND_CENTER_KEY_FILE=os.path.join(work, "key.json"),
        COMMAND_CENTER_AUDIT_FILE=os.path.join(work, "audit.json"))

    from fastapi.testclient import TestClient
    from algovoi_command_center import roles
    from algovoi_command_center.auth import hash_password, load_users, save_users
    from algovoi_command_center.app import create_app

    users = load_users()
    ph, sa = hash_password("look")
    users["val"] = {"pwd": ph, "salt": sa, "role": roles.VIEWER}
    save_users(users)

    noredir = TestClient(create_app(), follow_redirects=False)
    check("unauthenticated dashboard redirects to login", noredir.get("/").status_code == 303)
    check("bad credentials rejected (401)",
          noredir.post("/login", data={"username": "admin", "password": "x"}).status_code == 401)
    r = noredir.post("/login", data={"username": "admin", "password": "s3cret!"})
    check("good login sets a session cookie", r.status_code == 303 and "cc_session" in r.headers.get("set-cookie", ""))

    admin = TestClient(create_app())
    admin.post("/login", data={"username": "admin", "password": "s3cret!"})
    check("admin sees the dashboard", "Compliance Command Center" in admin.get("/").text)
    # exporting an auditor pack is step-up gated: without a fresh re-check it redirects to /verify
    check("export without step-up redirects to verify",
          admin.get("/export", follow_redirects=False).status_code == 303)
    admin.post("/verify", data={"next": "/export", "password": "s3cret!"})
    check("admin can export after step-up", admin.get("/export").status_code == 200)

    viewer = TestClient(create_app())
    viewer.post("/login", data={"username": "val", "password": "look"})
    vd = viewer.get("/").text
    check("viewer sees dashboard but not the export button",
          "Compliance Command Center" in vd and "Export auditor pack" not in vd)
    check("viewer is forbidden from exporting (403)", viewer.get("/export").status_code == 403)
    check("viewer is forbidden from the audit log (403)", viewer.get("/audit").status_code == 403)

    ap = admin.get("/audit").text
    check("console audit records actions + verifies",
          "audit chain verified" in ap and "view_dashboard" in ap and "export_auditor_pack" in ap)

    af = os.environ["COMMAND_CENTER_AUDIT_FILE"]
    arr = json.load(open(af))
    raw = json.loads(base64.urlsafe_b64decode(arr[0] + "==" * 2))
    raw["payload"]["action"] = "FORGED"
    arr[0] = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
    json.dump(arr, open(af, "w"))
    check("tampered console audit chain is detected", "audit chain verified" not in admin.get("/audit").text)

    shutil.rmtree(work, ignore_errors=True)
    print(f"\n=== PHASE-D (auth/RBAC/audit) RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
