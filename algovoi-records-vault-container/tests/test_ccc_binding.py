import os, sys, tempfile
D = tempfile.mkdtemp()
os.environ["COMMAND_CENTER_CONTAINER_DIR"] = os.path.join(D, "cc-containers")

# bypass fail-closed licence gates (as suite standalone tests do)
import algovoi_records_vault_container.licensing as _l1; _l1.require_license = lambda: {"type": "test"}
import algovoi_doc_archive.licensing as _l2; _l2.require_license = lambda: {"type": "test"}
import algovoi_command_center.licensing as _l3; _l3.require_license = lambda: {"type": "test"}

from algovoi_doc_archive import signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_command_center.audit import LocalSigner
from algovoi_command_center import containers
from algovoi_records_vault_container import open_container

P = F = 0
def ok(n, c):
    global P, F
    P += bool(c); F += (not c); print(("  PASS " if c else "  FAIL ") + n)
def raises(n, fn, needle=None):
    global P, F
    try: fn(); F += 1; print("  FAIL " + n + " (no error)")
    except Exception as e:
        good = needle is None or needle.lower() in str(e).lower()
        P += good; F += (not good); print(("  PASS " if good else f"  FAIL {n} ({e})") + (n if good else ""))

ipk, isk = signing.generate_keypair()
signer = LocalSigner(ipk, isk)
rpk, rsk = generate_mlkem_keypair()
import base64
reg = containers.get_registry(signer)
ok("registry available via console signer", reg is not None)

out = containers.create_from_request(reg, {
    "recipient_public_key_b64": base64.b64encode(rpk).decode(),
    "title": "board minutes",
    "documents": [{"name": "m1.txt", "data_b64": base64.b64encode(b"minutes one").decode()},
                  {"name": "m2.txt", "data_b64": base64.b64encode(b"minutes two").decode()}],
})
ok("CCC create -> container", out["documents"] == 2 and out["container_id"])
acv = out["download_path"]
hdr, got = open_container(acv, recipient_secret_key=rsk, crl_env=reg.current_crl())
ok("opens under CCC-signed clean CRL", set(got) == {"m1.txt", "m2.txt"} and got["m1.txt"] == b"minutes one")
ok("CCC posture 1/1/0", containers.posture(reg) == {"issued": 1, "revoked": 0, "active": 1})

reg.revoke(out["container_id"], reason="console test")
raises("revoked -> extractor refuses (CCC-signed CRL)",
       lambda: open_container(acv, recipient_secret_key=rsk, crl_env=reg.current_crl()), "revoked")
ok("CCC posture after revoke 1/0/1", containers.posture(reg) == {"issued": 1, "revoked": 1, "active": 0})

# CCC create with recovery policy -> returns one-time shares -> recover without recipient key
from algovoi_records_vault_container import recover_container
out2 = containers.create_from_request(reg, {
    "recipient_public_key_b64": base64.b64encode(rpk).decode(),
    "title": "with recovery",
    "recovery": {"threshold_k": 2, "total_n": 3},
    "documents": [{"name": "r.txt", "data_b64": base64.b64encode(b"recoverable").decode()}],
})
ok("CCC create returns 3 one-time recovery shares", out2.get("recovery", {}).get("total_n") == 3 and len(out2["recovery"]["shares"]) == 3)
acv2 = out2["download_path"]
_, gotr = recover_container(acv2, shares=out2["recovery"]["shares"][:2], crl_env=reg.current_crl())
ok("recover CCC container with 2/3 shares (no recipient key)", gotr["r.txt"] == b"recoverable")

# CCC console-escrow: create console_recoverable -> recover 100% from the console (no shares/recipient key)
out3 = containers.create_from_request(reg, {
    "recipient_public_key_b64": base64.b64encode(rpk).decode(),
    "title": "console recoverable",
    "console_recoverable": True,
    "documents": [{"name": "e.txt", "data_b64": base64.b64encode(b"escrowed doc").decode()}],
})
ok("CCC create console_recoverable=True", out3.get("console_recoverable") is True)
rec = containers.recover_from_console(reg, out3["container_id"])
ok("CCC recovers 100% from console escrow key",
   rec["documents"][0]["name"] == "e.txt" and base64.b64decode(rec["documents"][0]["data_b64"]) == b"escrowed doc")

# app builds + routes registered
try:
    from fastapi.testclient import TestClient
    from algovoi_command_center.app import create_app
    # reset module registry so the app builds its own
    containers._REGISTRY = None
    app = create_app(signer=signer)
    client = TestClient(app)
    ok("app /health 200", client.get("/health").status_code == 200)
    r = client.get("/containers", follow_redirects=False)
    ok("/containers route exists (redirect to login)", r.status_code in (302, 303))
    paths = {getattr(x, "path", "") for x in app.routes}
    ok("routes registered", "/v1/containers" in paths and "/v1/containers/{container_id}/revoke" in paths
       and "/v1/containers/{container_id}/recover" in paths and "/v1/containers/crl" in paths)
except ImportError as e:
    print(f"  SKIP TestClient ({e})")

print(f"\n{P} passed, {F} failed")
sys.exit(1 if F else 0)
