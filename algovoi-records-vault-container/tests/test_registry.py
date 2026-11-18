"""Registry (the create/revoke engine the CCC drives) — standalone runner."""
import os
import sys
import tempfile

from algovoi_records_vault_container import licensing
licensing.require_license = lambda: {"type": "test"}

from algovoi_doc_archive import signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_records_vault_container import ContainerRegistry, open_container

P = F = 0
def ok(name, cond):
    global P, F
    if cond: P += 1; print(f"  PASS {name}")
    else: F += 1; print(f"  FAIL {name}")
def raises(name, fn, needle=None):
    global P, F
    try:
        fn(); F += 1; print(f"  FAIL {name} (no error)")
    except Exception as exc:  # noqa: BLE001
        P += (needle is None or needle.lower() in str(exc).lower())
        if not (needle is None or needle.lower() in str(exc).lower()):
            F += 1; print(f"  FAIL {name} (wrong error: {exc})")
        else:
            print(f"  PASS {name}")

D = tempfile.mkdtemp()
ipk, isk = signing.generate_keypair()
rpk, rsk = generate_mlkem_keypair()
reg = ContainerRegistry(index_path=os.path.join(D, "idx.jsonl"), out_dir=os.path.join(D, "acv"),
                        issuer_public_key=ipk, issuer_secret_key=isk, registry="health")

DOCS = [{"name": "record1.txt", "data": b"patient record one " + os.urandom(40)},
        {"name": "record2.txt", "data": b"patient record two " + os.urandom(40)}]
man = reg.create(documents=DOCS, recipient_public_key=rpk, container_id="acv-001", title="Q3 disclosure")
ok("create returns manifest", man["container_id"] == "acv-001" and man["documents"] == 2)
ok("posture: 1 issued 0 revoked", reg.posture() == {"issued": 1, "revoked": 0, "active": 1})
ok("list hides server path", reg.list_containers()[0].get("path") is None and reg.list_containers()[0]["container_id"] == "acv-001")
raises("duplicate id refused", lambda: reg.create(documents=DOCS, recipient_public_key=rpk, container_id="acv-001"), "exists")

acv_path = man["path"]
# clean CRL -> opens
hdr, got = open_container(acv_path, recipient_secret_key=rsk, crl_env=reg.current_crl())
ok("opens under clean CRL", set(got) == {"record1.txt", "record2.txt"})

# revoke -> CRL now lists it -> extractor/open refuses
r = reg.revoke("acv-001", reason="superseded")
ok("revoke returns revoked=True", r["revoked"] is True and r["revoked_at"])
ok("posture: 1 issued 1 revoked", reg.posture() == {"issued": 1, "revoked": 1, "active": 0})
raises("revoked container refused after revoke", lambda: open_container(acv_path, recipient_secret_key=rsk, crl_env=reg.current_crl()), "revoked")

# persistence: a fresh registry over the same index sees the revocation
reg2 = ContainerRegistry(index_path=os.path.join(D, "idx.jsonl"), out_dir=os.path.join(D, "acv"),
                         issuer_public_key=ipk, issuer_secret_key=isk, registry="health")
ok("reload sees revocation", reg2.posture() == {"issued": 1, "revoked": 1, "active": 0})
raises("reloaded CRL still revokes", lambda: open_container(acv_path, recipient_secret_key=rsk, crl_env=reg2.current_crl()), "revoked")

print(f"\n{P} passed, {F} failed")
sys.exit(1 if F else 0)
