"""Validate the self-contained acv_unseal.py extractor end to end (subprocess, offline path)."""
import base64
import os
import subprocess
import sys
import tempfile

from algovoi_records_vault_container import licensing
licensing.require_license = lambda: {"type": "test"}

from algovoi_doc_archive import signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_records_vault_container import build_crl, seal_container

D = tempfile.mkdtemp()
ipk, isk = signing.generate_keypair()
rpk, rsk = generate_mlkem_keypair()
DOCS = [{"name": "report.txt", "data": b"quarterly report " + os.urandom(40)}]
acv = os.path.join(D, "c.acv")
seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
               container_id="C-EXT", out_path=acv, require_revocation_check=True)

sk_file = os.path.join(D, "sk.b64"); open(sk_file, "w").write(base64.b64encode(rsk).decode())
crl_clean = os.path.join(D, "clean.crl"); open(crl_clean, "w").write(build_crl(issuer_public_key=ipk, issuer_secret_key=isk, revoked=[]))
crl_rev = os.path.join(D, "rev.crl"); open(crl_rev, "w").write(
    build_crl(issuer_public_key=ipk, issuer_secret_key=isk,
              revoked=[{"container_id": "C-EXT", "revoked_at": "2026-07-07T00:00:00Z", "reason": "test"}]))

import algovoi_records_vault_container as _pkg  # locate the extractor via the (installed or src) package
ext = os.path.join(os.path.dirname(_pkg.__file__), "acv_unseal.py")
env = dict(os.environ, PYTHONPATH="")  # extractor must NOT need algovoi packages


def run(args):
    return subprocess.run([sys.executable, ext, *args], capture_output=True, text=True, env=env)

P = F = 0
def ok(name, cond, r=None):
    global P, F
    if cond: P += 1; print(f"  PASS {name}")
    else: F += 1; print(f"  FAIL {name}" + (f"\n    stdout={r.stdout}\n    stderr={r.stderr}" if r else ""))

out = os.path.join(D, "out")
r = run([acv, "--key", "@" + sk_file, "--revocation-list", "@" + crl_clean, "--out", out])
unsealed = os.path.join(out, "report.txt")
ok("extractor unseals with clean CRL (exit 0)", r.returncode == 0, r)
ok("extractor: content byte-exact", os.path.exists(unsealed) and open(unsealed, "rb").read() == DOCS[0]["data"])
ok("extractor: no algovoi import needed", "algovoi" not in (r.stderr + r.stdout).lower() or "VERIFIED" in r.stdout)

r = run([acv, "--key", "@" + sk_file, "--revocation-list", "@" + crl_rev, "--out", os.path.join(D, "o2")])
ok("extractor refuses REVOKED (exit != 0)", r.returncode != 0 and "revoked" in r.stderr.lower(), r)

r = run([acv, "--key", "@" + sk_file, "--out", os.path.join(D, "o3")])
ok("extractor refuses required-but-missing CRL", r.returncode != 0 and "revocation" in r.stderr.lower(), r)

_, wrong = generate_mlkem_keypair()
wf = os.path.join(D, "wrong.b64"); open(wf, "w").write(base64.b64encode(wrong).decode())
r = run([acv, "--key", "@" + wf, "--revocation-list", "@" + crl_clean, "--out", os.path.join(D, "o4")])
ok("extractor refuses wrong recipient key", r.returncode != 0, r)

# recovery via the extractor: reconstruct from k Shamir shares, no recipient key
acv_r = os.path.join(D, "cr.acv")
mr = seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
                    container_id="C-XR", out_path=acv_r, require_revocation_check=False,
                    recovery={"threshold_k": 2, "total_n": 3})
sh = mr["recovery"]["shares"]
r = run([acv_r, "--recover-share", sh[0], "--recover-share", sh[1], "--out", os.path.join(D, "orX")])
ok("extractor recovers with 2/3 shares (no key)",
   r.returncode == 0 and open(os.path.join(D, "orX", "report.txt"), "rb").read() == DOCS[0]["data"], r)
r = run([acv_r, "--recover-share", sh[0], "--out", os.path.join(D, "orX2")])
ok("extractor recovery fails with 1 share", r.returncode != 0, r)

# --genkey: recipient generates their own keypair, sender seals to it, recipient opens with it
gp = os.path.join(D, "reci")
r = run(["--genkey", gp])
ok("genkey writes pk + sk", r.returncode == 0 and os.path.exists(gp + "_pk.b64") and os.path.exists(gp + "_sk.b64"), r)
gpk = base64.b64decode(open(gp + "_pk.b64").read())
gacv = os.path.join(D, "gen.acv")
seal_container(documents=DOCS, recipient_public_key=gpk, issuer_public_key=ipk, issuer_secret_key=isk,
               container_id="C-GEN", out_path=gacv, require_revocation_check=False)
r = run([gacv, "--key", "@" + gp + "_sk.b64", "--out", os.path.join(D, "go")])
ok("open with genkey-produced key", r.returncode == 0
   and open(os.path.join(D, "go", "report.txt"), "rb").read() == DOCS[0]["data"], r)

# path-traversal (zip-slip): seal_container refuses unsafe names, so hand-craft a validly-signed
# malicious container (simulating a compromised issuer) and prove the EXTRACTOR independently refuses
# it (defense in depth) and writes NOTHING outside --out.
import hashlib, io, tarfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from algovoi_doc_archive.encryption import HybridPqcEncryptor

def _craft(doc_name, data, out_path, cid="C-EVIL"):
    cek = os.urandom(32)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("docs/" + doc_name); ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tar_bytes = buf.getvalue()
    payload = {
        "type": "acv_container", "version": "1", "container_id": cid, "title": None,
        "issuer_kid": signing.kid_for(ipk), "issuer_pub_b64": signing.public_key_b64(ipk),
        "created_at": "2026-07-07T00:00:00Z", "expires_at": None,
        "recipient_kid": hashlib.sha256(rpk).hexdigest()[:16],
        "docs": [{"name": doc_name, "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                  "has_receipt": False}],
        "wrapped_cek_b64": signing.b64u_encode(HybridPqcEncryptor(rpk).encrypt(cek)),
        "revocation": {"registry": "default", "required": False},
        "recovery": {"enabled": False}, "escrow": {"enabled": False},
        "kem": "ML-KEM-1024", "cipher": "AES-256-GCM",
    }
    hb = signing.make_envelope(payload, isk, ipk).encode()
    nonce = os.urandom(12)
    ct = AESGCM(cek).encrypt(nonce, tar_bytes, hashlib.sha256(hb).digest())
    open(out_path, "wb").write(b"ACV1\0" + len(hb).to_bytes(4, "big") + hb + nonce + ct)

evil = os.path.join(D, "evil.acv")
_craft("../PWNED_by_extractor.txt", b"pwn", evil)
escape = os.path.join(D, "PWNED_by_extractor.txt")           # sits in the PARENT of --out
r = run([evil, "--key", "@" + sk_file, "--out", os.path.join(D, "evilout")])
ok("extractor refuses path-traversal doc name", r.returncode != 0 and "traversal" in r.stderr.lower(), r)
ok("extractor wrote NOTHING outside --out", not os.path.exists(escape), r)

# and a validly-crafted SAFE nested name still opens fine (guard is not over-broad)
safe = os.path.join(D, "safe.acv")
_craft("sub/dir/ok.txt", b"okdata", safe, cid="C-SAFE")
r = run([safe, "--key", "@" + sk_file, "--out", os.path.join(D, "safeout")])
ok("extractor opens a safe nested name",
   r.returncode == 0 and open(os.path.join(D, "safeout", "sub", "dir", "ok.txt"), "rb").read() == b"okdata", r)

# B1: loud issuer-pin warning when --expect-issuer is absent; silent when pinned
r = run([acv, "--key", "@" + sk_file, "--revocation-list", "@" + crl_clean, "--out", os.path.join(D, "b1w")])
ok("extractor warns when issuer not pinned", r.returncode == 0 and "not pinned" in r.stderr.lower(), r)
kid = signing.kid_for(ipk)
r = run([acv, "--key", "@" + sk_file, "--expect-issuer", kid, "--revocation-list", "@" + crl_clean, "--out", os.path.join(D, "b1p")])
ok("extractor does not warn when pinned", r.returncode == 0 and "not pinned" not in r.stderr.lower(), r)

# C3: stale CRL refused; fresh CRL accepted
acv_fr = os.path.join(D, "fr.acv")
seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
               container_id="C-FR", out_path=acv_fr, require_revocation_check=True)
stale_f = os.path.join(D, "stale.crl")
open(stale_f, "w").write(build_crl(issuer_public_key=ipk, issuer_secret_key=isk, revoked=[], updated_at="2000-01-01T00:00:00Z"))
r = run([acv_fr, "--key", "@" + sk_file, "--revocation-list", "@" + stale_f, "--out", os.path.join(D, "c3s")])
ok("extractor refuses a stale CRL", r.returncode != 0 and "stale" in r.stderr.lower(), r)
fresh_f = os.path.join(D, "fresh.crl")
open(fresh_f, "w").write(build_crl(issuer_public_key=ipk, issuer_secret_key=isk, revoked=[], updated_at="2099-01-01T00:00:00Z"))
r = run([acv_fr, "--key", "@" + sk_file, "--revocation-list", "@" + fresh_f, "--out", os.path.join(D, "c3f")])
ok("extractor opens with a fresh CRL", r.returncode == 0, r)

# G1: opaque names — extractor writes under the RESTORED real name
acv_op = os.path.join(D, "op.acv")
seal_container(documents=[{"name": "secret-report.pdf", "data": b"z" * 20}], recipient_public_key=rpk,
               issuer_public_key=ipk, issuer_secret_key=isk, container_id="C-OP", out_path=acv_op,
               require_revocation_check=False, opaque_names=True, title="TOPSECRET")
opout = os.path.join(D, "opout")
r = run([acv_op, "--key", "@" + sk_file, "--out", opout])
ok("extractor restores real name from an opaque container",
   r.returncode == 0 and os.path.exists(os.path.join(opout, "secret-report.pdf")), r)
ok("opaque: real filename not printed by the extractor", "secret-report.pdf" not in r.stdout, r)

print(f"\n{P} passed, {F} failed")
sys.exit(1 if F else 0)
