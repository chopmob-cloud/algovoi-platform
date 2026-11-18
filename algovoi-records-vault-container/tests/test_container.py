"""Standalone test runner for algovoi-records-vault-container. Run: python tests/test_container.py
Monkeypatches the licence gate (as the other suite packages' standalone tests do)."""
import asyncio
import os
import sys
import tempfile

from algovoi_records_vault_container import licensing
licensing.require_license = lambda: {"type": "test"}  # noqa: E305 — bypass fail-closed gate in tests
from algovoi_doc_archive import licensing as _da_lic
_da_lic.require_license = lambda: {"type": "test"}     # doc-archive gate (Archive ctor) in tests

from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.backend import LocalFsBackend
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair
from algovoi_records_vault_container import (
    build_crl, open_container, read_header, recover_container, recover_via_escrow, seal_container,
    seal_from_archive, verify_crl, is_revoked,
)

P = F = 0
def ok(name, cond):
    global P, F
    if cond: P += 1; print(f"  PASS {name}")
    else: F += 1; print(f"  FAIL {name}")
def raises(name, fn, needle=None):
    global P, F
    try:
        fn(); F += 1; print(f"  FAIL {name} (no error raised)")
    except Exception as exc:  # noqa: BLE001
        if needle and needle.lower() not in str(exc).lower():
            F += 1; print(f"  FAIL {name} (wrong error: {exc})")
        else:
            P += 1; print(f"  PASS {name}")

D = tempfile.mkdtemp()
ipk, isk = signing.generate_keypair()                 # issuer (Falcon)
rpk, rsk = generate_mlkem_keypair()                    # recipient (ML-KEM)
_, wrong_sk = generate_mlkem_keypair()                 # a different recipient
DOCS = [{"name": "a.txt", "data": b"alpha record " + os.urandom(32)},
        {"name": "b.txt", "data": b"beta record " + os.urandom(64)}]

# 1) seal + open roundtrip (no revocation required)
c1 = os.path.join(D, "c1.acv")
man = seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk,
                     issuer_secret_key=isk, container_id="C-1", out_path=c1,
                     require_revocation_check=False, title="test")
hdr, got = open_container(c1, recipient_secret_key=rsk)
ok("roundtrip: 2 docs recovered", set(got) == {"a.txt", "b.txt"})
ok("roundtrip: bytes match", got["a.txt"] == DOCS[0]["data"] and got["b.txt"] == DOCS[1]["data"])
ok("manifest: sha256 + ids", man["documents"] == 2 and man["container_id"] == "C-1" and man["issuer_kid"] == hdr["issuer_kid"])
ok("read_header without decrypt", read_header(c1)["container_id"] == "C-1")

# 2) wrong recipient key cannot open
raises("wrong recipient key refused", lambda: open_container(c1, recipient_secret_key=wrong_sk))

# 3) tamper the ciphertext -> AES-GCM fails
blob = bytearray(open(c1, "rb").read()); blob[-1] ^= 0x01
ct1 = os.path.join(D, "ct.acv"); open(ct1, "wb").write(blob)
raises("tampered ciphertext refused", lambda: open_container(ct1, recipient_secret_key=rsk), "tamper")

# 4) tamper the header (flip a byte inside the base64url header region) -> malformed/signature fails
raw = open(c1, "rb").read()
hlen = int.from_bytes(raw[5:9], "big")
bad = bytearray(raw); bad[9 + hlen // 2] ^= 0x01
ht = os.path.join(D, "hdr.acv"); open(ht, "wb").write(bytes(bad))
raises("tampered header refused", lambda: open_container(ht, recipient_secret_key=rsk))

# 5) expiry
c_exp = os.path.join(D, "exp.acv")
seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
               container_id="C-EXP", out_path=c_exp, require_revocation_check=False,
               expires_at="2000-01-01T00:00:00Z")
raises("expired container refused", lambda: open_container(c_exp, recipient_secret_key=rsk), "expired")

# 6) revocation required
c2 = os.path.join(D, "c2.acv")
seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
               container_id="C-2", out_path=c2, require_revocation_check=True)
raises("required revocation + no CRL refused", lambda: open_container(c2, recipient_secret_key=rsk), "revocation")
crl_empty = build_crl(issuer_public_key=ipk, issuer_secret_key=isk, revoked=[])
hdr2, got2 = open_container(c2, recipient_secret_key=rsk, crl_env=crl_empty)
ok("required revocation + clean CRL opens", set(got2) == {"a.txt", "b.txt"})
crl_rev = build_crl(issuer_public_key=ipk, issuer_secret_key=isk,
                    revoked=[{"container_id": "C-2", "revoked_at": "2026-07-07T00:00:00Z", "reason": "test"}])
raises("revoked container refused", lambda: open_container(c2, recipient_secret_key=rsk, crl_env=crl_rev), "revoked")

# 7) CRL signed by a different key does not verify
opk, osk = signing.generate_keypair()
crl_foreign = build_crl(issuer_public_key=opk, issuer_secret_key=osk, revoked=[])
raises("foreign-signed CRL refused", lambda: open_container(c2, recipient_secret_key=rsk, crl_env=crl_foreign), "did not verify")
ok("verify_crl wrong issuer -> None", verify_crl(crl_rev, opk) is None)
ok("is_revoked positive", is_revoked("C-2", crl_rev, ipk) is True)
ok("is_revoked negative", is_revoked("C-2", crl_empty, ipk) is False)

# 8) seal_from_archive: store a doc, seal by hash, receipts verify
async def _from_archive():
    akp, ask = generate_mlkem_keypair()
    a = Archive(public_key=ipk, secret_key=isk, storage=LocalFsBackend(os.path.join(D, "arch")),
                encryptor=HybridPqcEncryptor(akp, ask))
    r = await a.notarize(data=b"archived record " + os.urandom(48), content_type="text/plain", title="rec")
    c3 = os.path.join(D, "c3.acv")
    m = await seal_from_archive(a, [r["doc_hash"]], recipient_public_key=rpk, issuer_public_key=ipk,
                                issuer_secret_key=isk, container_id="C-3", out_path=c3,
                                require_revocation_check=False)
    hdr3, got3 = open_container(c3, recipient_secret_key=rsk)          # verify_receipts=True by default
    return m, hdr3, got3
m3, hdr3, got3 = asyncio.run(_from_archive())
ok("seal_from_archive: 1 doc + receipt", m3["documents"] == 1 and hdr3["docs"][0]["has_receipt"] is True)
ok("seal_from_archive: content recovered", len(got3) == 1)

# 9) recovery: Shamir k-of-n on the CEK -> open WITHOUT the recipient key
c_rec = os.path.join(D, "rec.acv")
mrec = seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
                      container_id="C-REC", out_path=c_rec, require_revocation_check=False,
                      recovery={"threshold_k": 2, "total_n": 3})
shares = mrec["recovery"]["shares"]
ok("recovery: enabled + 3 shares issued", mrec["recovery"]["enabled"] and len(shares) == 3)
_, gotR = recover_container(c_rec, shares=shares[:2])       # any 2 of 3, no recipient key
ok("recover with 2/3 shares opens", set(gotR) == {"a.txt", "b.txt"} and gotR["a.txt"] == DOCS[0]["data"])
raises("recover with 1 share insufficient", lambda: recover_container(c_rec, shares=shares[:1]))
ok("recovery does not weaken recipient path", open_container(c_rec, recipient_secret_key=rsk)[1]["a.txt"] == DOCS[0]["data"])
raises("recover on a no-recovery container", lambda: recover_container(c1, shares=shares[:2]), "no recovery")

# recovery still honours revocation
c_rec2 = os.path.join(D, "rec2.acv")
m2 = seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
                    container_id="C-REC2", out_path=c_rec2, require_revocation_check=True,
                    recovery={"threshold_k": 2, "total_n": 2})
crl_r = build_crl(issuer_public_key=ipk, issuer_secret_key=isk,
                  revoked=[{"container_id": "C-REC2", "revoked_at": "2026-07-07T00:00:00Z", "reason": "x"}])
raises("recovery honours revocation", lambda: recover_container(c_rec2, shares=m2["recovery"]["shares"], crl_env=crl_r), "revoked")

# 10) console escrow recovery: wrap CEK to a console key -> recover with no recipient key + no shares
epk, esk = generate_mlkem_keypair()
c_esc = os.path.join(D, "esc.acv")
mesc = seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
                      container_id="C-ESC", out_path=c_esc, require_revocation_check=False, escrow_public_key=epk)
ok("escrow: enabled in manifest", mesc["escrow"]["enabled"] is True)
_, gotE = recover_via_escrow(c_esc, escrow_secret_key=esk)
ok("escrow recover opens (no recipient key/shares)", gotE["a.txt"] == DOCS[0]["data"])
raises("escrow recover wrong key fails", lambda: recover_via_escrow(c_esc, escrow_secret_key=wrong_sk), "escrow recovery failed")
raises("escrow recover on a non-escrow container", lambda: recover_via_escrow(c1, escrow_secret_key=esk), "not console-recoverable")
ok("recipient path still works on escrow container", open_container(c_esc, recipient_secret_key=rsk)[1]["a.txt"] == DOCS[0]["data"])
ok("no-escrow container reports escrow disabled", read_header(c1).get("escrow", {}).get("enabled") in (False, None))

# 11) path-traversal document names are refused fail-closed at SEAL time (zip-slip guard)
from algovoi_records_vault_container import safe_name
for bad in ["../evil.txt", "a/../../evil.txt", "/abs/evil.txt", "C:/evil.txt", "sub\\..\\evil.txt", "x\x00y"]:
    raises(f"seal rejects unsafe name {bad!r}",
           lambda b=bad: seal_container(documents=[{"name": b, "data": b"x"}], recipient_public_key=rpk,
                                        issuer_public_key=ipk, issuer_secret_key=isk,
                                        container_id="C-BAD", out_path=os.path.join(D, "bad.acv"),
                                        require_revocation_check=False))
for good in ["a.txt", "sub/dir/a.txt", "a.b.c"]:
    ok(f"safe_name allows {good!r}", safe_name(good) == good)
def _seal_ok(name):
    p = os.path.join(D, "okname.acv")
    seal_container(documents=[{"name": name, "data": b"ok"}], recipient_public_key=rpk,
                   issuer_public_key=ipk, issuer_secret_key=isk, container_id="C-OK-"+name.replace("/", "_"),
                   out_path=p, require_revocation_check=False)
    return open_container(p, recipient_secret_key=rsk)[1]
ok("nested-but-safe name seals + opens", set(_seal_ok("sub/dir/a.txt")) == {"sub/dir/a.txt"})

# 12) CRL freshness (anti-replay): a validly-signed CRL older than the container's floor is refused
c_fresh = os.path.join(D, "fresh.acv")
mf = seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
                    container_id="C-FRESH", out_path=c_fresh, require_revocation_check=True)
ok("header carries min_crl_at floor", read_header(c_fresh)["revocation"].get("min_crl_at") == mf["created_at"])
stale = build_crl(issuer_public_key=ipk, issuer_secret_key=isk, revoked=[], updated_at="2000-01-01T00:00:00Z")
raises("stale CRL (pre-container) refused", lambda: open_container(c_fresh, recipient_secret_key=rsk, crl_env=stale), "stale")
fresh = build_crl(issuer_public_key=ipk, issuer_secret_key=isk, revoked=[], updated_at="2099-01-01T00:00:00Z")
ok("fresh CRL opens", set(open_container(c_fresh, recipient_secret_key=rsk, crl_env=fresh)[1]) == {"a.txt", "b.txt"})
fresh_rev = build_crl(issuer_public_key=ipk, issuer_secret_key=isk, updated_at="2099-01-01T00:00:00Z",
                      revoked=[{"container_id": "C-FRESH", "revoked_at": "2099-01-01T00:00:00Z", "reason": "x"}])
raises("fresh CRL still enforces revocation", lambda: open_container(c_fresh, recipient_secret_key=rsk, crl_env=fresh_rev), "revoked")
# recipient freshness policy: a CRL past the header floor but older than max_crl_age_seconds is refused
import datetime as _dt
floor_old = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
c_age = os.path.join(D, "age.acv")
seal_container(documents=DOCS, recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
               container_id="C-AGE", out_path=c_age, require_revocation_check=True, min_crl_at=floor_old)
old_at = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
old_ok = build_crl(issuer_public_key=ipk, issuer_secret_key=isk, revoked=[], updated_at=old_at)  # past floor, 10d old
raises("CRL older than recipient max age refused",
       lambda: open_container(c_age, recipient_secret_key=rsk, crl_env=old_ok, max_crl_age_seconds=3600), "too old")
ok("CRL within recipient max age opens",
   set(open_container(c_age, recipient_secret_key=rsk, crl_env=old_ok, max_crl_age_seconds=30 * 86400)[1]) == {"a.txt", "b.txt"})

# 13) issuer pin (in-process): open_container binds to a known issuer_kid
from algovoi_doc_archive import signing as _sig
good_kid = _sig.kid_for(ipk)
ok("expect_issuer match opens", open_container(c1, recipient_secret_key=rsk, expect_issuer=good_kid)[1]["a.txt"] == DOCS[0]["data"])
raises("expect_issuer mismatch refused", lambda: open_container(c1, recipient_secret_key=rsk, expect_issuer="deadbeefdeadbeef"), "does not match")

# 14) opaque names: header hides names + title; body restores real names
c_op = os.path.join(D, "opaque.acv")
seal_container(documents=[{"name": "patient-jane-doe.pdf", "data": b"phi " + os.urandom(40)},
                          {"name": "diagnosis.txt", "data": b"dx " + os.urandom(40)}],
               recipient_public_key=rpk, issuer_public_key=ipk, issuer_secret_key=isk,
               container_id="C-OPAQUE", out_path=c_op, require_revocation_check=False,
               title="SENSITIVE", opaque_names=True)
hop = read_header(c_op)
hdr_names = [d["name"] for d in hop["docs"]]
ok("opaque: header names are opaque ids", all(n.startswith("d") and n[1:].isdigit() for n in hdr_names))
ok("opaque: title hidden + flag set", hop.get("title") is None and hop.get("names_opaque") is True)
ok("opaque: real filenames not in cleartext header", "patient-jane-doe.pdf" not in read_header(c_op).__str__())
_, gotop = open_container(c_op, recipient_secret_key=rsk)
ok("opaque: real names restored on open", set(gotop) == {"patient-jane-doe.pdf", "diagnosis.txt"})

print(f"\n{P} passed, {F} failed")
sys.exit(1 if F else 0)
