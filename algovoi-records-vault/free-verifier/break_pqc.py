"""Adversarial break harness for AlgoVoi's PQC evidence layer — LOCAL, offline.

Tries to make the verifier do the WRONG thing: accept a forgery/tamper (false-accept),
or crash on hostile input. RESISTED = the attack failed (good). BROKEN = the verifier
accepted something it must not (bad). EXPECTED-ACCEPT = a documented property, not a bug.

Run: python break_pqc.py
"""
import asyncio, base64, contextlib, copy, io, json, os, random, shutil, sys, tempfile, unicodedata, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")
sys.path.insert(0, HERE)

from algovoi_doc_archive import licensing as base_licensing
base_licensing.require_license = lambda: {"test": True}
from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.backend import LocalFsBackend
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair
from algovoi_records_vault import licensing as rv_licensing
rv_licensing.require_license = lambda: {"test": True}
from algovoi_records_vault import Principal, RecordsVault
from algovoi_records_vault.vault import ACCESS_PREFIX, ACCESS_TYPE, TSA_PREFIX, TSA_TYPE, _VaultStream
import algovoi_verify as V

REG_URL = "https://api.algovoi.co.uk/.well-known/algovoi-product-keys.json"
RESULTS = []  # (category, attack, outcome, detail)


def rec(cat, attack, outcome, detail=""):
    RESULTS.append((cat, attack, outcome, detail))


def quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **k)


def reg_verifies(doc):
    """True if the verifier ACCEPTS this registry doc."""
    p = os.path.join(HERE, "_atk_reg.json")
    json.dump(doc, open(p, "w", encoding="utf-8"))
    try:
        return quiet(V.verify_product_registry, p) == 0
    finally:
        os.remove(p)


def expect_reject(cat, attack, accepted, expected_accept=False):
    if expected_accept:
        rec(cat, attack, "EXPECTED-ACCEPT" if accepted else "ANOMALY", "documented self-signed property")
    else:
        rec(cat, attack, "BROKEN" if accepted else "RESISTED")


# ───────────────────────── registry attacks ─────────────────────────
def registry_attacks(reg):
    # R1: tamper a value inside the signed payload
    d = copy.deepcopy(reg); k = d["payload"]["algovoi_operated_keys"][0]
    k["public_key"] = ("A" if k["public_key"][0] != "A" else "B") + k["public_key"][1:]
    expect_reject("registry", "R1 tamper signed payload byte", reg_verifies(d))

    # R2: tamper the signature
    d = copy.deepcopy(reg); s = d["sig"]; d["sig"] = ("A" if s[0] != "A" else "B") + s[1:]
    expect_reject("registry", "R2 tamper signature", reg_verifies(d))

    # R3: substitute attacker public key, keep original signature
    apk, ask = signing.generate_keypair()
    d = copy.deepcopy(reg); d["public_key_pqclean_b64"] = base64.b64encode(apk).decode()
    expect_reject("registry", "R3 substitute pubkey, keep sig", reg_verifies(d))

    # R4: kid not matching its public key
    d = copy.deepcopy(reg); d["kid"] = "deadbeefdeadbeef"
    expect_reject("registry", "R4 kid != sha256(pubkey)", reg_verifies(d))

    # R5: algorithm downgrade — claim alg=none and supply garbage sig
    d = copy.deepcopy(reg); d["alg"] = "none"; d["sig"] = base64.urlsafe_b64encode(b"\x00" * 64).decode()
    expect_reject("registry", "R5 downgrade alg=none + junk sig", reg_verifies(d))

    # R6: full re-sign with an attacker key over a forged payload (self-signed)
    apk, ask = signing.generate_keypair()
    payload = copy.deepcopy(reg["payload"]); payload["algovoi_operated_keys"][0]["name"] = "ATTACKER"
    sig = signing.sign_bytes(ask, V.jcs(payload))
    d = {"alg": "Falcon-1024", "kid": signing.kid_for(apk) if hasattr(signing, "kid_for") else
         __import__("hashlib").sha256(apk).hexdigest()[:16],
         "payload": payload, "public_key_pqclean_b64": base64.b64encode(apk).decode(),
         "sig": base64.urlsafe_b64encode(sig).decode().rstrip("=")}
    expect_reject("registry", "R6 full re-sign w/ attacker key (self-signed)",
                  reg_verifies(d), expected_accept=True)


# ───────────────────────── receipt / chain attacks ─────────────────────────
def receipt_attacks(chain, pk, other_chain, other_pk):
    # C1: tamper a receipt's signed content
    env = chain[0]
    payload, sig, _ = signing.open_envelope(env)
    bad = copy.deepcopy(payload); bad["_x"] = "tampered"
    forged = json.dumps({"payload": bad, "sig": signing.b64u_encode(sig),
                         "pk": signing.public_key_b64(pk)})
    try:
        ok = quiet(V.verify_receipt, signing.b64u_encode(forged.encode()), pk)[0]
        expect_reject("receipt", "C1 tamper signed payload", bool(ok))
    except Exception as e:
        rec("receipt", "C1 tamper signed payload", "RESISTED", f"rejected: {type(e).__name__}")

    # C2: genuine receipt under the wrong key
    ok = quiet(V.verify_receipt, chain[0], other_pk)[0]
    expect_reject("receipt", "C2 genuine receipt, wrong key", bool(ok))

    # C3: signature malleability — flip bits in the signature
    payload, sig, _ = signing.open_envelope(chain[0])
    msig = bytearray(sig); msig[len(msig) // 2] ^= 0x01
    ok = quiet(V.falcon_ok, pk, V.jcs(payload), bytes(msig))
    expect_reject("receipt", "C3 signature bit-flip (malleability)", bool(ok))

    # C4: full forgery — attacker signs a payload, presents under victim key
    payload, _, _ = signing.open_envelope(chain[0])
    afk_pk, afk_sk = signing.generate_keypair()
    env = signing.make_envelope(payload, afk_sk, afk_pk)
    ok = quiet(V.verify_receipt, env, pk)[0]
    expect_reject("receipt", "C4 forge under attacker key, verify as victim", bool(ok))

    # C5: chain reorder
    if len(chain) >= 2:
        reordered = [chain[1], chain[0]] + list(chain[2:])
        ok = quiet(V.verify_chain, reordered, pk)[0]
        expect_reject("chain", "C5 reorder entries", bool(ok))

    # C6: drop the head entry
    if len(chain) >= 2:
        ok = quiet(V.verify_chain, chain[1:], pk)[0]
        # dropping head may be legal (tail still links); only BROKEN if it hides a real break.
        rec("chain", "C6 drop head entry", "ACCEPTED" if ok else "RESISTED",
            "informational: does verifier notice a missing prefix?")

    # C7: cross-chain splice — insert an entry signed in another chain
    if other_chain:
        spliced = list(chain[:1]) + [other_chain[0]] + list(chain[1:])
        ok = quiet(V.verify_chain, spliced, pk)[0]
        expect_reject("chain", "C7 splice foreign entry", bool(ok))

    # C8: duplicate JSON key in a signed payload (canonicalization confusion)
    payload, sig, _ = signing.open_envelope(chain[0])
    raw = json.dumps(payload)
    raw_dup = raw[:-1] + ', "decision": "granted"}' if not raw.rstrip().endswith("}}") else raw
    env_dup = signing.b64u_encode(json.dumps(
        {"payload_raw": raw_dup}).encode())  # malformed shape on purpose
    try:
        ok = quiet(V.verify_receipt, env_dup, pk)[0]
        expect_reject("canon", "C8 duplicate-key / malformed payload", bool(ok))
    except Exception as e:
        rec("canon", "C8 duplicate-key / malformed payload", "RESISTED", f"rejected: {type(e).__name__}")


# ───────────────────────── fuzz / robustness ─────────────────────────
def fuzz_attacks(pk):
    cases = {
        "F1 empty string": "",
        "F2 not base64": "!!!!not-b64!!!!",
        "F3 b64 of non-JSON": signing.b64u_encode(b"\xff\x00\xfegarbage"),
        "F4 b64 of JSON list": signing.b64u_encode(b"[1,2,3]"),
        "F5 truncated envelope": signing.b64u_encode(b'{"payload":{"a":1},"sig":"AA'),
        "F6 huge payload": signing.b64u_encode(json.dumps({"x": "A" * 2_000_000}).encode()),
    }
    for name, env in cases.items():
        try:
            ok = quiet(V.verify_receipt, env, pk)[0]
            rec("fuzz", name, "BROKEN" if ok else "RESISTED",
                "" if not ok else "verifier ACCEPTED hostile input")
        except Exception as e:
            rec("fuzz", name, "CRASH", f"{type(e).__name__}: {str(e)[:60]}")


# ───────────────────────── deep fuzz / property-based ─────────────────────────
def _mutate(raw):
    b = bytearray(raw)
    for _ in range(random.randint(1, 4)):
        i = random.randrange(len(b)); b[i] ^= 1 << random.randrange(8)
    return bytes(b)


def fuzz_property(chain, pk, reg, iters=3000):
    # A break = the verifier accepts a receipt whose SIGNED CONTENT (jcs payload) differs from
    # the original. Accepts where jcs(payload) is unchanged are cosmetic (whitespace / non-signed
    # transport bytes) and are correct behaviour, not forgeries.
    p0_payload, _, _ = signing.open_envelope(chain[0]); p0 = V.jcs(p0_payload)
    raw = signing.b64u_decode(chain[0]); forge = cosmetic = cr = 0
    for _ in range(iters):
        env = signing.b64u_encode(_mutate(raw))
        try:
            ok, payload = quiet(V.verify_receipt, env, pk)
            if ok:
                if V.jcs(payload) != p0:
                    forge += 1
                else:
                    cosmetic += 1
        except Exception:
            cr += 1
    rec("deep-fuzz", f"P1 receipt random-mutation x{iters}", "BROKEN" if forge else "RESISTED",
        f"{forge} content-forgeries, {cosmetic} cosmetic-accepts, {cr} handled")

    p0r = V.jcs(reg["payload"]); rawr = json.dumps(reg).encode(); forge = cosmetic = cr = 0
    p = os.path.join(HERE, "_fz_reg.json")
    for _ in range(iters):
        try:
            open(p, "wb").write(_mutate(rawr))
            if quiet(V.verify_product_registry, p) == 0:
                d = json.load(open(p, encoding="utf-8"))
                if V.jcs(d["payload"]) != p0r:
                    forge += 1
                else:
                    cosmetic += 1
        except Exception:
            cr += 1
    if os.path.exists(p):
        os.remove(p)
    rec("deep-fuzz", f"P2 registry random-mutation x{iters}", "BROKEN" if forge else "RESISTED",
        f"{forge} content-forgeries, {cosmetic} cosmetic-accepts, {cr} handled")


def sig_sweep(chain, pk, positions=1500):
    payload, sig, _ = signing.open_envelope(chain[0])
    msg = V.jcs(payload); nbits = len(sig) * 8; fa = 0
    for _ in range(positions):
        bit = random.randrange(nbits)
        b = bytearray(sig); b[bit // 8] ^= 1 << (bit % 8)
        if quiet(V.falcon_ok, pk, msg, bytes(b)):
            fa += 1
    rec("deep-fuzz", f"P3 signature bit-flip sweep x{positions}", "BROKEN" if fa else "RESISTED",
        f"{fa} forgeries")
    t1 = quiet(V.falcon_ok, pk, msg, sig[:-1])
    t2 = quiet(V.falcon_ok, pk, msg, sig + b"\x00")
    expect_reject("deep-fuzz", "P4 signature truncate / extend", bool(t1 or t2))


def transplant(chain, pk):
    pa, sa, _ = signing.open_envelope(chain[0])
    pb, _, _ = signing.open_envelope(chain[1] if len(chain) > 1 else chain[0])
    if V.jcs(pa) == V.jcs(pb):
        rec("transplant", "P5 sig(A) on payload(B)", "SKIP", "payloads identical")
        return
    ok = quiet(V.falcon_ok, pk, V.jcs(pb), sa)
    expect_reject("transplant", "P5 sig(A) on payload(B)", bool(ok))


def canon_deep(pk, sk):
    s1 = signing.sign_bytes(sk, V.jcs({"n": 1}))
    same = signing.verify_bytes(pk, V.jcs({"n": 1.0}), s1)
    rec("canon-deep", "P6 JCS number 1 vs 1.0", "ACCEPTED" if same else "RESISTED",
        "informational: share canonical form per RFC 8785" if same else "distinct forms")
    nfc = unicodedata.normalize("NFC", "é"); nfd = unicodedata.normalize("NFD", "é")
    s = signing.sign_bytes(sk, V.jcs({"s": nfc}))
    conf = signing.verify_bytes(pk, V.jcs({"s": nfd}), s)
    expect_reject("canon-deep", "P7 unicode NFC vs NFD not conflated", bool(conf))


def json_bomb(pk, depth=4000):
    raw = ("[" * depth + "]" * depth).encode()
    env = signing.b64u_encode(raw)
    try:
        ok = quiet(V.verify_receipt, env, pk)[0]
        rec("deep-fuzz", f"P8 deeply-nested JSON x{depth}", "BROKEN" if ok else "RESISTED")
    except RecursionError:
        rec("deep-fuzz", f"P8 deeply-nested JSON x{depth}", "CRASH", "uncaught RecursionError")
    except Exception as e:
        rec("deep-fuzz", f"P8 deeply-nested JSON x{depth}", "RESISTED", f"handled {type(e).__name__}")


def pack_attacks(pack, other_pack):
    # Pin the genuine pack's kid out-of-band, the way a real relying party does. Without an
    # anchor every trial would sit at exit 3 (intact but self-asserted) and a key-substitution
    # attack would read as "rejected" for the wrong reason.
    with open(os.path.join(pack, "public_key.b64"), encoding="utf-8") as fh:
        anchor_kid = V._kid(base64.b64decode(fh.read().strip()))

    if quiet(V.verify_pack, pack, anchor_kid) != 0:
        rec("pack", "baseline pack verifies", "ANOMALY", "valid pack failed to verify"); return

    def trial(name, mutate):
        d = pack + "_atk"
        if os.path.exists(d):
            shutil.rmtree(d)
        shutil.copytree(pack, d)
        mutate(d)
        accepted = quiet(V.verify_pack, d, anchor_kid) == 0
        shutil.rmtree(d)
        return accepted

    def t_tamper(d):
        f = os.path.join(d, "archive_chain.json"); b = open(f, "rb").read()
        i = len(b) // 2; open(f, "wb").write(b[:i] + bytes([b[i] ^ 1]) + b[i + 1:])
    expect_reject("pack", "P9 tamper archive chain", trial("tamper", t_tamper))

    def t_key(d):
        shutil.copy(os.path.join(other_pack, "public_key.b64"), os.path.join(d, "public_key.b64"))
    expect_reject("pack", "P10 swap in foreign public key", trial("key", t_key))

    def t_tsa(d):
        shutil.copy(os.path.join(other_pack, "tsa_chain.json"), os.path.join(d, "tsa_chain.json"))
    expect_reject("pack", "P11 splice foreign timestamp chain", trial("tsa", t_tsa))


# ───────────────────────── build valid artifacts ─────────────────────────
async def build_chain(tmp, tag, n=3):
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    storage = LocalFsBackend(os.path.join(tmp, f"arch_{tag}"))
    archive = Archive(public_key=pk, secret_key=sk, storage=storage,
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    os.environ.pop("VAULT_TSA_URL", None)
    vault = RecordsVault(archive=archive)
    for i in range(n):
        await vault.notarize(data=f"break-harness record {tag}-{i}".encode(), title=f"rec-{tag}-{i}")
    chain = await archive.list_entries()
    return chain, pk, sk


async def build_pack(tmp, tag):
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    storage = LocalFsBackend(os.path.join(tmp, f"pkstore_{tag}"))
    archive = Archive(public_key=pk, secret_key=sk, storage=storage,
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    os.environ.pop("VAULT_TSA_URL", None)
    vault = RecordsVault(archive=archive)
    out = await vault.notarize(data=f"pack record {tag}".encode(), title=f"p-{tag}")
    await vault.retrieve(doc_hash=out["archive"]["doc_hash"], principal=Principal(did="did:web:reader"))
    pack = os.path.join(tmp, f"pack_{tag}")
    os.makedirs(pack, exist_ok=True)

    async def export(etype, prefix, name):
        s = _VaultStream(storage=storage, public_key=pk, secret_key=None, entry_type=etype, prefix=prefix)
        json.dump(await s.list_entries(), open(os.path.join(pack, name), "w", encoding="utf-8"))

    json.dump(await archive.list_entries(), open(os.path.join(pack, "archive_chain.json"), "w", encoding="utf-8"))
    await export(TSA_TYPE, TSA_PREFIX, "tsa_chain.json")
    await export(ACCESS_TYPE, ACCESS_PREFIX, "access_chain.json")
    open(os.path.join(pack, "public_key.b64"), "w", encoding="utf-8").write(signing.public_key_b64(pk))
    return pack


async def main():
    tmp = tempfile.mkdtemp(prefix="breakpqc-")
    chain, pk, sk = await build_chain(tmp, "A")
    other_chain, other_pk, _ = await build_chain(tmp, "B")

    reg = None
    try:
        local = os.path.join(HERE, "reg.json")
        if os.path.exists(local):
            reg = json.load(open(local, encoding="utf-8"))
        else:
            req = urllib.request.Request(REG_URL, headers={"User-Agent": "Mozilla/5.0 (break-harness)"})
            reg = json.loads(urllib.request.urlopen(req, timeout=15).read().decode())
        registry_attacks(reg)
    except Exception as e:
        rec("registry", "fetch live registry", "SKIP", f"{type(e).__name__}: {str(e)[:60]}")

    receipt_attacks(chain, pk, other_chain, other_pk)
    fuzz_attacks(pk)

    # deep / property-based
    if reg is not None:
        fuzz_property(chain, pk, reg)
    sig_sweep(chain, pk)
    transplant(chain, pk)
    canon_deep(pk, sk)
    json_bomb(pk)
    pack_a = await build_pack(tmp, "A")
    pack_b = await build_pack(tmp, "B")
    pack_attacks(pack_a, pack_b)

    # report
    width = max(len(a) for _, a, _, _ in RESULTS)
    print("=" * 78)
    print("  ADVERSARIAL BREAK HARNESS — AlgoVoi PQC evidence layer (LOCAL)")
    print("=" * 78)
    cur = None
    for cat, attack, outcome, detail in RESULTS:
        if cat != cur:
            print(f"\n[{cat}]"); cur = cat
        mark = {"RESISTED": "ok ", "BROKEN": "XX ", "CRASH": "!! ",
                "EXPECTED-ACCEPT": "-- ", "ACCEPTED": "?? ", "SKIP": ".. ",
                "ANOMALY": "!! "}.get(outcome, "?? ")
        print(f"  {mark}{attack:<{width}}  {outcome}" + (f"   ({detail})" if detail else ""))
    broken = [r for r in RESULTS if r[2] in ("BROKEN", "CRASH", "ANOMALY")]
    accepted = [r for r in RESULTS if r[2] == "ACCEPTED"]
    print("\n" + "=" * 78)
    print(f"  RESULT: {len(broken)} broken/crash, {len(accepted)} informational-accept, "
          f"{sum(1 for r in RESULTS if r[2] == 'RESISTED')} resisted, "
          f"{sum(1 for r in RESULTS if r[2] == 'EXPECTED-ACCEPT')} expected-accept")
    print("=" * 78)
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
