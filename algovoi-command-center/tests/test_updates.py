"""Standalone tests for the operator-controlled update mechanism (updates.py).
Run: python tests/test_updates.py    (needs pqcrypto, rfc8785, cryptography)

Verifies the security-critical properties: no egress while disabled, Falcon-signed release manifests,
host pinning to pip.algovoi.co.uk, and verify-then-install with tamper rejection. Signs test releases
with a throwaway issuer key (monkeypatched in), so the real issuer private key is never needed.
"""
import base64, hashlib, io, json, os, tarfile, tempfile

from algovoi_command_center import licensing as _cc_lic
_cc_lic.require_license = lambda: {"type": "test"}

from algovoi_command_center import updates
import rfc8785
from pqcrypto.sign.falcon_1024 import generate_keypair, sign as _falcon_sign
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

P = F = 0
def ok(n, c):
    global P, F
    if c: P += 1; print(f"  PASS {n}")
    else: F += 1; print(f"  FAIL {n}")
def raises(n, fn, exc=Exception):
    global P, F
    try:
        fn(); F += 1; print(f"  FAIL {n} (no error)")
    except exc:
        P += 1; print(f"  PASS {n}")
    except Exception as e:  # noqa: BLE001
        F += 1; print(f"  FAIL {n} (wrong error: {type(e).__name__}: {e})")

def _b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

# throwaway issuer key; point the module's verifier at it
IPK, ISK = generate_keypair()
updates._issuer_pk = lambda: IPK

def sign_release(payload, sk=ISK, pk=IPK):
    sig = _falcon_sign(sk, rfc8785.dumps(payload))
    env = {"payload": payload, "alg": "Falcon-1024",
           "kid": hashlib.sha256(pk).hexdigest()[:16], "sig": _b64u(sig)}
    return _b64u(json.dumps(env).encode())

def make_algv(cek, wheels):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        man = {"bundle": "algovoi-verifiable-compliance-suite", "version": "test",
               "wheels": [{"name": n, "sha256": hashlib.sha256(d).hexdigest()} for n, d in wheels.items()]}
        mb = json.dumps(man).encode(); ti = tarfile.TarInfo("BUNDLE_MANIFEST.json"); ti.size = len(mb)
        tf.addfile(ti, io.BytesIO(mb))
        for n, d in wheels.items():
            ti = tarfile.TarInfo("wheels/" + n); ti.size = len(d); tf.addfile(ti, io.BytesIO(d))
    nonce = os.urandom(12)
    return b"ALGV1\0" + nonce + AESGCM(cek).encrypt(nonce, buf.getvalue(), b"algovoi-onprem-bundle/v1")

D = tempfile.mkdtemp(); os.environ["COMMAND_CENTER_DATA_DIR"] = D

# 1) policy defaults to fully offline; toggling persists
pol = updates.load_policy()
ok("online checks disabled by default", pol["online_enabled"] is False)
ok("channel is host-pinned by default", updates.ALLOWED_HOST in pol["channel_url"])
updates.set_online(True)
ok("enable persists", updates.load_policy()["online_enabled"] is True)
updates.set_online(False)
ok("disable persists", updates.load_policy()["online_enabled"] is False)

# 2) while disabled: check_online refuses AND makes no network call
_fetch_calls = {"n": 0}
_orig_fetch = updates._fetch
updates._fetch = lambda *a, **k: (_fetch_calls.__setitem__("n", _fetch_calls["n"] + 1) or b"")
raises("check refused while disabled", lambda: updates.check_online(), updates.UpdatesDisabled)
ok("no egress attempted while disabled", _fetch_calls["n"] == 0)
updates._fetch = _orig_fetch

# 3) host pinning — the only egress path refuses anything but https://pip.algovoi.co.uk
raises("refuses non-allowed host", lambda: updates._fetch("https://evil.example/x", 2), updates.UpdateError)
raises("refuses http (non-tls)", lambda: updates._fetch("http://pip.algovoi.co.uk/x", 2), updates.UpdateError)

# 4) release manifest verification
good = {"type": "algovoi_release_manifest", "channel": "vcs",
        "bundle": "algovoi-verifiable-compliance-suite", "version": "9.9.9",
        "released_at": "2026-07-07T00:00:00Z", "notes": "test",
        "wheels": [{"name": "algovoi_command_center-9.9.9-py3-none-any.whl", "sha256": "00"}]}
ok("valid signed manifest verifies", updates.verify_release(sign_release(good)) is not None)
bad = dict(good); tampered = sign_release(good)
# tamper the payload after signing -> signature must fail
env = json.loads(base64.urlsafe_b64decode(tampered + "==="))
env["payload"]["version"] = "0.0.1"
tam = _b64u(json.dumps(env).encode())
ok("tampered manifest rejected", updates.verify_release(tam) is None)
WPK, WSK = generate_keypair()
ok("wrong-key manifest rejected", updates.verify_release(sign_release(good, WSK, WPK)) is None)
ok("wrong type rejected", updates.verify_release(sign_release({**good, "type": "x"})) is None)

# 5) version diff vs what is installed (command-center itself is installed)
ups = updates._diff(good)
ok("newer wheel shows as an upgrade", any(u["package"] == "algovoi-command-center" for u in ups))
older = {**good, "wheels": [{"name": "algovoi_command_center-0.0.1-py3-none-any.whl", "sha256": "00"}]}
ok("older wheel is not an upgrade", updates._diff(older) == [])

# 6) apply: verify-then-install (do_install=False so pip never runs on the dummy wheel)
cek = os.urandom(32)
wheel_bytes = b"PK\x03\x04 dummy wheel " + os.urandom(64)
wname = "algovoi_command_center-9.9.9-py3-none-any.whl"
algv = make_algv(cek, {wname: wheel_bytes})
licence = _b64u(json.dumps({"payload": {"cek_b64": base64.b64encode(cek).decode()}}).encode())
manifest = sign_release({**good, "bundle_sha256": hashlib.sha256(algv).hexdigest(),
                         "wheels": [{"name": wname, "version": "9.9.9",
                                     "sha256": hashlib.sha256(wheel_bytes).hexdigest()}]})
rep = updates.apply_release(manifest, algv, licence_key=licence, do_install=False)
ok("apply verifies + stages the wheel", rep["wheels"] == [wname] and rep["installed"] is False)

# tamper cases must fail closed
bad_bundle = sign_release({**good, "bundle_sha256": "deadbeef" * 8,
                           "wheels": [{"name": wname, "sha256": hashlib.sha256(wheel_bytes).hexdigest()}]})
raises("wrong bundle sha256 rejected",
       lambda: updates.apply_release(bad_bundle, algv, licence_key=licence, do_install=False), updates.UpdateError)
bad_wheel = sign_release({**good, "bundle_sha256": hashlib.sha256(algv).hexdigest(),
                          "wheels": [{"name": wname, "sha256": "00" * 32}]})
raises("wrong wheel sha256 rejected",
       lambda: updates.apply_release(bad_wheel, algv, licence_key=licence, do_install=False), updates.UpdateError)
wrong_cek = _b64u(json.dumps({"payload": {"cek_b64": base64.b64encode(os.urandom(32)).decode()}}).encode())
raises("wrong licence CEK rejected",
       lambda: updates.apply_release(manifest, algv, licence_key=wrong_cek, do_install=False), updates.UpdateError)
raises("unsigned/garbage manifest rejected",
       lambda: updates.apply_release("garbage", algv, licence_key=licence, do_install=False), updates.UpdateError)

# 7) offline apply from files, no network
ap = os.path.join(D, "u.algv"); open(ap, "wb").write(algv)
_orig = updates._fetch
updates._fetch = lambda *a, **k: (_ for _ in ()).throw(AssertionError("offline apply must not use the network"))
rep2 = updates.apply_offline(manifest, ap, licence_key=licence, do_install=False)
ok("offline apply works with no network", rep2.get("offline") is True and rep2["wheels"] == [wname])
updates._fetch = _orig

# 8) state() never touches the network
_orig = updates._fetch
updates._fetch = lambda *a, **k: (_ for _ in ()).throw(AssertionError("state() must not use the network"))
st = updates.state()
ok("state() reports policy + inventory offline", st["online_enabled"] is False and "algovoi-command-center" in st["installed"])
updates._fetch = _orig

print(f"\n{P} passed, {F} failed")
raise SystemExit(1 if F else 0)
