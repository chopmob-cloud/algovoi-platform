"""PKCS#11 adapter test — exercises the python-pkcs11 session API shape via an in-process fake HSM
(no SoftHSM needed). The fake's get_key(label=).encrypt/decrypt use a local AES-256-GCM key (the
'HSM-resident KEK'). Validates wrap -> sign/encrypt through the HSM-backed Signer/Encryptor -> verify
-> round-trip. Run:  python tests/test_pkcs11.py

For real-HSM validation, point the same adapter at a SoftHSM token (see README).
"""
import asyncio, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
PLATFORM = os.path.dirname(PKG)
sys.path[:0] = [
    f"{PLATFORM}/algovoi-doc-archive/src",
    f"{PKG}/src",
    f"{PLATFORM}/algovoi-records-vault/free-verifier",   # algovoi_verify (free verifier)
]

from algovoi_doc_archive import licensing as _bl; _bl.require_license = lambda: {"t": 1}
import algovoi_doc_archive_pkcs11.licensing as _pl; _pl.require_license = lambda: {"t": 1}

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.backend import LocalFsBackend
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_doc_archive_pkcs11 import pkcs11_wrap, pkcs11_signer, pkcs11_encryptor
import algovoi_verify as V

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


class _FakeHsmKey:
    """In-process stand-in for an HSM-resident AES key (the KEK never leaves this object)."""
    def __init__(self):
        self._a = AESGCM(os.urandom(32))

    def encrypt(self, data):
        n = os.urandom(12)
        return n + self._a.encrypt(n, bytes(data), None)

    def decrypt(self, blob):
        blob = bytes(blob)
        return self._a.decrypt(blob[:12], blob[12:], None)


class _FakeSession:
    def __init__(self):
        self._k = _FakeHsmKey()

    def get_key(self, label=None):
        return self._k


async def _run(session):
    KL = "algovoi-kek"
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()

    w_sign = pkcs11_wrap(sk, session=session, key_label=KL)
    w_enc = pkcs11_wrap(kem_sk, session=session, key_label=KL)
    check("wrapped blobs differ from raw keys", w_sign != sk and w_enc != kem_sk)

    signer = pkcs11_signer(pk, w_sign, session=session, key_label=KL)
    enc = pkcs11_encryptor(kem_pk, w_enc, session=session, key_label=KL)

    tmp = tempfile.mkdtemp()
    arch = Archive(signer=signer, encryptor=enc, storage=LocalFsBackend(f"{tmp}/a"))
    data = b"document under PKCS#11 HSM key custody"
    out = await arch.notarize(data=data, title="hsm-1")

    check("document round-trips (HSM-unwrapped decrypt)", (await arch.retrieve(doc_hash=out["doc_hash"])) == data)
    chain = await arch.list_entries()
    check("HSM-signed receipt verifies via the free verifier", V.verify_receipt(chain[0], pk)[0] is True)
    other_pk, _ = signing.generate_keypair()
    check("receipt rejected under the wrong key", V.verify_receipt(chain[0], other_pk)[0] is False)
    check("enc_alg is post-quantum hybrid", out["enc_alg"] == "ML-KEM-1024+AES-256-GCM")


def _error_paths():
    """Audit fix #9: HSM unwrap failures / empty results surface as Pkcs11AdapterError."""
    from algovoi_doc_archive_pkcs11 import pkcs11_signer
    from algovoi_doc_archive_pkcs11.hsm import Pkcs11AdapterError

    pk, _sk = signing.generate_keypair()

    class _Key:
        def __init__(self, mode):
            self._mode = mode
        def decrypt(self, blob):
            if self._mode == "raise":
                raise RuntimeError("CKR_KEY_HANDLE_INVALID")
            return b""  # empty plaintext

    class _Session:
        def __init__(self, mode):
            self._k = _Key(mode)
        def get_key(self, label=None):
            return self._k

    wrapped = False
    try:
        pkcs11_signer(pk, b"w", session=_Session("raise"), key_label="k").sign(b"m")
    except Pkcs11AdapterError as e:
        wrapped = "CKR_KEY_HANDLE_INVALID" in str(e)
    check("PKCS#11 adapter wraps an HSM unwrap failure in Pkcs11AdapterError", wrapped)

    empty = False
    try:
        pkcs11_signer(pk, b"w", session=_Session("empty"), key_label="k").sign(b"m")
    except Pkcs11AdapterError:
        empty = True
    check("PKCS#11 adapter raises on empty HSM plaintext", empty)


def main():
    asyncio.run(_run(_FakeSession()))
    _error_paths()
    print(f"\n=== PKCS11-ADAPTER RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
