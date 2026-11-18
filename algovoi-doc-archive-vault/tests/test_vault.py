"""Vault adapter test — exercises the real transit API shape via an in-process fake (no Vault server).

The fake implements client.secrets.transit.encrypt_data / decrypt_data with a local AES-256-GCM KEK,
matching Vault transit's contract (base64 plaintext in, ``vault:v1:`` ciphertext token out). Validates
wrap -> sign/encrypt through the Vault-backed Signer/Encryptor -> verify -> round-trip. Run:
    python tests/test_vault.py
"""
import asyncio, base64, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
PLATFORM = os.path.dirname(PKG)
sys.path[:0] = [
    f"{PLATFORM}/algovoi-doc-archive/src",
    f"{PKG}/src",
    f"{PLATFORM}/algovoi-records-vault/free-verifier",   # algovoi_verify (free verifier)
]

from algovoi_doc_archive import licensing as _bl; _bl.require_license = lambda: {"t": 1}
import algovoi_doc_archive_vault.licensing as _vl; _vl.require_license = lambda: {"t": 1}

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.backend import LocalFsBackend
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_doc_archive_vault import vault_wrap, vault_signer, vault_encryptor
import algovoi_verify as V

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


class _FakeTransit:
    """Faithful in-process stand-in for Vault's transit engine (KEK never leaves this object)."""
    def __init__(self):
        self._aes = AESGCM(os.urandom(32))

    def encrypt_data(self, name, plaintext):           # plaintext: base64 str
        raw = base64.b64decode(plaintext)
        nonce = os.urandom(12)
        blob = nonce + self._aes.encrypt(nonce, raw, name.encode())
        return {"data": {"ciphertext": "vault:v1:" + base64.b64encode(blob).decode()}}

    def decrypt_data(self, name, ciphertext):
        blob = base64.b64decode(ciphertext.split("vault:v1:", 1)[1])
        nonce, ct = blob[:12], blob[12:]
        raw = self._aes.decrypt(nonce, ct, name.encode())
        return {"data": {"plaintext": base64.b64encode(raw).decode()}}


class _FakeClient:
    def __init__(self):
        self.secrets = type("S", (), {"transit": _FakeTransit()})()


async def _run(client):
    KN = "algovoi"
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()

    w_sign = vault_wrap(sk, key_name=KN, client=client)
    w_enc = vault_wrap(kem_sk, key_name=KN, client=client)
    check("transit ciphertext token, not the raw key", w_sign.startswith(b"vault:v1:") and w_sign != sk)

    signer = vault_signer(pk, w_sign, key_name=KN, client=client)
    enc = vault_encryptor(kem_pk, w_enc, key_name=KN, client=client)

    tmp = tempfile.mkdtemp()
    arch = Archive(signer=signer, encryptor=enc, storage=LocalFsBackend(f"{tmp}/a"))
    data = b"document under HashiCorp Vault transit custody"
    out = await arch.notarize(data=data, title="vault-1")

    check("document round-trips (transit-unwrapped decrypt)", (await arch.retrieve(doc_hash=out["doc_hash"])) == data)
    chain = await arch.list_entries()
    check("Vault-signed receipt verifies via the free verifier", V.verify_receipt(chain[0], pk)[0] is True)
    other_pk, _ = signing.generate_keypair()
    check("receipt rejected under the wrong key", V.verify_receipt(chain[0], other_pk)[0] is False)
    check("enc_alg is post-quantum hybrid", out["enc_alg"] == "ML-KEM-1024+AES-256-GCM")


def _error_paths():
    """Audit fix #9: sealed/403 transit failures + malformed responses surface as VaultAdapterError."""
    from algovoi_doc_archive_vault import vault_signer
    from algovoi_doc_archive_vault.vault import VaultAdapterError

    pk, _sk = signing.generate_keypair()

    class _Transit:
        def __init__(self, mode):
            self._mode = mode
        def decrypt_data(self, **kw):
            if self._mode == "raise":
                raise RuntimeError("Vault is sealed")
            if self._mode == "empty":
                return {"data": {"plaintext": ""}}  # decodes to b""
            return {"data": {}}  # missing plaintext

    class _Client:
        def __init__(self, mode):
            self.secrets = type("S", (), {"transit": _Transit(mode)})()

    raised = False
    try:
        vault_signer(pk, b"vault:v1:xx", key_name="k", client=_Client("badshape")).sign(b"m")
    except VaultAdapterError:
        raised = True
    check("Vault adapter raises VaultAdapterError on missing data.plaintext", raised)

    wrapped = False
    try:
        vault_signer(pk, b"vault:v1:xx", key_name="k", client=_Client("raise")).sign(b"m")
    except VaultAdapterError as e:
        wrapped = "sealed" in str(e)
    check("Vault adapter wraps a transit decrypt failure in VaultAdapterError", wrapped)

    empty = False
    try:
        vault_signer(pk, b"vault:v1:xx", key_name="k", client=_Client("empty")).sign(b"m")
    except VaultAdapterError:
        empty = True
    check("Vault adapter rejects an empty plaintext", empty)


def main():
    asyncio.run(_run(_FakeClient()))
    _error_paths()
    print(f"\n=== VAULT-ADAPTER RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
