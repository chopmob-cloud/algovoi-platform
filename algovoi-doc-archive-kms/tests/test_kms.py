"""KMS adapter test (moto-mocked — exercises the real boto3 KMS Encrypt/Decrypt path, no AWS).

Wraps the Falcon + ML-KEM keys with a KMS key, signs/encrypts through the KMS-backed Signer/Encryptor,
verifies the receipt with the free verifier, and confirms the document round-trips. Run:
    python tests/test_kms.py
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
import algovoi_doc_archive_kms.licensing as _kl; _kl.require_license = lambda: {"t": 1}

import boto3
from moto import mock_aws
from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.backend import LocalFsBackend
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_doc_archive_kms import kms_wrap, kms_signer, kms_encryptor
import algovoi_verify as V

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


async def _run(kms, key_id):
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()

    w_sign = kms_wrap(sk, key_id=key_id, client=kms)
    w_enc = kms_wrap(kem_sk, key_id=key_id, client=kms)
    check("wrapped blobs differ from the raw keys", w_sign != sk and w_enc != kem_sk)

    signer = kms_signer(pk, w_sign, client=kms)
    enc = kms_encryptor(kem_pk, w_enc, client=kms)

    tmp = tempfile.mkdtemp()
    arch = Archive(signer=signer, encryptor=enc, storage=LocalFsBackend(f"{tmp}/a"))
    data = b"document under AWS KMS key custody"
    out = await arch.notarize(data=data, title="kms-1")

    check("document round-trips (KMS-unwrapped decrypt)", (await arch.retrieve(doc_hash=out["doc_hash"])) == data)

    chain = await arch.list_entries()
    check("KMS-signed receipt verifies via the free verifier", V.verify_receipt(chain[0], pk)[0] is True)
    other_pk, _ = signing.generate_keypair()
    check("receipt rejected under the wrong key", V.verify_receipt(chain[0], other_pk)[0] is False)
    check("enc_alg is post-quantum hybrid", out["enc_alg"] == "ML-KEM-1024+AES-256-GCM")


def _error_paths():
    """Audit fix #9: malformed KMS responses / provider failures surface as KmsAdapterError."""
    from algovoi_doc_archive_kms import kms_signer
    from algovoi_doc_archive_kms.kms import KmsAdapterError

    pk, _sk = signing.generate_keypair()

    class _BadShape:
        def decrypt(self, **kw):
            return {}  # no "Plaintext"

    class _Denied:
        def decrypt(self, **kw):
            raise RuntimeError("AccessDeniedException")

    raised = False
    try:
        kms_signer(pk, b"wrapped", client=_BadShape()).sign(b"m")
    except KmsAdapterError:
        raised = True
    check("KMS adapter raises KmsAdapterError on a missing Plaintext", raised)

    wrapped = False
    try:
        kms_signer(pk, b"wrapped", client=_Denied()).sign(b"m")
    except KmsAdapterError as e:
        wrapped = "AccessDenied" in str(e)
    check("KMS adapter wraps a provider Decrypt failure in KmsAdapterError", wrapped)


def main():
    with mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        key_id = kms.create_key()["KeyMetadata"]["KeyId"]
        asyncio.run(_run(kms, key_id))
    _error_paths()
    print(f"\n=== KMS-ADAPTER RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
