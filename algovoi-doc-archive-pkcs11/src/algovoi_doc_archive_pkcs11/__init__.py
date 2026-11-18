"""algovoi-doc-archive-pkcs11 — PKCS#11 (HSM) key custody for the AlgoVoi engine.

Hold your Falcon-1024 signing key and ML-KEM encryption key wrapped by an HSM-resident key; AlgoVoi
only ever holds the wrapped blob. Build a Signer / Encryptor backed by your HSM and hand them to
``Archive`` — the evidence format and verification are unchanged. Works with any PKCS#11 HSM
(SoftHSM, Luna, nCipher, CloudHSM via PKCS#11).

Usage::

    import pkcs11
    from algovoi_doc_archive.archive import Archive
    from algovoi_doc_archive_pkcs11 import pkcs11_wrap, pkcs11_signer, pkcs11_encryptor

    token = pkcs11.lib("/usr/lib/softhsm/libsofthsm2.so").get_token(token_label="algovoi")
    with token.open(user_pin="1234") as session:
        wrapped_sign = pkcs11_wrap(falcon_secret_key, session=session, key_label="algovoi-kek")
        signer    = pkcs11_signer(falcon_public_key, wrapped_sign, session=session, key_label="algovoi-kek")
        encryptor = pkcs11_encryptor(mlkem_public_key, wrapped_enc, session=session, key_label="algovoi-kek")
        archive   = Archive(signer=signer, encryptor=encryptor, storage=...)
"""
from algovoi_doc_archive_pkcs11.hsm import pkcs11_encryptor, pkcs11_signer, pkcs11_wrap

__all__ = ["pkcs11_wrap", "pkcs11_signer", "pkcs11_encryptor"]
