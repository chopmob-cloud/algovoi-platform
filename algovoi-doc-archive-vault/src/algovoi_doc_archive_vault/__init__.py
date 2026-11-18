"""algovoi-doc-archive-vault — HashiCorp Vault (transit) key custody for the AlgoVoi engine.

Hold your Falcon-1024 signing key and ML-KEM encryption key in Vault's transit engine; AlgoVoi only
ever holds the transit ciphertext. Build a Signer / Encryptor backed by Vault and hand them to
``Archive`` — the evidence format and verification are unchanged.

Usage::

    from algovoi_doc_archive.archive import Archive
    from algovoi_doc_archive_vault import vault_wrap, vault_signer, vault_encryptor

    # one-time setup: wrap each private key with a transit key
    wrapped_sign = vault_wrap(falcon_secret_key, key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)
    wrapped_enc  = vault_wrap(mlkem_secret_key,  key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)

    # runtime: keys unwrap via Vault transit only at sign / decrypt time
    signer    = vault_signer(falcon_public_key, wrapped_sign, key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)
    encryptor = vault_encryptor(mlkem_public_key, wrapped_enc, key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)
    archive   = Archive(signer=signer, encryptor=encryptor, storage=...)
"""
__version__ = "0.1.2"

from algovoi_doc_archive_vault.vault import vault_encryptor, vault_signer, vault_wrap

__all__ = ["vault_wrap", "vault_signer", "vault_encryptor", "__version__"]
