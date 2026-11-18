# algovoi-doc-archive-vault

HashiCorp Vault (transit engine) key custody for the AlgoVoi Verifiable Archive / Records Vault.

Hold your **Falcon-1024 signing key** and **ML-KEM encryption key** in Vault's transit engine. AlgoVoi
only ever holds the transit ciphertext; each key is unwrapped via transit only at sign / decrypt time
and zeroized after. The key-encryption-key never leaves Vault, and transit performs only a classical
unwrap — so this works with Vault today. The evidence format is unchanged, so verification is
unaffected. Ideal for self-hosted / air-gapped estates that already run Vault.

```python
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive_vault import vault_wrap, vault_signer, vault_encryptor

wrapped_sign = vault_wrap(falcon_secret_key, key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)
wrapped_enc  = vault_wrap(mlkem_secret_key,  key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)

signer    = vault_signer(falcon_public_key, wrapped_sign, key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)
encryptor = vault_encryptor(mlkem_public_key, wrapped_enc, key_name="algovoi", url=VAULT_ADDR, token=VAULT_TOKEN)
archive   = Archive(signer=signer, encryptor=encryptor, storage=...)
```

Requires a valid AlgoVoi OEM licence (`ALGOVOI_LICENSE_KEY` / `ALGOVOI_LICENSE_FILE`); verified
offline, fail-closed. Commercial — see `LicenseRef-AlgoVoi-Commercial-1.0`.
