# algovoi-doc-archive-kms

AWS KMS key custody for the AlgoVoi Verifiable Archive / Records Vault.

Hold your **Falcon-1024 signing key** and **ML-KEM encryption key** in AWS KMS. AlgoVoi only ever
holds the *wrapped* blobs; each key is unwrapped via KMS `Decrypt` only at sign / decrypt time and
zeroized after. KMS performs only a classical unwrap, so this works with AWS KMS today — no
post-quantum support required in KMS. The evidence format is unchanged, so verification is unaffected.

```python
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive_kms import kms_wrap, kms_signer, kms_encryptor

# one-time setup: wrap each private key with your KMS key
wrapped_sign = kms_wrap(falcon_secret_key, key_id="alias/algovoi")
wrapped_enc  = kms_wrap(mlkem_secret_key,  key_id="alias/algovoi")

# runtime: keys unwrap via KMS Decrypt only when needed
signer    = kms_signer(falcon_public_key, wrapped_sign, region_name="eu-west-2")
encryptor = kms_encryptor(mlkem_public_key, wrapped_enc, region_name="eu-west-2")
archive   = Archive(signer=signer, encryptor=encryptor, storage=...)
```

Requires a valid AlgoVoi OEM licence (`ALGOVOI_LICENSE_KEY` / `ALGOVOI_LICENSE_FILE`); verified
offline, fail-closed. Commercial — see `LicenseRef-AlgoVoi-Commercial-1.0`.
