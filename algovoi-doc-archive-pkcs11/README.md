# algovoi-doc-archive-pkcs11

PKCS#11 (HSM) key custody for the AlgoVoi Verifiable Archive / Records Vault.

Hold your **Falcon-1024 signing key** and **ML-KEM encryption key** wrapped by a key resident in your
HSM. AlgoVoi only ever holds the wrapped blob; each key is unwrapped via the HSM only at sign / decrypt
time and zeroized after. The HSM performs only a classical unwrap, so this works with any PKCS#11 HSM
today (SoftHSM, Thales Luna, Entrust nCipher, AWS CloudHSM via PKCS#11). The evidence format is
unchanged, so verification is unaffected.

```python
import pkcs11
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive_pkcs11 import pkcs11_wrap, pkcs11_signer, pkcs11_encryptor

token = pkcs11.lib("/usr/lib/softhsm/libsofthsm2.so").get_token(token_label="algovoi")
with token.open(user_pin="1234") as session:
    wrapped_sign = pkcs11_wrap(falcon_secret_key, session=session, key_label="algovoi-kek")
    signer    = pkcs11_signer(falcon_public_key, wrapped_sign, session=session, key_label="algovoi-kek")
    encryptor = pkcs11_encryptor(mlkem_public_key, wrapped_enc, session=session, key_label="algovoi-kek")
    archive   = Archive(signer=signer, encryptor=encryptor, storage=...)
```

Requires a valid AlgoVoi OEM licence (`ALGOVOI_LICENSE_KEY` / `ALGOVOI_LICENSE_FILE`); verified
offline, fail-closed. Commercial — see `LicenseRef-AlgoVoi-Commercial-1.0`.
