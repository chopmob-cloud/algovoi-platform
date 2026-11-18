"""algovoi-doc-archive-kms — AWS KMS key custody for the AlgoVoi engine.

Hold your Falcon-1024 signing key and ML-KEM encryption key in AWS KMS; AlgoVoi only ever holds the
wrapped blobs. Build a Signer / Encryptor backed by KMS and hand them to ``Archive`` — the evidence
format and verification are unchanged.

Usage::

    from algovoi_doc_archive.archive import Archive
    from algovoi_doc_archive_kms import kms_wrap, kms_signer, kms_encryptor

    # one-time setup: wrap each private key with your KMS key, store the blobs
    wrapped_sign = kms_wrap(falcon_secret_key, key_id="alias/algovoi")
    wrapped_enc  = kms_wrap(mlkem_secret_key,  key_id="alias/algovoi")

    # runtime: keys are unwrapped via KMS Decrypt only at sign / decrypt time
    signer    = kms_signer(falcon_public_key, wrapped_sign, region_name="eu-west-2")
    encryptor = kms_encryptor(mlkem_public_key, wrapped_enc, region_name="eu-west-2")
    archive   = Archive(signer=signer, encryptor=encryptor, storage=...)
"""
from algovoi_doc_archive_kms.kms import kms_encryptor, kms_signer, kms_wrap

__all__ = ["kms_wrap", "kms_signer", "kms_encryptor"]
