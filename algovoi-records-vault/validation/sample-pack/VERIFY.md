# Verify this System Validation Evidence Pack

No AlgoVoi software is required. The trust base is two public libraries and the
published public key in this directory.

    pip install pqcrypto rfc8785
    python verify_validation_pack.py .

Three checks: the manifest carries a valid Falcon-1024 signature over the
canonical (RFC 8785) manifest; every file's SHA-256 matches what that signature
commits to; the IQ, OQ and PQ sections are well formed. Exit code 0 means every
check passed and the validation evidence is genuine and unaltered.
