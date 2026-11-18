# Records Vault evidence pack — how to verify

You do **not** need any AlgoVoi software to check this evidence.

1. `pip install pqcrypto rfc8785`
2. `python verify_evidence_pack.py`

Exit code 0 means every signed chain (archive, timestamps, access log, legal holds) verified against
the published public key, and every timestamp binds to its archive receipt. The verifier contains no
AlgoVoi imports — read it; it is ~120 lines of Falcon-1024 verification + RFC 8785 hashing.

`record_blob.bin` is the encrypted demonstration record. It is deliberately included and is
unreadable (its ML-KEM key is not in the pack) — proving the evidence verifies without ever exposing
record contents. See `REPORT.md` for the capability-by-capability breakdown and `MANIFEST.json` for
per-file SHA-256 digests.
