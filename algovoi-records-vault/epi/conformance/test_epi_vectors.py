"""Validate the committed `.epi` conformance vectors (standalone, runnable).

Re-derives JCS bytes + SHA-256 for every vector and confirms they match the committed values (the
cross-implementation contract), and verifies the falcon1024 signature vector against its public key.
Run: python algovoi-records-vault/epi/conformance/test_epi_vectors.py
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")

import rfc8785  # noqa: E402
from algovoi_doc_archive import signing  # noqa: E402

PASS = 0
FAIL = 0


def check(label, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


def main() -> int:
    path = os.path.join(HERE, "epi_jcs_vectors.json")
    if not os.path.exists(path):
        print("epi_jcs_vectors.json missing — run gen_vectors.py first")
        return 1
    doc = json.load(open(path, encoding="utf-8"))

    # JCS vectors are deterministic: re-canonicalize the input and confirm bytes + hash match.
    for v in doc["jcs_vectors"]:
        canon = rfc8785.dumps(v["input"])
        check(f"JCS bytes reproduce: {v['name']}", canon.hex() == v["jcs_utf8_hex"])
        check(f"SHA-256 reproduces: {v['name']}", hashlib.sha256(canon).hexdigest() == v["sha256"])

    # signature vector verifies against the published public key (no secret needed)
    sv = doc["signature_vector"]
    pk = signing.load_key_b64(sv["public_key_b64"])
    # the signed message is the JCS of the named vector input
    named = next(v for v in doc["jcs_vectors"] if v["name"] == sv["message_name"])
    msg = rfc8785.dumps(named["input"])
    check("signature vector: message hash matches", hashlib.sha256(msg).hexdigest() == sv["message_sha256"])
    check("signature vector: kid matches public key", signing.kid_for(pk) == sv["kid"])
    check("falcon1024 signature verifies offline (public key only)",
          signing.verify_bytes(pk, msg, signing.b64u_decode(sv["signature_b64url"])) is True)
    # tamper -> fails
    check("a one-byte message change breaks the signature",
          signing.verify_bytes(pk, msg + b" ", signing.b64u_decode(sv["signature_b64url"])) is False)

    print(f"\n=== EPI-VECTORS RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
