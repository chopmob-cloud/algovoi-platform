"""Generate `.epi` PQC-profile conformance vectors (JCS canonicalization + Falcon-1024 signature).

Run once to (re)write ``epi_jcs_vectors.json``. The JCS vectors are deterministic — any conformant
RFC 8785 implementation must reproduce the same canonical bytes + SHA-256, which is exactly the
cross-implementation check Discussion #806 is running. The signature vector lets any verifier confirm
the optional ``falcon1024`` suite against a published public key.

Run: python algovoi-records-vault/epi/conformance/gen_vectors.py
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

# JCS edge cases relevant to .epi artifacts: key ordering, unicode, integers, null, nesting.
JCS_INPUTS = {
    "epi_step": {"seq": 0, "stream": "access", "type": "vault_access_event",
                 "evidence_hash": "sha256:" + "ab" * 32, "recorded_at": "2026-06-12T00:00:00Z",
                 "prev": None},
    "epi_manifest_core": {"schema_version": "algovoi-epi-pqc/0.1", "artifact_id": "urn:algovoi:epi:1",
                          "generator": "algovoi-records-vault", "canonicalization": "RFC 8785 (JCS)",
                          "signature_suite": "falcon1024", "steps_count": 3, "kid": "6edb82b2c6f66d4c"},
    "control_mapping": {"mappings": [{"stream": "holds", "framework": "FRCP/GDPR",
                                      "requirement_id": "37(e) / Art.17(3)(e)", "coverage": "hold"}]},
    # explicit codepoints so the vector is unambiguous regardless of source-file encoding:
    # é(U+00E9) — em dash(U+2014) ï(U+00EF) 照(U+7167) 🔒(U+1F512). RFC 8785 keeps these as UTF-8.
    "unicode_reason": {"reason": "rédaction — naïve 照 \U0001f512",
                       "n": 1000000, "ok": True, "x": None},
    "key_ordering": {"z": 1, "a": 2, "m": {"y": 3, "b": 4}},
}


def main() -> int:
    vectors = []
    for name, obj in JCS_INPUTS.items():
        canon = rfc8785.dumps(obj)
        vectors.append({
            "name": name,
            "input": obj,
            "jcs_utf8_hex": canon.hex(),
            "sha256": hashlib.sha256(canon).hexdigest(),
        })

    # falcon1024 signature vector over a canonical manifest core
    pk, sk = signing.generate_keypair()
    msg = rfc8785.dumps(JCS_INPUTS["epi_manifest_core"])
    sig = signing.sign_bytes(sk, msg)
    sig_vector = {
        "suite": "falcon1024",
        "message_name": "epi_manifest_core",
        "message_sha256": hashlib.sha256(msg).hexdigest(),
        "public_key_b64": signing.public_key_b64(pk),
        "kid": signing.kid_for(pk),
        "signature_b64url": signing.b64u_encode(sig),
    }

    doc = {
        "spec": "algovoi-epi-pqc/0.1",
        "canonicalization": "RFC 8785 (JCS)",
        "hash_alg": "SHA-256",
        "jcs_vectors": vectors,
        "signature_vector": sig_vector,
    }
    out = os.path.join(HERE, "epi_jcs_vectors.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=True)
    print(f"wrote {len(vectors)} JCS vectors + 1 falcon1024 signature vector -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
