"""Generate the `epi_pqc_v0` conformance set into the algovoi-jcs-conformance-vectors repo.

Mirrors the epi_interop_v0 envelope/vector conventions exactly, and adds the PROPOSED optional
post-quantum signature suite (falcon1024) + F7 key-lineage anchors. JCS vectors are deterministic;
the signature/lineage anchors are verify-reproducible against their published public keys.

Run once: python algovoi-records-vault/epi/conformance/make_epi_pqc_v0.py
"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")

import rfc8785  # noqa: E402
from algovoi_doc_archive import signing  # noqa: E402

REPO = "C:/algo/algovoi-jcs-conformance-vectors"
OUT_DIR = os.path.join(REPO, "vectors", "epi_pqc_v0")

_SPEC = ("JCS (RFC 8785) of input, then SHA-256, lowercase hex; canonicalisation citable to "
         "draft-hopley-x402-canonicalisation-jcs-v1")


def _frame(obj):
    jcs = rfc8785.dumps(obj)
    return base64.b64encode(jcs).decode("ascii"), "sha256:" + hashlib.sha256(jcs).hexdigest()


# ── the .epi-PQC-profile input objects (the JCS canonicalisation vectors) ──────────────────────
MANIFEST_CORE = {
    "schema_version": "algovoi-epi-pqc/0.1", "artifact_id": "urn:algovoi:epi:1",
    "generator": "algovoi-records-vault", "created_at": "2026-06-12T00:00:00Z",
    "canonicalization": "RFC 8785 (JCS)", "signature_suite": "falcon1024", "hash_alg": "SHA-256",
    "steps_count": 3, "steps_head": "sha256:" + "ab" * 32,
}
EPI_STEP = {"seq": 0, "stream": "access", "type": "vault_access_event",
            "evidence_hash": "sha256:" + "cd" * 32, "recorded_at": "2026-06-12T00:00:00Z", "prev": None}
CONTROL_MAPPING = {"mappings": [{"stream": "holds", "framework": "FRCP/GDPR",
                                 "requirement_id": "37(e) / Art.17(3)(e)", "coverage": "hold"}]}
UNICODE = {"reason": "rédaction — naïve 照 \U0001f512", "n": 1000000, "ok": True, "x": None}

VECS = [
    ("epi-pqc-001", "manifest_core_falcon1024", MANIFEST_CORE, "iso8601-string"),
    ("epi-pqc-002", "epi_step_hash_linked", EPI_STEP, "iso8601-string"),
    ("epi-pqc-003", "control_mapping", CONTROL_MAPPING, "none"),
    ("epi-pqc-004", "unicode_redaction_reason", UNICODE, "none"),
]


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    vectors = []
    for vid, name, obj, ts in VECS:
        b64, frame = _frame(obj)
        vectors.append({"id": vid, "source_name": name, "input": obj,
                        "canonical_preimage_spec": _SPEC,
                        "expected_jcs_bytes_b64": b64, "frame_id": frame,
                        "timestamp_encoding": ts})

    # signature suite anchor: Falcon-1024 over the JCS of MANIFEST_CORE (epi-pqc-001)
    pk, sk = signing.generate_keypair()
    msg = rfc8785.dumps(MANIFEST_CORE)
    sig = signing.sign_bytes(sk, msg)
    kid = signing.kid_for(pk)
    sig_anchor = {
        "suite": "falcon1024", "alg": "Falcon-1024 (FN-DSA, NIST FIPS 206)",
        "message_vector_id": "epi-pqc-001",
        "message_frame_id": "sha256:" + hashlib.sha256(msg).hexdigest(),
        "public_key_b64": signing.public_key_b64(pk), "kid": kid,
        "signature_b64url": signing.b64u_encode(sig),
        "signature_string": f"falcon1024:{kid}:{signing.b64u_encode(sig)}",
        "verify": "Falcon-1024 verify signature_b64url over JCS(epi-pqc-001.input) under public_key_b64; kid == sha256(pubkey)[:16]",
    }

    # key-lineage anchor: F7 cross-signed rotation k1->k2->k3
    keys = [signing.generate_keypair() for _ in range(3)]
    proofs = []
    for (opk, osk), (npk, nsk), when in zip(keys[:-1], keys[1:], ("2027-01-01T00:00:00Z", "2028-01-01T00:00:00Z")):
        binding = {"old_kid": signing.kid_for(opk), "new_kid": signing.kid_for(npk),
                   "old_pubkey_b64": signing.public_key_b64(opk),
                   "new_pubkey_b64": signing.public_key_b64(npk), "rotated_at": when}
        bmsg = rfc8785.dumps(binding)
        proofs.append({**binding,
                       "old_sig": signing.b64u_encode(signing.sign_bytes(osk, bmsg)),
                       "new_sig": signing.b64u_encode(signing.sign_bytes(nsk, bmsg))})
    lineage_anchor = {
        "note": "F7 cross-signed rotation continuity — validate an artefact whose signing key was retired years ago",
        "verify": "for each proof, Falcon-verify old_sig (under old_pubkey_b64) AND new_sig (under new_pubkey_b64) over JCS(binding); new_kid of proof N == old_kid of proof N+1",
        "proofs": proofs,
    }

    doc = {
        "schema_version": "epi-pqc-v0",
        "artefact_id": "epi_pqc_v0",
        "published_at": "2026-06-12",
        "canon_version": "jcs-rfc8785-v1",
        "canonicalizer": "rfc8785 (AlgoVoi conformance corpus)",
        "category": "epi-pqc-profile",
        "status": "PROPOSED optional signature suite — NOT an adopted .epi suite; .epi default remains ed25519",
        "anchored_to": "canon: draft-hopley-x402-canonicalisation-jcs-v1 (JCS RFC 8785); signature: NIST FIPS 206 FN-DSA (Falcon-1024)",
        "source": "AlgoVoi Records Vault — PQC profile for .epi (microsoft/agent-governance-toolkit Discussion #806)",
        "rationale": (".epi targets decades-long audit but seals with classical Ed25519. This set pins an "
                      "optional post-quantum signature suite (falcon1024) plus key-lineage continuity, so "
                      "artefacts stay verifiable past the post-quantum migration. Ed25519 stays the default; "
                      "this is interop, not replacement."),
        "timestamp_note": ("Inputs carry .epi-form ISO-8601 STRING timestamps (created_at / recorded_at / "
                           "rotated_at). Same boundary as epi_interop_v0: this set pins canonicalisation + the "
                           "falcon1024 signature recipe, NOT substrate integer-millisecond timestamp compliance "
                           "(draft-hopley-x402-canonicalisation-jcs-v1 section 4.1). Each vector declares its "
                           "timestamp_encoding."),
        "verification_recipe": {
            "canonicalisation": "JCS RFC 8785 over input -> SHA-256 -> 'sha256:'+lowerhex = frame_id; base64(canonical bytes) = expected_jcs_bytes_b64",
            "signature": sig_anchor["verify"],
            "key_lineage": lineage_anchor["verify"],
        },
        "vectors": vectors,
        "signature_suite_anchor": sig_anchor,
        "key_lineage_anchor": lineage_anchor,
    }
    out = os.path.join(OUT_DIR, "epi_pqc_v0.json")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=True)
        fh.write("\n")
    print(f"wrote {len(vectors)} JCS vectors + falcon1024 signature anchor + {len(proofs)}-step key lineage -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
