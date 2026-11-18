#!/usr/bin/env python3
"""Generate rfc9421_hardening_v1.json — a deterministic conformance vector set for
the RFC 9421 Hardening Profile.

Positive control plus one negative vector per attack class. Signed headers are
produced with the RFC 8032 §7.1 deterministic Ed25519 keypair and a fixed
`created`, so the corpus is byte-reproducible and implementation-neutral (any
byte-parity signer yields the same bytes). Negative vectors are the positive
baseline with a single, named tampering applied.

Run from a checkout that can import substrate2 (signer only; the vectors it emits
are consumed by any conformant verifier).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from substrate2.httpsig import sign_request, DEFAULT_COVERED

SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
PUBKEY_HEX = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"
KEYID = "did:web:api.algovoi.co.uk"
AUTHORITY = "api.algovoi.co.uk"
PATH = "/compliance/screen"
METHOD = "POST"
CREATED = 1750000000
BODY = b'{"agent_id":"bench-agent-001","amount":100}'
NOW = CREATED + 5  # fresh relative to created


def _sign(**kw):
    kw.setdefault("created", CREATED)
    return sign_request(
        method=METHOD, authority=AUTHORITY, path=PATH, body=BODY,
        private_key=SEED_HEX, keyid=KEYID, **kw,
    )


def _headers(res):
    return {
        "host": AUTHORITY,
        "content-digest": res.content_digest,
        "signature-input": res.signature_input,
        "signature": res.signature,
    }


def _noncanonical_b64(sig_header: str) -> str:
    """Return the same signature with non-canonical base64 (non-zero pad bits).

    Decodes the label=:b64: value, then re-encodes flipping a trailing pad bit so
    the string differs but decodes to the identical 64 signature bytes. Exposes
    base64/​signature-string malleability: a canonical-check verifier rejects it,
    a permissive one still verifies.
    """
    label, rest = sig_header.split("=:", 1)
    b64 = rest[:-1]
    raw = base64.b64decode(b64, validate=True)
    # 64 bytes -> 88 base64 chars ending in '=='. The last DATA char (before the
    # padding) carries unused low bits. Flip one so the string differs but decodes
    # to the identical bytes -> signature-string malleability.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    stripped = b64.rstrip("=")
    pad = b64[len(stripped):]
    idx = alphabet.index(stripped[-1])
    for bit in (0b0001, 0b0010, 0b0100, 0b1000):
        nc = stripped[:-1] + alphabet[idx ^ bit] + pad
        if nc != b64 and base64.b64decode(nc) == raw:
            return f"{label}=:{nc}:"
    raise RuntimeError("could not construct a non-canonical base64 for this signature")


def build():
    vectors = []

    def add(vid, desc, attack, http, expect, control, verify_args=None):
        vectors.append({
            "id": vid,
            "description": desc,
            "attack_class": attack,
            "profile_control": control,
            "http": http,
            "verify_args": verify_args or {},
            "expect": expect,
        })

    def http_from(headers, body=BODY):
        return {
            "method": METHOD, "authority": AUTHORITY, "path": PATH, "scheme": "https",
            "headers": headers, "body_hex": body.hex(),
        }

    base = _sign()
    base_h = _headers(base)

    # --- positive control ---
    add("positive_baseline",
        "Well-formed RFC 9421 signature over method/authority/path/content-digest/created.",
        "none", http_from(dict(base_h)),
        {"valid": True}, "RC-8",
        {"now": NOW, "require_content_digest": True})

    # --- RC-2 body binding ---
    tampered_body = dict(base_h)
    add("body_swapped",
        "Body altered after signing; Content-Digest no longer matches the body.",
        "body_binding", http_from(tampered_body, body=b'{"agent_id":"bench-agent-001","amount":999999}'),
        {"valid": False, "reason_contains": "content-digest"}, "RC-2",
        {"now": NOW, "require_content_digest": True})

    narrow = _sign(covered_components=["@method", "@authority", "@path", "created"])
    add("content_digest_not_covered",
        "Body present and require_content_digest, but content-digest is not a covered component.",
        "body_binding", http_from(_headers(narrow)),
        {"valid": False, "reason_contains": "covered"}, "RC-2",
        {"now": NOW, "require_content_digest": True})

    # --- RC-9 parser strictness ---
    dup_alg = dict(base_h)
    dup_alg["signature-input"] = base_h["signature-input"] + ';alg="weak-hmac"'
    add("duplicate_alg_param",
        "Second alg parameter appended (last-wins downgrade ambiguity).",
        "parser_strictness", http_from(dup_alg),
        {"valid": False, "reason_contains": "duplicate"}, "RC-9",
        {"now": NOW})

    dup_created = dict(base_h)
    dup_created["signature-input"] = base_h["signature-input"] + ";created=1"
    add("duplicate_created_param",
        "Second created parameter appended.",
        "parser_strictness", http_from(dup_created),
        {"valid": False, "reason_contains": "duplicate"}, "RC-9",
        {"now": NOW})

    dup_comp = dict(base_h)
    dup_comp["signature-input"] = base_h["signature-input"].replace(
        '("@method"', '("@method" "@method"', 1)
    add("duplicate_covered_component",
        "A covered component (@method) listed twice (RFC 9421 §2.1 violation).",
        "parser_strictness", http_from(dup_comp),
        {"valid": False, "reason_contains": "duplicate"}, "RC-9",
        {"now": NOW})

    multi = dict(base_h)
    multi["signature-input"] = (
        base_h["signature-input"]
        + ', evil=("@method");created=1;keyid="attacker";alg="ed25519"'
    )
    add("multiple_signatures",
        "A second attacker-controlled signature member appended to Signature-Input.",
        "parser_strictness", http_from(multi),
        {"valid": False, "reason_contains": "multiple"}, "RC-9",
        {"now": NOW})

    label_mm = dict(base_h)
    label_mm["signature-input"] = "sigX=" + base_h["signature-input"].split("=", 1)[1]
    add("label_mismatch",
        "Signature-Input label differs from Signature label (label not in signing base).",
        "parser_strictness", http_from(label_mm),
        {"valid": False, "reason_contains": "match"}, "RC-9",
        {"now": NOW})

    # --- malleability: non-canonical base64 (same 64 sig bytes, different string) ---
    nc = dict(base_h)
    nc["signature"] = _noncanonical_b64(base_h["signature"])
    add("noncanonical_base64_signature",
        "Signature re-encoded with non-zero base64 pad bits; decodes to identical bytes.",
        "malleability", http_from(nc),
        {"valid": False, "reason_contains": "canonical"}, "RC-9",
        {"now": NOW})

    # --- RC-6 algorithm binding ---
    no_alg = dict(base_h)
    no_alg["signature-input"] = base_h["signature-input"].replace(';alg="ed25519"', "")
    add("missing_alg",
        "alg parameter stripped (downgrade-by-omission).",
        "algorithm_binding", http_from(no_alg),
        {"valid": False, "reason_contains": "alg"}, "RC-6",
        {"now": NOW})

    add("disallowed_alg",
        "Valid ed25519 signature but caller pins allowed_algorithms to exclude ed25519.",
        "algorithm_binding", http_from(dict(base_h)),
        {"valid": False, "reason_contains": "allowed"}, "RC-6",
        {"now": NOW, "allowed_algorithms": ["ecdsa-p256-sha256"]})

    # --- RC-4 freshness / replay ---
    add("stale_created",
        "created far in the past; caller enforces a 300s max-age window.",
        "freshness", http_from(dict(base_h)),
        {"valid": False, "reason_contains": "age"}, "RC-4",
        {"now": CREATED + 10_000, "max_age_seconds": 300})

    future = _sign(created=CREATED + 10_000)
    add("future_created",
        "created beyond the allowed skew into the future.",
        "freshness", http_from(_headers(future)),
        {"valid": False, "reason_contains": "future"}, "RC-4",
        {"now": CREATED, "require_created": True})

    nonce_sig = _sign(nonce="nonce-replay-001")
    add("replayed_nonce",
        "Single-use nonce already recorded by the caller's store.",
        "freshness", http_from(_headers(nonce_sig)),
        {"valid": False, "reason_contains": "replay"}, "RC-4",
        {"now": NOW, "__nonce_seen__": "replayed"})

    # --- RC-1 required-components policy ---
    no_reqline = _sign(covered_components=["@method", "content-digest", "created"])
    add("required_component_missing",
        "Signature omits @authority and @path; caller requires all three request-line components.",
        "coverage_policy", http_from(_headers(no_reqline)),
        {"valid": False, "reason_contains": "required"}, "RC-1",
        {"now": NOW, "require_content_digest": True,
         "required_components": ["@method", "@authority", "@path"],
         "__requires_kwarg__": "required_components"})

    # --- RC-7 mode pin ---
    add("unknown_mode",
        "Caller passes an unknown signing-base mode.",
        "mode_pin", http_from(dict(base_h)),
        {"valid": False}, "RC-7",
        {"now": NOW, "mode": "totally-made-up"})

    doc = {
        "name": "rfc9421_hardening_v1",
        "description": (
            "RFC 9421 Hardening Profile conformance vectors: parser strictness, "
            "coverage policy, algorithm binding, freshness/replay, mode pin and "
            "base64/signature malleability. One positive control plus one negative "
            "vector per attack class."
        ),
        "spec": "draft-hopley-x402-rfc9421-binding + RFC 9421 + RFC 9530",
        "keypair": {"seed_hex": SEED_HEX, "public_key_hex": PUBKEY_HEX, "keyid": KEYID},
        "created": CREATED,
        "public_key_hex": PUBKEY_HEX,
        "vectors": vectors,
    }
    return doc


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rfc9421_hardening_v1.json")
    out.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    doc = json.loads(out.read_text(encoding="utf-8"))
    print(f"wrote {out} with {len(doc['vectors'])} vectors")
