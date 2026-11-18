"""
Section 2 — RFC 8032 §7.1 known-answer test + RFC 9421 signing-base pin.

Two independent checks:
  1. A genuine RFC 8032 Section 7.1 TEST 1 known-answer test: the real Test 1 seed
     (ending ...cae7f60) must derive the RFC's published public key and produce the
     RFC's published signature over the empty message. This verifies our Ed25519
     implementation against the RFC itself.
  2. A substrate signing-base pin: rebuild the canonical anchor vector with a fixed
     deterministic local test key (seed ending ...cae3d55, which is NOT the RFC 8032
     Test 1 seed) and the fixed `created=1748000000`, then assert substrate2's signing
     base, signature_input, and content-digest match the pinned strings and the
     signature is a 64-byte Ed25519 sig.
"""
from __future__ import annotations

import base64
import hashlib

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55")  # local test key, NOT RFC 8032 Test 1 (that seed ends ...cae7f60)
KEYID = "did:web:api.algovoi.co.uk"
CREATED = 1748000000
BODY = b'{"agent_id":"bench-agent-001","chain":"algorand"}'


def run():
    from substrate2.httpsig import sign_request, DEFAULT_COVERED

    r = sign_request(
        method="POST",
        authority="api.algovoi.co.uk",
        path="/compliance/screen",
        body=BODY,
        private_key=SEED,
        keyid=KEYID,
        created=CREATED,
    )

    cd_b64 = base64.b64encode(hashlib.sha256(BODY).digest()).decode()
    expected_cd = f"sha-256=:{cd_b64}:"
    params = (
        '("@method" "@authority" "@path" "content-digest" "created")'
        f";created={CREATED}"
        f';keyid="{KEYID}"'
        ';alg="ed25519"'
    )
    expected_si = "sig=" + params
    expected_base = "\n".join([
        '"@method": POST',
        '"@authority": api.algovoi.co.uk',
        '"@path": /compliance/screen',
        f'"content-digest": {expected_cd}',
        f'"created": {CREATED}',
        f'"@signature-params": {params}',
    ])

    checks = {
        "covered_components": r.covered_components == DEFAULT_COVERED,
        "content_digest": r.content_digest == expected_cd,
        "signature_input": r.signature_input == expected_si,
        "signing_base": r.signing_base == expected_base,
    }
    try:
        sig_b64 = r.signature[len("sig=:"):-1]
        checks["signature_len_64"] = len(base64.b64decode(sig_b64)) == 64
    except Exception:
        checks["signature_len_64"] = False

    # Genuine RFC 8032 Section 7.1 TEST 1 known-answer test (authoritative values
    # from the RFC): the real Test 1 seed (...cae7f60) must derive the published
    # public key and sign the empty message to the published signature.
    from nacl.signing import SigningKey as _SK
    _real = _SK(bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    checks["rfc8032_kat_pubkey"] = (
        _real.verify_key.encode().hex()
        == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    checks["rfc8032_kat_sig"] = (
        _real.sign(b"").signature.hex()
        == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    fails = [k for k, ok in checks.items() if not ok]
    ok = not fails
    detail = "all fixture checks pass" if ok else "FAIL: " + ", ".join(fails)
    return ok, detail
