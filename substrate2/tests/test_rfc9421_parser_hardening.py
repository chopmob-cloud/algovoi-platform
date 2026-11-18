"""RFC 9421 Hardening Profile: parser strictness (RC-9), required-components
(RC-1) and mode-pin (RC-7) tests.

These cover the controls added on top of the freshness (RC-4), alg-binding (RC-6)
and tag suites: they exercise the attacks a lenient parser lets through
(duplicate parameters, multiple signatures, label confusion, base64 garbage) and
the caller policy hooks (required covered components, pinned signing-base mode).
"""
from __future__ import annotations

import pytest

from substrate2.rfc9421_verifier import (
    SignatureInputParseError,
    parse_signature_input,
    parse_signature_value,
    verify_request,
)
from substrate2.httpsig import sign_request

SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
PUBKEY_HEX = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"
AUTHORITY = "api.algovoi.co.uk"
PATH = "/compliance/attestation"
METHOD = "GET"
KEYID = "did:web:api.algovoi.co.uk"


def _sign(**kw) -> dict:
    res = sign_request(
        method=METHOD, authority=AUTHORITY, path=PATH, body=b"",
        private_key=SEED_HEX, keyid=KEYID, **kw,
    )
    return {
        "host": AUTHORITY,
        "content-digest": res.content_digest,
        "signature-input": res.signature_input,
        "signature": res.signature,
    }


def _verify(headers, **kw):
    return verify_request(
        method=METHOD, authority=AUTHORITY, path=PATH,
        headers=headers, body=b"", public_key=PUBKEY_HEX, **kw,
    )


# --- RC-9: parser strictness (unit level) ---

def test_duplicate_parameter_rejected():
    headers = _sign()
    tampered = headers["signature-input"] + ";created=1700000000"
    with pytest.raises(SignatureInputParseError, match="duplicate signature parameter"):
        parse_signature_input(tampered)


def test_duplicate_covered_component_rejected():
    raw = (
        'sig=("@method" "@method");created=1778955520;'
        'keyid="k";alg="ed25519"'
    )
    with pytest.raises(SignatureInputParseError, match="duplicate covered component"):
        parse_signature_input(raw)


def test_multiple_signatures_rejected():
    raw = (
        'sig=("@method");created=1;keyid="k";alg="ed25519", '
        'sig2=("@path");created=2;keyid="k";alg="ed25519"'
    )
    with pytest.raises(SignatureInputParseError, match="multiple signatures"):
        parse_signature_input(raw)


def test_single_signature_still_parses():
    si = parse_signature_input(_sign()["signature-input"])
    assert si.label == "sig"
    assert "@method" in si.covered_components


def test_base64_garbage_rejected():
    with pytest.raises(SignatureInputParseError, match="base64"):
        parse_signature_value("sig=:not valid base64!!!:")


def test_multi_member_signature_header_rejected():
    # A second byte-sequence member turns the b64 slice into non-alphabet bytes,
    # which validate=True rejects rather than silently decoding garbage.
    with pytest.raises(SignatureInputParseError):
        parse_signature_value("sig=:AAAA:, sig2=:BBBB:")


def test_noncanonical_base64_rejected():
    # A valid signature re-encoded with non-zero pad bits decodes to identical
    # bytes but is a different header string -> signature-string malleability.
    # The canonical round-trip check must reject it (parity with the standalone
    # algovoi-rfc9421-verifier). Surfaced by rfc9421_hardening_v1.
    import base64
    valid = _sign()["signature"]
    label, rest = valid.split("=:", 1)
    b64 = rest[:-1]
    raw = base64.b64decode(b64, validate=True)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    stripped = b64.rstrip("=")
    pad = b64[len(stripped):]
    idx = alphabet.index(stripped[-1])
    noncanon = None
    for bit in (1, 2, 4, 8):
        cand = stripped[:-1] + alphabet[idx ^ bit] + pad
        if cand != b64 and base64.b64decode(cand) == raw:
            noncanon = cand
            break
    assert noncanon is not None
    with pytest.raises(SignatureInputParseError, match="canonical"):
        parse_signature_value(f"{label}=:{noncanon}:")


# --- RC-9: label confusion (verify level) ---

def test_label_mismatch_rejected():
    headers = _sign()
    # Rename only the Signature-Input label; the label is not in the signing base,
    # so the Ed25519 signature would still verify -- this is exactly the confusion
    # the cross-check exists to catch.
    headers["signature-input"] = "sigX=" + headers["signature-input"].split("=", 1)[1]
    result = _verify(headers)
    assert result.valid is False
    assert any("does not match" in e for e in result.errors)


def test_matching_label_passes():
    result = _verify(_sign())
    assert result.valid is True, result.errors


# --- RC-1: required covered components ---

def test_required_components_present_passes():
    result = _verify(_sign(), required_components=["@method", "@authority", "@path"])
    assert result.valid is True, result.errors


def test_required_components_missing_rejected():
    # Sign a narrow set that omits @authority and @path; the signature is valid over
    # that narrow base, but the caller's required set is not satisfied.
    headers = _sign(covered_components=["@method", "content-digest", "created"])
    result = _verify(headers, required_components=["@method", "@authority", "@path"])
    assert result.valid is False
    assert any("required covered components missing" in e for e in result.errors)


def test_narrow_signature_valid_without_policy():
    # Control: the same narrow signature is cryptographically valid when no
    # required-components policy is applied, proving the rejection above is policy,
    # not a broken signature.
    headers = _sign(covered_components=["@method", "content-digest", "created"])
    result = _verify(headers)
    assert result.valid is True, result.errors


# --- RC-7: mode pin ---

def test_unknown_mode_rejected():
    result = _verify(_sign(), mode="totally-made-up")
    assert result.valid is False
    assert any("unknown signing-base mode" in e for e in result.errors)
