"""Regression: RFC 9421 header field names are case-insensitive (RFC 9110 s5.1).

A caller sending capitalised 'Signature-Input' / 'Signature' / 'Content-Digest'
(e.g. the gibberlink VAL envelope) must verify the same as lowercase. Before the
2026-08-23 fix, verify_request checked '"signature-input" not in headers' without
normalising the header keys, so under the substrate2 compat shim the gibberlink
audio transport failed 401 'missing Signature-Input header'. This pins the fix.
"""
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import substrate2


def _signed(body=b'{"amount":"1.00"}'):
    seed = bytes(range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_raw = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    common = dict(method="POST", authority="api.algovoi.co.uk", path="/v1/pay")
    res = substrate2.sign_request(
        headers={"content-type": "application/json"}, body=body,
        private_key=seed, keyid="k1", **common)
    return res, pk_raw, body, common


def test_verify_request_accepts_capitalised_header_names():
    """Capitalised header names (as the gibberlink VAL envelope emits) verify."""
    res, pk_raw, body, common = _signed()
    hdrs = {"Content-Type": "application/json", "Signature-Input": res.signature_input,
            "Signature": res.signature, "Content-Digest": res.content_digest}
    assert substrate2.verify_request(headers=hdrs, body=body, public_key=pk_raw, **common).valid


def test_verify_request_mixed_case_header_names():
    """Arbitrary mixed case also verifies (case-insensitive per RFC 9110)."""
    res, pk_raw, body, common = _signed()
    hdrs = {"content-type": "application/json", "SiGnAtUrE-InPuT": res.signature_input,
            "signature": res.signature, "CONTENT-DIGEST": res.content_digest}
    assert substrate2.verify_request(headers=hdrs, body=body, public_key=pk_raw, **common).valid


def test_verify_request_lowercase_unchanged():
    """The existing lowercase path is unaffected by the normalisation."""
    res, pk_raw, body, common = _signed()
    hdrs = {"content-type": "application/json", "signature-input": res.signature_input,
            "signature": res.signature, "content-digest": res.content_digest}
    assert substrate2.verify_request(headers=hdrs, body=body, public_key=pk_raw, **common).valid
