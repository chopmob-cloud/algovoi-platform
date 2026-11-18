"""
Section 5 — JWS receipt round-trip + tamper detection.

The receipt-signing key is AlgoVoi's private key (not a published fixture), so the
conformance signal here is round-trip: substrate2 signs a compliance receipt, verifies it
against a JWKS built from the matching public key, and confirms a tampered token fails.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def run():
    from substrate2.jws import (
        ReceiptVerificationError,
        jwk_for,
        kid_for,
        sign_receipt,
        verify_compliance_receipt,
    )
    from substrate2.receipts.compliance import build_compliance_receipt

    sk = Ed25519PrivateKey.generate()
    pk_raw = sk.public_key().public_bytes_raw()

    receipt = build_compliance_receipt(
        payer_ref="sha256:0dd5d0b76c9b9281fdeb2509ad38ab132b16a17385ca01d976ff9e6e12563a0f",
        screen_result="ALLOW",
        screen_timestamp_ms=1716494400000,
        screen_provider_did="did:web:api.algovoi.co.uk",
        jurisdiction_flags=["UK", "EU"],
    )
    jws = sign_receipt(receipt, private_key=sk)
    jwks = {"keys": [jwk_for(pk_raw)]}

    checks = {}

    res = verify_compliance_receipt(jws, jwks=jwks)
    checks["valid_roundtrip"] = bool(res) and res.raw_payload == receipt and res.kid == kid_for(pk_raw)

    # tamper the signature segment
    h, p, s = jws.split(".")
    tampered = f"{h}.{p}." + ("AAAA" if s[:4] != "AAAA" else "BBBB") + s[4:]
    try:
        verify_compliance_receipt(tampered, jwks=jwks)
        checks["tamper_rejected"] = False
    except ReceiptVerificationError as exc:
        checks["tamper_rejected"] = exc.code == "TAMPERED_SIGNATURE"

    # no resolvable key for the header kid (empty JWKS) -> cannot verify the signature
    try:
        verify_compliance_receipt(jws, jwks={"keys": []})
        checks["no_key_rejected"] = False
    except ReceiptVerificationError as exc:
        checks["no_key_rejected"] = exc.code == "TAMPERED_SIGNATURE"

    fails = [k for k, ok in checks.items() if not ok]
    return (not fails), ("sign/verify + tamper + unknown-kid all correct" if not fails else "FAIL: " + ", ".join(fails))
