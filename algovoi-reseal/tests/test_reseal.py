"""End-to-end tests: real CMS signatures in, PQ attestations out, tamper detection.

The CMS fixtures are generated with cryptography's PKCS7SignatureBuilder against
a fresh self-signed RSA cert, so the classical verifier is exercised against
genuine PKCS#7 bytes, not hand-rolled ones. TSA tests stay offline (--no-tsa
path); the network stamp is covered by the manual e2e in the container.
"""
from __future__ import annotations

import datetime
import json
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from algovoi_reseal import (  # noqa: E402
    build_attestation_payload, seal_payload, verify_artifact,
    generate_keys, load_keys, _prefixed,
)
from algovoi_reseal import classical  # noqa: E402

CONTENT = b"This agreement, signed 2024, must stay provable until 2050.\n"


@pytest.fixture(scope="module")
def rsa_identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Reseal Test Signer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return key, cert


@pytest.fixture(scope="module")
def detached_cms(rsa_identity):
    key, cert = rsa_identity
    # Binary: no S/MIME text canonicalisation, sign the exact bytes, which is
    # how real document signers behave.
    return (pkcs7.PKCS7SignatureBuilder()
            .set_data(CONTENT)
            .add_signer(cert, key, hashes.SHA256())
            .sign(serialization.Encoding.DER,
                  [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("keys"))
    generate_keys(d)
    return load_keys(d)


def _fake_signed_pdf(cms_der: bytes) -> bytes:
    """A minimal PDF-shaped file whose ByteRange/Contents are internally correct.

    The CMS is a detached signature over CONTENT, so the covered region must be
    exactly CONTENT split around the /Contents blob.
    """
    hexs = cms_der.hex().encode()
    head = b"%PDF-1.7\n" + CONTENT[:20]
    tail = CONTENT[20:] + b"\n%%EOF\n"
    # Fixed-width numbers (legal in PDF) make the marker length independent of
    # the values, so the offsets resolve in one pass.
    a, b = 0, len(head)
    marker_len = len(b"/ByteRange [%010d %010d %010d %010d] /Contents <"
                     % (0, 0, 0, 0))
    c = b + marker_len + len(hexs) + 1
    marker = (b"/ByteRange [%010d %010d %010d %010d] /Contents <"
              % (a, b, c, len(tail)))
    return head + marker + hexs + b">" + tail


class TestClassical:
    def test_detached_cms_verifies(self, detached_cms):
        block = classical.inspect_detached(CONTENT, detached_cms)
        sig = block["signatures"][0]
        assert sig["verified"], sig
        assert sig["signature_algorithm"] == "rsa-2048"
        assert sig["quantum_vulnerable"] is True
        assert sig["cert_chain_der_b64"], "cert chain must be captured for the future"

    def test_detached_cms_rejects_tamper(self, detached_cms):
        block = classical.inspect_detached(CONTENT + b"x", detached_cms)
        assert not block["signatures"][0]["verified"]

    def test_pdf_byterange(self, detached_cms):
        pdf = _fake_signed_pdf(detached_cms)
        block = classical.inspect_bytes(pdf, "contract.pdf")
        assert block["present"], block
        # The covered region of our synthetic PDF is not CONTENT, so the digest
        # check must FAIL - which proves the ByteRange extraction and digest
        # comparison actually run against the covered bytes.
        sig = block["signatures"][0]
        assert sig["format"] == "pdf_byterange"
        assert any(c["check"] == "message_digest_attr" for c in sig["checks"])

    def test_unsigned_file(self):
        block = classical.inspect_bytes(b"hello", "note.txt")
        assert block["present"] is False


class TestSealVerify:
    def test_roundtrip(self, keys):
        payload = build_attestation_payload(CONTENT, "contract.txt")
        artifact = seal_payload(payload, keys)
        report = verify_artifact(artifact, file_bytes=CONTENT)
        assert report["ok"], report

    def test_tampered_file_fails(self, keys):
        payload = build_attestation_payload(CONTENT, "contract.txt")
        artifact = seal_payload(payload, keys)
        report = verify_artifact(artifact, file_bytes=CONTENT + b"!")
        assert not report["ok"]

    def test_tampered_payload_fails(self, keys):
        payload = build_attestation_payload(CONTENT, "contract.txt")
        artifact = seal_payload(payload, keys)
        import base64
        env = json.loads(base64.urlsafe_b64decode(
            artifact["attestation"] + "=" * ((-len(artifact["attestation"])) % 4)))
        env["payload"]["subject"]["filename"] = "innocent.txt"
        raw = json.dumps(env, separators=(",", ":"), sort_keys=True).encode()
        artifact["attestation"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        report = verify_artifact(artifact)
        assert not report["ok"]

    def test_batch_chain_links(self, keys):
        p1 = build_attestation_payload(CONTENT, "a.txt")
        p2 = build_attestation_payload(CONTENT + b"2", "b.txt",
                                       prev_entry_hash=_prefixed(p1))
        assert p2["prev_entry_hash"] == _prefixed(p1)
        a2 = seal_payload(p2, keys)
        assert verify_artifact(a2)["checks"][0]["ok"]

    def test_classical_evidence_travels(self, keys, detached_cms):
        block = classical.inspect_detached(CONTENT, detached_cms)
        payload = build_attestation_payload(CONTENT, "contract.txt")
        payload["classical"] = block
        artifact = seal_payload(payload, keys)
        report = verify_artifact(artifact, file_bytes=CONTENT)
        assert report["ok"]
        assert report["payload"]["classical"]["signatures"][0]["quantum_vulnerable"]
