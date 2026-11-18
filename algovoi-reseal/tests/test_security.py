"""Adversarial tests: every input crossing a trust boundary gets attacked.

Boundary 1: inspect/seal parse attacker-controlled files (PDF, CMS).
Boundary 2: verify consumes attacker-supplied artifacts.
Boundary 3: stored RFC 3161 token blocks are attacker-suppliable.
"""
from __future__ import annotations

import base64
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
    generate_keys, load_keys, _kid, _b64u_dec,
)
from algovoi_reseal import classical  # noqa: E402
from algovoi_reseal.cli import main as cli_main  # noqa: E402

CONTENT = b"evidence bytes\n"


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("keys"))
    generate_keys(d)
    return load_keys(d)


@pytest.fixture(scope="module")
def attacker_keys(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("attacker"))
    generate_keys(d)
    return load_keys(d)


def _make_cms(content: bytes, digest, days_valid=365):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sec Test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .sign(key, hashes.SHA256()))
    return (pkcs7.PKCS7SignatureBuilder().set_data(content)
            .add_signer(cert, key, digest)
            .sign(serialization.Encoding.DER,
                  [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))


class TestForgedArtifacts:
    """Boundary 2: the artifact carries its own key, so an attacker can always
    make an internally-perfect one. Anchoring is what must stop them."""

    def test_fabricated_artifact_is_intact_but_never_anchored(self, attacker_keys):
        payload = build_attestation_payload(b"forged claims", "innocent.pdf")
        artifact = seal_payload(payload, attacker_keys)
        report = verify_artifact(artifact)
        assert report["ok"] is True        # internally consistent - expected
        assert report["anchored"] is False  # and the report must say so

    def test_expected_kid_rejects_attacker_artifact(self, keys, attacker_keys):
        our_kid = _kid(_b64u_dec(keys["falcon_pk"]))
        payload = build_attestation_payload(b"forged claims", "innocent.pdf")
        artifact = seal_payload(payload, attacker_keys)
        report = verify_artifact(artifact, expected_kid=our_kid)
        assert report["ok"] is False
        assert report["anchored"] is False

    def test_expected_kid_accepts_genuine_artifact(self, keys):
        our_kid = _kid(_b64u_dec(keys["falcon_pk"]))
        artifact = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        report = verify_artifact(artifact, expected_kid=our_kid)
        assert report["ok"] is True and report["anchored"] is True

    def test_swapped_signer_key_fails_kid_binding(self, keys, attacker_keys):
        # Take a genuine artifact and swap in the attacker's pk: either the
        # signature or the kid binding must break - never a clean pass.
        artifact = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        artifact["signer"]["falcon_pk"] = attacker_keys["falcon_pk"]
        report = verify_artifact(artifact)
        assert report["ok"] is False


class TestMalformedArtifacts:
    """Boundary 2: garbage must fail clean, never crash or pass."""

    @pytest.mark.parametrize("artifact", [
        {},
        {"format": "algovoi-reseal/2"},
        {"format": "algovoi-reseal/2", "attestation": "!!!not-b64!!!", "signer": {}},
        {"format": "algovoi-reseal/2",
         "attestation": base64.urlsafe_b64encode(b"not json").decode(), "signer": {}},
        {"format": "algovoi-reseal/2",
         "attestation": base64.urlsafe_b64encode(b'{"payload": 42}').decode(),
         "signer": {"falcon_pk": "AAAA"}},
        {"format": "wrong/9", "attestation": "", "signer": {}},
    ])
    def test_garbage_fails_clean(self, artifact):
        report = verify_artifact(artifact)
        assert report["ok"] is False

    def test_cli_verify_malformed_file_exits_2(self, tmp_path):
        p = tmp_path / "junk.reseal.json"
        p.write_bytes(b"\x00\x01 not json")
        assert cli_main(["verify", str(p)]) == 2

    def test_cli_verify_non_object_exits_2(self, tmp_path):
        p = tmp_path / "arr.reseal.json"
        p.write_text("[1,2,3]")
        assert cli_main(["verify", str(p)]) == 2

    def test_cli_verify_accepts_all_flags(self, keys, tmp_path):
        # Regression: --tsa-roots / --expect-kid must be wired to the parser and
        # not raise (a missing add_argument crashed verify entirely).
        from algovoi_reseal import seal_payload
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        p = tmp_path / "a.reseal.json"
        p.write_text(json.dumps(art))
        rc = cli_main(["verify", str(p), "--expect-kid", "sha256:deadbeef",
                       "--tsa-roots", str(tmp_path / "nonexistent")])
        assert rc in (0, 1, 3)  # a real verdict, not a crash/usage error

    def test_bad_rfc3161_block_fails_clean(self, keys):
        artifact = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        artifact["rfc3161"] = {"token_b64": base64.b64encode(b"garbage").decode(),
                               "tsa_url": "http://evil.example"}
        report = verify_artifact(artifact, file_bytes=CONTENT)
        assert report["ok"] is False


class TestMalformedInputs:
    """Boundary 1: attacker-controlled files into inspect/seal."""

    @pytest.mark.parametrize("blob,name", [
        (b"", "empty.txt"),
        (b"%PDF-1.7\n/ByteRange [0 5 3 2] junk", "bad_range.pdf"),
        (b"%PDF-1.7\n/ByteRange [0 999999 1000000 5] x", "oob_range.pdf"),
        (b"%PDF-1.7\n" + b"A" * 64, "unsigned.pdf"),
        (b"\x30\x82\xff\xff garbage der", "junk.p7s"),
        (os.urandom(512), "random.bin"),
    ])
    def test_hostile_bytes_never_crash(self, blob, name):
        payload = build_attestation_payload(blob, name)
        assert payload["subject"]["size"] == len(blob)
        for sig in payload["classical"].get("signatures", []):
            assert sig.get("verified") is not True or "error" not in sig

    def test_detached_p7s_alone_is_honest(self):
        cms = _make_cms(CONTENT, hashes.SHA256())
        block = classical.inspect_bytes(cms, "sig.p7s")
        sig = block["signatures"][0]
        assert not sig.get("verified")
        assert "detached" in sig.get("error", "")


class TestEvidenceQualityFlags:
    def test_sha1_cms_flagged_weak(self):
        # cryptography refuses to BUILD SHA-1 CMS (correctly), but legacy
        # SHA-1 blobs exist in the wild; rewrite a SHA-256 CMS's digest
        # algorithm to sha1 to exercise the flag path.
        from asn1crypto import cms as a_cms
        ci = a_cms.ContentInfo.load(_make_cms(CONTENT, hashes.SHA256()))
        ci["content"]["signer_infos"][0]["digest_algorithm"] = {"algorithm": "sha1"}
        block = classical.inspect_detached(CONTENT, ci.dump(force=True))
        sig = block["signatures"][0]
        assert sig["weak_digest"] is True
        assert not sig.get("verified")  # digest no longer matches - also correct

    def test_sha256_cms_not_flagged(self):
        cms = _make_cms(CONTENT, hashes.SHA256())
        sig = classical.inspect_detached(CONTENT, cms)["signatures"][0]
        assert sig["weak_digest"] is False
        assert sig["verified"] is True

    def test_pdf_partial_coverage_flagged(self):
        # Build a synthetic signed-pdf shape, then append an unsigned revision.
        cms = _make_cms(CONTENT, hashes.SHA256())
        hexs = cms.hex().encode()
        head = b"%PDF-1.7\nrev1 "
        tail = b" rev1-end"
        marker_len = len(b"/ByteRange [%010d %010d %010d %010d] /Contents <" % (0, 0, 0, 0))
        c = len(head) + marker_len + len(hexs) + 1
        marker = (b"/ByteRange [%010d %010d %010d %010d] /Contents <"
                  % (0, len(head), c, len(tail)))
        pdf = head + marker + hexs + b">" + tail
        shadow = pdf + b"\nrev2: totally different rendered content\n%%EOF\n"
        sigs = classical.inspect_bytes(shadow, "shadow.pdf")["signatures"]
        assert sigs[0]["covers_entire_file"] is False
        assert "coverage_note" in sigs[0]

    def test_cert_fingerprint_is_full_der(self):
        import hashlib as h
        cms = _make_cms(CONTENT, hashes.SHA256())
        sig = classical.inspect_detached(CONTENT, cms)["signatures"][0]
        der = base64.b64decode(sig["cert_chain_der_b64"][0])
        assert sig["signer_cert_sha256"] == h.sha256(der).hexdigest()
