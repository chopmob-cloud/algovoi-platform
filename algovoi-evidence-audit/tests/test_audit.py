# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""Functional: mixed archive -> correct counts/flags; report verifies with the
FREE verifier; baseline diff; licence gate."""
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

from algovoi_evidence_audit import run_audit, sign_report, LicenseError
from algovoi_evidence_audit.signer import generate_keys, load_keys
from algovoi_reseal_verify import verify_artifact

CONTENT = b"a signed record that must stay provable\n"


@pytest.fixture
def keys(tmp_path):
    generate_keys(str(tmp_path / "ak"))
    return load_keys(str(tmp_path / "ak"))


def _detached_p7s(content, digest=hashes.SHA256()):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Records Signer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365)).sign(key, hashes.SHA256()))
    return (pkcs7.PKCS7SignatureBuilder().set_data(content).add_signer(cert, key, digest)
            .sign(serialization.Encoding.DER,
                  [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))


@pytest.fixture
def archive(tmp_path):
    d = tmp_path / "arc"
    d.mkdir()
    # 1: signed record + detached sig (valid)
    (d / "contract.txt").write_bytes(CONTENT)
    (d / "contract.txt.p7s").write_bytes(_detached_p7s(CONTENT))
    # 2: unsigned plain file
    (d / "notes.txt").write_bytes(b"just some notes")
    # 3: a tampered pairing (sig doesn't match content)
    (d / "invoice.txt").write_bytes(b"tampered body")
    (d / "invoice.txt.p7s").write_bytes(_detached_p7s(CONTENT))  # sig over different content
    return str(d)


class TestAudit:
    def test_counts(self, archive):
        rep = run_audit([archive])
        s = rep["summary"]
        assert s["total"] == 3            # contract, notes, invoice (the .p7s are evidence, not subjects)
        assert s["verified"] == 1         # contract verifies
        assert s["invalid"] == 1          # invoice sig doesn't match
        assert s["unsigned"] == 1         # notes
        assert s["quantum_exposed"] >= 1  # the valid RSA sig is quantum-exposed

    def test_report_is_signed_and_verifies_with_free_tool(self, archive, keys):
        rep = run_audit([archive])
        report_bytes, artifact = sign_report(rep, keys)
        # the FREE verifier must confirm the report attestation over the bytes
        result = verify_artifact(artifact, file_bytes=report_bytes)
        assert result["ok"] is True

    def test_tampered_report_detected(self, archive, keys):
        rep = run_audit([archive])
        report_bytes, artifact = sign_report(rep, keys)
        assert verify_artifact(artifact, file_bytes=report_bytes + b"x")["ok"] is False

    def test_baseline_diff(self, archive, keys, tmp_path):
        rep1 = run_audit([archive])
        # change one file
        with open(os.path.join(archive, "notes.txt"), "ab") as fh:
            fh.write(b" updated")
        rep2 = run_audit([archive], baseline=rep1)
        d = rep2["baseline_diff"]
        assert "notes.txt" in d["changed"]
        assert d["unchanged"] >= 1

    def test_zip_archive(self, tmp_path):
        import zipfile
        z = tmp_path / "records.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("a.txt", "hello")
            zf.writestr("b.txt", "world")
        rep = run_audit([str(z)])
        assert rep["summary"]["total"] == 2


class TestLicenceGate:
    def test_run_audit_requires_licence(self, archive, monkeypatch):
        # Gated at the engine, like every commercial app: no licence, no audit.
        monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
        with pytest.raises(LicenseError):
            run_audit([archive])

    def test_sign_requires_licence(self, archive, keys, monkeypatch):
        rep = run_audit([archive])   # has the autouse test licence
        monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
        with pytest.raises(LicenseError):
            sign_report(rep, keys)
