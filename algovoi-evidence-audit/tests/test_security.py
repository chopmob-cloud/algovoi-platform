# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""Adversarial: hostile files must not crash the batch runner or produce a false
'verified'; licence bypass battery; report tamper."""
from __future__ import annotations

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from algovoi_evidence_audit import run_audit, sign_report, LicenseError
from algovoi_evidence_audit.signer import generate_keys, load_keys
from algovoi_evidence_audit import licensing as L


@pytest.fixture
def keys(tmp_path):
    generate_keys(str(tmp_path / "ak"))
    return load_keys(str(tmp_path / "ak"))


class TestHostileInputs:
    def test_hostile_archive_never_crashes_and_no_false_verified(self, tmp_path):
        d = tmp_path / "hostile"
        d.mkdir()
        (d / "empty.txt").write_bytes(b"")
        (d / "bad.pdf").write_bytes(b"%PDF-1.7\n/ByteRange [0 5 3 2] junk")
        (d / "oob.pdf").write_bytes(b"%PDF-1.7\n/ByteRange [0 999999 1000000 5] x")
        (d / "junk.p7s").write_bytes(b"\x30\x82\xff\xff not der")
        (d / "rand.bin").write_bytes(os.urandom(400))
        (d / "huge_digits.pdf").write_bytes(b"%PDF-1.7\n/ByteRange [0 " + b"9" * 5000 + b" 1 1] x")
        (d / "fake.reseal.json").write_text('{"format":"x"}')
        rep = run_audit([str(d)])                      # must not raise
        assert rep["summary"]["total"] == 7
        for f in rep["findings"]:
            assert f["verified"] is not True           # nothing hostile counts as verified

    def test_bad_zip_skipped(self, tmp_path):
        (tmp_path / "broken.zip").write_bytes(b"PK\x03\x04 not really a zip")
        rep = run_audit([str(tmp_path / "broken.zip")])
        assert rep["summary"]["total"] == 0

    def test_zip_bomb_bounded(self, tmp_path):
        import zipfile
        z = tmp_path / "b.zip"
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", b"\x00" * (2 * 1024 * 1024))  # 2MB, under cap
        rep = run_audit([str(z)])
        assert rep["summary"]["total"] == 1  # decompresses, bounded by _MAX_FILE


class TestReselAttestationTrust:
    """A genuine, internally-valid reseal artifact minted by an unknown key must NOT count as verified
    unless it is anchored to a pinned kid AND bound to the actual archived subject (fix 2026-08-19)."""

    def _mint(self, tmp_path, subdir, subject: bytes, filename="report.json"):
        from algovoi_evidence_audit.signer import sign_bytes
        kd = tmp_path / subdir
        info = generate_keys(str(kd))
        art = sign_bytes(subject, load_keys(str(kd)), filename=filename)
        return info, art

    def test_self_signed_reseal_is_not_verified_without_anchor(self, tmp_path):
        subject = b'{"finding":"attacker-controlled","amount":0}'
        _info, art = self._mint(tmp_path, "attacker", subject)
        d = tmp_path / "arc"; d.mkdir()
        (d / "report.json").write_bytes(subject)
        (d / "report.json.reseal.json").write_text(json.dumps(art))
        rep = run_audit([str(d)])                      # no pinned kid
        reseal = next(f for f in rep["findings"] if f["path"].endswith(".reseal.json"))
        assert reseal["verified"] is not True          # signer not pinned -> self-asserted, not verified
        assert "unanchored" in reseal["flags"]

    def test_reseal_verified_only_when_anchored_and_subject_bound(self, tmp_path):
        subject = b'{"finding":"legit"}'
        info, art = self._mint(tmp_path, "auditor", subject)
        d = tmp_path / "arc"; d.mkdir()
        (d / "report.json").write_bytes(subject)
        (d / "report.json.reseal.json").write_text(json.dumps(art))
        rep = run_audit([str(d)], expected_kid=info["falcon_kid"])
        reseal = next(f for f in rep["findings"] if f["path"].endswith(".reseal.json"))
        assert reseal["verified"] is True and "unanchored" not in reseal["flags"]

    def test_reseal_with_tampered_subject_not_verified(self, tmp_path):
        info, art = self._mint(tmp_path, "auditor", b"ORIGINAL")
        d = tmp_path / "arc"; d.mkdir()
        (d / "report.json").write_bytes(b"TAMPERED-DIFFERENT-BYTES")   # subject no longer matches
        (d / "report.json.reseal.json").write_text(json.dumps(art))
        rep = run_audit([str(d)], expected_kid=info["falcon_kid"])
        reseal = next(f for f in rep["findings"] if f["path"].endswith(".reseal.json"))
        assert reseal["verified"] is not True          # subject sha256 mismatch


class TestLicenceBypass:
    def _try(self, keys, env):
        if env is None:
            os.environ.pop("ALGOVOI_LICENSE_KEY", None)
        else:
            os.environ["ALGOVOI_LICENSE_KEY"] = env
        os.environ.pop("ALGOVOI_LICENSE_FILE", None)
        try:
            sign_report({"type": "evidence_audit_report", "v": 1, "run_at_ms": 0,
                         "scope": {"root": "x", "file_count": 0}, "summary": {}, "findings": []}, keys)
            return "SIGNED"
        except LicenseError:
            return "blocked"

    def test_bypass_battery(self, keys, mint):
        assert self._try(keys, None) == "blocked"
        assert self._try(keys, "") == "blocked"
        assert self._try(keys, "garbage") == "blocked"
        assert self._try(keys, mint(package="algovoi-reseal")) == "blocked"          # wrong package
        assert self._try(keys, mint(expires="2000-01-01T00:00:00Z")) == "blocked"    # expired
        # attacker-signed (own key): forge a licence under a different issuer
        from pqcrypto.sign.falcon_1024 import generate_keypair, sign
        import rfc8785
        apk, ask = generate_keypair()
        p = {"type": "oem_license", "package": "algovoi-evidence-audit", "expires_at": "2099-01-01T00:00:00Z"}
        env = {"payload": p, "sig": base64.urlsafe_b64encode(sign(ask, rfc8785.dumps(p))).decode().rstrip("=")}
        forged = base64.urlsafe_b64encode(json.dumps(env).encode()).decode().rstrip("=")
        assert self._try(keys, forged) == "blocked"
        # valid + on-prem bundle
        assert self._try(keys, mint()) == "SIGNED"
        assert self._try(keys, mint(typ="bundle_license", bundle="algovoi-substrate2-onprem")) == "SIGNED"
