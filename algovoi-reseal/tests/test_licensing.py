# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""Licence-gating on the seal (minting) path — fail-closed, offline, per-package.

Inspection and verification are NOT gated (they live in the open package); only
seal_payload requires a licence.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from algovoi_reseal import (  # noqa: E402
    build_attestation_payload, seal_payload, verify_artifact,
    generate_keys, load_keys, LicenseError,
)
from algovoi_reseal.licensing import require_license, verify_license_offline

CONTENT = b"licensed minting\n"


@pytest.fixture
def keys(tmp_path):
    d = str(tmp_path / "k")
    generate_keys(d)  # keygen is NOT gated
    return load_keys(d)


class TestSealGate:
    def test_seal_works_with_valid_license(self, keys):
        # _default_license (conftest) provides one.
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        assert verify_artifact(art, file_bytes=CONTENT)["ok"] is True

    def test_seal_fails_without_license(self, keys, monkeypatch):
        monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
        with pytest.raises(LicenseError):
            seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)

    def test_seal_fails_expired_license(self, keys, mint, monkeypatch):
        monkeypatch.setenv("ALGOVOI_LICENSE_KEY", mint(expires="2000-01-01T00:00:00Z"))
        with pytest.raises(LicenseError):
            seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)

    def test_seal_fails_wrong_package_license(self, keys, mint, monkeypatch):
        monkeypatch.setenv("ALGOVOI_LICENSE_KEY", mint(package="algovoi-records-vault"))
        with pytest.raises(LicenseError):
            seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)

    def test_keygen_is_not_gated(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
        info = generate_keys(str(tmp_path / "k2"))  # must NOT raise
        assert info["falcon_kid"].startswith("sha256:")

    def test_verify_is_not_gated(self, keys, mint, monkeypatch):
        # Seal (with licence), then drop the licence and verify: must still work.
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
        assert verify_artifact(art, file_bytes=CONTENT)["ok"] is True


class TestLicenseVerification:
    def test_bundle_license_accepted(self, keys, mint, monkeypatch):
        # The on-prem bundle licence unlocks every estate package, reseal included.
        monkeypatch.setenv("ALGOVOI_LICENSE_KEY",
                           mint(typ="bundle_license", bundle="algovoi-substrate2-onprem"))
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        assert verify_artifact(art, file_bytes=CONTENT)["ok"] is True

    def test_wrong_bundle_rejected(self, mint):
        ok, reason = verify_license_offline(
            mint(typ="bundle_license", bundle="some-other-bundle"))
        assert ok is False

    def test_tampered_signature_rejected(self, mint):
        key = mint()
        bad = key[:-4] + ("AAAA" if key[-4:] != "AAAA" else "BBBB")
        ok, _ = verify_license_offline(bad)
        assert ok is False

    def test_malformed_license_rejected(self):
        ok, reason = verify_license_offline("not-a-real-licence")
        assert ok is False
