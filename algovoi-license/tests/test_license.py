"""Fail-closed behaviour of the shared licence gate. A valid-licence path is proven end to end against
a real suite licence in the deploy checks (same code the rest of the suite already runs on)."""
from __future__ import annotations

import pytest

import algovoi_license as lic


def test_no_licence_fails_closed(monkeypatch):
    monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)
    with pytest.raises(lic.LicenseError) as e:
        lic.require_license("algovoi-example-addon")
    assert "algovoi-example-addon" in str(e.value)


def test_malformed_and_wrong_type_rejected():
    ok, reason = lic.verify_license_offline("not-a-real-key")
    assert not ok and reason in ("malformed licence key", "pqcrypto unavailable", "rfc8785 unavailable")


def test_soft_crypto_absent_fails_closed(monkeypatch):
    # if the suite crypto is not importable (a lifted standalone install), verification refuses
    monkeypatch.setattr(lic, "_HAS_FALCON", False)
    ok, reason = lic.verify_license_offline("anything")
    assert not ok and reason == "pqcrypto unavailable"
