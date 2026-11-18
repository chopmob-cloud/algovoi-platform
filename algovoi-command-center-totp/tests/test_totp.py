"""TOTP correctness tests, including the RFC 6238 Appendix B SHA-1 test vector, plus the licence gate."""
from __future__ import annotations

import base64

import pytest

import algovoi_command_center_totp as t
from algovoi_command_center_totp import licensing


@pytest.fixture()
def licensed(monkeypatch):
    """Bypass the licence gate for tests that construct the factor (no test signing key available)."""
    monkeypatch.setattr(licensing, "require_license", lambda: {"ok": True})


# RFC 6238 Appendix B uses the ASCII seed "12345678901234567890" (20 bytes) with SHA-1.
_SEED_B32 = base64.b32encode(b"12345678901234567890").decode()


def test_rfc6238_vector_6_digits():
    # At T=59s the 8-digit reference code is 94287082; its low 6 digits are 287082.
    assert t.totp_at(_SEED_B32, when=59) == "287082"
    assert t.verify(_SEED_B32, "287082", when=59)
    assert not t.verify(_SEED_B32, "000000", when=59)


def test_skew_window_and_rejects():
    secret = t._b32_secret()
    now = 1_000_000.0
    code = t.totp_at(secret, when=now)
    assert t.verify(secret, code, when=now)
    assert t.verify(secret, code, when=now + 29)          # same step
    assert t.verify(secret, code, when=now + 30)          # next step, within +/-1 window
    assert not t.verify(secret, code, when=now + 120)     # far outside the window
    assert not t.verify(secret, "12ab56")                 # non-numeric
    assert not t.verify(secret, "12345")                  # wrong length


def test_factor_requires_license(monkeypatch):
    # with no licence key present, constructing the factor fails closed
    monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)
    with pytest.raises(licensing.LicenseError):
        t.TotpFactor()


def test_enroll_shape_and_roundtrip(licensed):
    f = t.TotpFactor()
    assert f.name == "totp"
    e = f.enroll("alice")
    assert {"secret", "provisioning_uri", "instructions"} <= set(e)
    assert e["provisioning_uri"].startswith("otpauth://totp/")
    assert "secret=" in e["provisioning_uri"] and "issuer=" in e["provisioning_uri"]
    # a live code for the freshly enrolled secret verifies through the factor
    assert f.verify(e["secret"], t.totp_at(e["secret"]))


def test_qr_svg_generated_when_segno_present(licensed):
    import importlib.util
    if importlib.util.find_spec("segno") is None:
        pytest.skip("segno not installed")
    svg = t.qr_svg("otpauth://totp/Test:alice?secret=ABC234XYZ&issuer=Test")
    assert svg and svg.lstrip().startswith("<svg") and "</svg>" in svg
    assert "qr_svg" in t.TotpFactor().enroll("alice")
