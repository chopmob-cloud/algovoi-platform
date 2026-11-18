"""Test harness: bypass runtime licence enforcement (never shipped in the wheel)."""
import pytest

from algovoi_crypto_agility import licensing


@pytest.fixture(autouse=True)
def _bypass_license(monkeypatch):
    monkeypatch.setattr(
        licensing, "require_license",
        lambda *a, **k: {"package": licensing.PACKAGE_NAME, "tier": "test"},
    )
