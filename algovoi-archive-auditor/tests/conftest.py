"""Test harness: bypass runtime licence enforcement.

The shipped package refuses to construct its engine without a valid AlgoVoi OEM licence
(`licensing.require_license`). The vendor's own unit tests + build-smoke don't carry a prod-signed
licence, so they neutralise the check here. This bypass lives only in the test tree — it is never
shipped in the wheel, so real installs stay enforced.
"""
import pytest

from algovoi_archive_auditor import licensing


@pytest.fixture(autouse=True)
def _bypass_license(monkeypatch):
    monkeypatch.setattr(
        licensing, "require_license",
        lambda *a, **k: {"package": licensing.PACKAGE_NAME, "tier": "test"},
    )
