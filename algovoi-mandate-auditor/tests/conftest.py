"""Test harness: bypass runtime licence enforcement.

Both the payment-mandate issuer and the mandate auditor enforce licensing.
This conftest patches both so tests run without a real AlgoVoi OEM key.
The bypasses live only in the test tree and are never shipped in the wheel.
"""
import pytest

from algovoi_payment_mandate import licensing as mandate_licensing
from algovoi_mandate_auditor import licensing as auditor_licensing


@pytest.fixture(autouse=True)
def _bypass_license(monkeypatch):
    monkeypatch.setattr(
        mandate_licensing, "require_license",
        lambda *a, **k: {"package": mandate_licensing.PACKAGE_NAME, "tier": "test"},
    )
    monkeypatch.setattr(
        auditor_licensing, "require_license",
        lambda *a, **k: {"package": auditor_licensing.PACKAGE_NAME, "tier": "test"},
    )
