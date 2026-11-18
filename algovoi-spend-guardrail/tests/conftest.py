"""Test harness: bypass runtime licence enforcement.

The shipped package refuses to construct its engine without a valid AlgoVoi OEM licence
(`licensing.require_license`). The vendor's own unit tests + build-smoke don't carry a prod-signed
licence, so they neutralise the check here. This bypass lives only in the test tree — it is never
shipped in the wheel, so real installs stay enforced.
"""
import pytest

from algovoi_agent_passport import licensing as passport_licensing
from algovoi_payment_mandate import licensing as mandate_licensing

from algovoi_spend_guardrail import licensing


@pytest.fixture(autouse=True)
def _bypass_license(monkeypatch):
    # The guardrail composes the Agent Passport + Payment Mandate engines, each of which enforces its
    # own licence at construction. Neutralise all three here so the vendor's own unit tests run without
    # a prod-signed licence. This bypass lives only in the test tree — it is never shipped in a wheel.
    for mod in (licensing, passport_licensing, mandate_licensing):
        monkeypatch.setattr(
            mod, "require_license",
            lambda *a, _m=mod, **k: {"package": _m.PACKAGE_NAME, "tier": "test"},
        )
