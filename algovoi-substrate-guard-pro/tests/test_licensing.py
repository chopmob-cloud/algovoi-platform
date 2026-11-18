"""Fail-closed licence enforcement at the gate constructor."""
import pytest

from algovoi_substrate_guard_pro import GuardService, signing
from algovoi_substrate_guard_pro.licensing import LicenseError


def test_service_refuses_without_license(monkeypatch):
    monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)
    pk, sk = signing.generate_keypair()
    with pytest.raises(LicenseError):
        GuardService(decision_secret_key=sk, decision_public_key=pk)  # no _skip_license
