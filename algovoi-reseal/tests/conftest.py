# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""Test licence harness.

Sealing is licence-gated (require_license), so the test suite installs a TEST
issuer key over the embedded production one and mints valid licences signed by
it. Real production licences are signed by AlgoVoi's private key (not in the
repo); tests never need it. The default fixture gives every seal test a valid
licence; licensing tests override the env to exercise the fail-closed paths.
"""
from __future__ import annotations

import base64
import json
import os
import sys

import pytest
import rfc8785
from pqcrypto.sign.falcon_1024 import generate_keypair, sign

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@pytest.fixture(scope="session")
def _issuer_sk():
    """Generate a test issuer keypair and swap its pubkey in for the embedded
    production one, so test-minted licences verify."""
    import algovoi_reseal.licensing as L
    pk, sk = generate_keypair()
    original = L._ISSUER_PUBKEY_B64
    L._ISSUER_PUBKEY_B64 = base64.b64encode(pk).decode()
    yield sk
    L._ISSUER_PUBKEY_B64 = original


@pytest.fixture
def mint(_issuer_sk):
    """Mint a licence key signed by the test issuer."""
    def _m(package="algovoi-reseal", expires="2099-01-01T00:00:00Z",
           typ="oem_license", bundle=None):
        payload = {"type": typ, "package": package, "expires_at": expires}
        if bundle is not None:
            payload["bundle"] = bundle
        env = {"payload": payload, "sig": _b64u(sign(_issuer_sk, rfc8785.dumps(payload)))}
        return _b64u(json.dumps(env).encode())
    return _m


@pytest.fixture(autouse=True)
def _default_license(_issuer_sk, mint, monkeypatch):
    """Every test gets a valid licence unless it overrides ALGOVOI_LICENSE_KEY."""
    monkeypatch.setenv("ALGOVOI_LICENSE_KEY", mint())
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)
    yield
