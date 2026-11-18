# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""Test licence harness — swaps a test issuer key over the embedded prod one and
mints valid licences so report-signing tests can run. Real licences are signed
by AlgoVoi's private key (not in the repo)."""
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
    import algovoi_evidence_audit.licensing as L
    pk, sk = generate_keypair()
    original = L._ISSUER_PUBKEY_B64
    L._ISSUER_PUBKEY_B64 = base64.b64encode(pk).decode()
    yield sk
    L._ISSUER_PUBKEY_B64 = original


@pytest.fixture
def mint(_issuer_sk):
    def _m(package="algovoi-evidence-audit", expires="2099-01-01T00:00:00Z",
           typ="oem_license", bundle=None):
        payload = {"type": typ, "package": package, "expires_at": expires}
        if bundle is not None:
            payload["bundle"] = bundle
        env = {"payload": payload, "sig": _b64u(sign(_issuer_sk, rfc8785.dumps(payload)))}
        return _b64u(json.dumps(env).encode())
    return _m


@pytest.fixture(autouse=True)
def _default_license(_issuer_sk, mint, monkeypatch):
    monkeypatch.setenv("ALGOVOI_LICENSE_KEY", mint())
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)
    yield
