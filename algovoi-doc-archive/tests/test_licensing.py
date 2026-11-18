"""Licence verification tests.

Added 2026-11-14 because a reviewer flagged "INSUFFICIENT CONTEXT" on the licensing change and the
follow-up grep showed the real problem: `verify_license_offline` had NO test at all. tests/conftest.py
monkeypatches `require_license` away, so every other test bypasses licensing entirely. That means the
`bundle_license` acceptance path added that day was unexercised: a wrong bundle name, an expired bundle
licence, or an oem licence that stopped verifying would all have shipped green.

The issuer public key is module state, so these tests swap in a test keypair and sign with it. That is
deliberate: the production private key is not available here, and patching the key is the only way to
drive the real verification code rather than a stub.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from algovoi_doc_archive import licensing, signing

# tests/conftest.py installs an AUTouse fixture that replaces licensing.require_license with a stub for
# every test in the suite (so the other 30 tests never need a real licence). The two tests at the bottom
# of this file exist to exercise the real function, so they capture it at import time — before any
# fixture has run — and put it back before calling.
_REAL_REQUIRE_LICENSE = licensing.require_license


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _future(days: int = 30) -> str:
    return _iso(datetime.now(timezone.utc) + timedelta(days=days))


def _past(days: int = 30) -> str:
    return _iso(datetime.now(timezone.utc) - timedelta(days=days))


def _licence(payload: dict, sk: bytes) -> str:
    sig = signing.sign_bytes(sk, __import__("rfc8785").dumps(payload))
    return _b64u(json.dumps({"payload": payload, "sig": _b64u(sig)}, separators=(",", ":")).encode())


@pytest.fixture
def issuer(monkeypatch):
    """Swap the embedded issuer key for a test keypair so licences can actually be signed."""
    pk, sk = signing.generate_keypair()
    monkeypatch.setattr(licensing, "_ISSUER_PUBKEY_B64", base64.b64encode(pk).decode())
    monkeypatch.setattr(licensing, "_PUBLIC_KEY_BYTES", len(pk))
    return pk, sk


def test_oem_licence_for_this_package_is_accepted(issuer):
    pk, sk = issuer
    key = _licence({"type": "oem_license", "package": licensing.PACKAGE_NAME,
                    "expires_at": _future()}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is True, reason


def test_oem_licence_for_another_package_is_refused(issuer):
    pk, sk = issuer
    key = _licence({"type": "oem_license", "package": "algovoi-something-else",
                    "expires_at": _future()}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False
    assert "not algovoi-doc-archive" in reason


def test_expired_oem_licence_is_refused(issuer):
    pk, sk = issuer
    key = _licence({"type": "oem_license", "package": licensing.PACKAGE_NAME,
                    "expires_at": _past()}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False and reason == "licence has expired"


def test_bundle_licence_is_accepted(issuer):
    """The 2026-11 running change: a substrate2 on-prem bundle licence runs every app in the bundle."""
    pk, sk = issuer
    key = _licence({"type": "bundle_license", "bundle": "algovoi-substrate2-onprem",
                    "expires_at": _future()}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is True, reason


def test_bundle_licence_for_a_different_bundle_is_refused(issuer):
    pk, sk = issuer
    key = _licence({"type": "bundle_license", "bundle": "algovoi-some-other-bundle",
                    "expires_at": _future()}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False
    assert "algovoi-some-other-bundle" in reason


def test_expired_bundle_licence_is_refused(issuer):
    pk, sk = issuer
    key = _licence({"type": "bundle_license", "bundle": "algovoi-substrate2-onprem",
                    "expires_at": _past()}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False and reason == "bundle licence has expired"


def test_bundle_licence_without_an_expiry_is_refused(issuer):
    """A missing expires_at must fail closed, not read as perpetual."""
    pk, sk = issuer
    key = _licence({"type": "bundle_license", "bundle": "algovoi-substrate2-onprem"}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False and reason == "bundle licence has expired"


@pytest.mark.parametrize("bad_type", ["archive_licence", "", "oem_licence"])
def test_unknown_licence_type_is_refused(issuer, bad_type):
    pk, sk = issuer
    key = _licence({"type": bad_type, "package": licensing.PACKAGE_NAME,
                    "expires_at": _future()}, sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False
    assert reason == "not a recognised AlgoVoi licence type"


def test_forged_signature_is_refused(issuer):
    """A payload signed by a DIFFERENT key must not verify against the issuer key."""
    pk, sk = issuer
    _, attacker_sk = signing.generate_keypair()
    key = _licence({"type": "oem_license", "package": licensing.PACKAGE_NAME,
                    "expires_at": _future()}, attacker_sk)
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False and reason == "signature verification failed"


def test_tampered_payload_is_refused(issuer):
    """Re-sign is impossible without the key, so flipping a field after signing must fail."""
    pk, sk = issuer
    payload = {"type": "oem_license", "package": "algovoi-other", "expires_at": _future()}
    sig = signing.sign_bytes(sk, __import__("rfc8785").dumps(payload))
    payload["package"] = licensing.PACKAGE_NAME          # escalate after signing
    key = _b64u(json.dumps({"payload": payload, "sig": _b64u(sig)},
                           separators=(",", ":")).encode())
    ok, reason = licensing.verify_license_offline(key)
    assert ok is False and reason == "signature verification failed"


def test_malformed_keys_are_refused(issuer):
    for bad in ("", "not-base64!!", _b64u(b"{}"), _b64u(b'{"payload":1}')):
        ok, reason = licensing.verify_license_offline(bad)
        assert ok is False, f"{bad!r} was accepted"
        assert reason in ("malformed licence key", "signature verification failed")


def test_require_license_raises_when_nothing_is_configured(monkeypatch):
    """Engine construction must stay fail-closed with no licence present."""
    monkeypatch.setattr(licensing, "require_license", _REAL_REQUIRE_LICENSE)
    monkeypatch.setattr(licensing, "_load_license_keys", lambda: [])
    with pytest.raises(licensing.LicenseError):
        licensing.require_license()


def test_require_license_accepts_a_valid_bundle_licence(issuer, monkeypatch):
    pk, sk = issuer
    key = _licence({"type": "bundle_license", "bundle": "algovoi-substrate2-onprem",
                    "expires_at": _future()}, sk)
    monkeypatch.setattr(licensing, "require_license", _REAL_REQUIRE_LICENSE)
    monkeypatch.setattr(licensing, "_load_license_keys", lambda: [key])
    payload = licensing.require_license()
    assert payload["type"] == "bundle_license"


def test_require_license_rejects_an_expired_licence_even_when_present(issuer, monkeypatch):
    """Fail-closed: a licence being configured is not the same as it being valid."""
    pk, sk = issuer
    key = _licence({"type": "oem_license", "package": licensing.PACKAGE_NAME,
                    "expires_at": _past()}, sk)
    monkeypatch.setattr(licensing, "require_license", _REAL_REQUIRE_LICENSE)
    monkeypatch.setattr(licensing, "_load_license_keys", lambda: [key])
    with pytest.raises(licensing.LicenseError):
        licensing.require_license()
