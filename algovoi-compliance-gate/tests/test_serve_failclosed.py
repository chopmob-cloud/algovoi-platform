# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""The shipped serve target must FAIL CLOSED (security fix 2026-08-19):

- it must NOT silently screen with an allow-all screener (which would sign a compliant ALLOW for a
  sanctioned address); allow-all is an explicit dev opt-in only,
- it must refuse a non-loopback bind without an API token.
"""
from __future__ import annotations

import pytest

from algovoi_compliance_gate.screener import AllowAllScreener, DenylistScreener
from algovoi_compliance_gate.serve import _build_screener, build_app


def test_refuses_to_start_without_a_screener(monkeypatch):
    monkeypatch.delenv("GATE_ALLOW_ALL_SCREENER", raising=False)
    monkeypatch.delenv("GATE_DENY_LIST", raising=False)
    monkeypatch.delenv("GATE_REFER_LIST", raising=False)
    with pytest.raises(RuntimeError, match="without a screener"):
        _build_screener()


def test_allow_all_requires_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("GATE_DENY_LIST", raising=False)
    monkeypatch.delenv("GATE_REFER_LIST", raising=False)
    monkeypatch.setenv("GATE_ALLOW_ALL_SCREENER", "1")
    assert isinstance(_build_screener(), AllowAllScreener)


def test_deny_list_builds_a_list_screener(monkeypatch):
    monkeypatch.delenv("GATE_ALLOW_ALL_SCREENER", raising=False)
    monkeypatch.setenv("GATE_DENY_LIST", "addr:sanctioned1, addr:sanctioned2")
    monkeypatch.delenv("GATE_REFER_LIST", raising=False)
    s = _build_screener()
    assert isinstance(s, DenylistScreener)


def test_public_bind_without_token_is_refused(monkeypatch):
    # allow-all opt-in so the screener step passes; the bind guard is what must reject.
    monkeypatch.setenv("GATE_ALLOW_ALL_SCREENER", "1")
    monkeypatch.setenv("GATE_HOST", "0.0.0.0")
    monkeypatch.delenv("GATE_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="non-loopback"):
        build_app()


def test_loopback_default_builds(monkeypatch, tmp_path):
    monkeypatch.setenv("GATE_ALLOW_ALL_SCREENER", "1")
    monkeypatch.delenv("GATE_HOST", raising=False)          # default loopback
    monkeypatch.delenv("GATE_API_TOKEN", raising=False)
    monkeypatch.setenv("GATE_KEY_FILE", str(tmp_path / "k.json"))
    app = build_app()                                       # licence bypassed by autouse fixture
    assert app is not None
