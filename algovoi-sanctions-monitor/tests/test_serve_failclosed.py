# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""The shipped serve target must FAIL CLOSED (security fix 2026-08-19):

- it must NOT silently screen with an allow-all screener (which would clear every sanctioned address and
  can emit a signed "cleared" delta for a sanctioned party); allow-all is an explicit dev opt-in only,
- it must refuse a non-loopback bind without an API token.
"""
from __future__ import annotations

import pytest

from algovoi_sanctions_monitor.screener import AllowAllScreener, DenylistScreener
from algovoi_sanctions_monitor.serve import _screener, build_app


def test_refuses_to_start_without_a_screener(monkeypatch):
    for v in ("SCREEN_URL", "SCREEN_DENY_LIST", "SCREEN_REFER_LIST", "MONITOR_ALLOW_INSECURE_SCREENER"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuntimeError, match="without a screener"):
        _screener()


def test_allow_all_requires_explicit_opt_in(monkeypatch):
    for v in ("SCREEN_URL", "SCREEN_DENY_LIST", "SCREEN_REFER_LIST"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("MONITOR_ALLOW_INSECURE_SCREENER", "1")
    assert isinstance(_screener(), AllowAllScreener)


def test_deny_list_builds_a_denylist_screener(monkeypatch):
    monkeypatch.delenv("SCREEN_URL", raising=False)
    monkeypatch.delenv("MONITOR_ALLOW_INSECURE_SCREENER", raising=False)
    monkeypatch.setenv("SCREEN_DENY_LIST", "voi:SANCTIONED1, eth:0xbad")
    monkeypatch.delenv("SCREEN_REFER_LIST", raising=False)
    assert isinstance(_screener(), DenylistScreener)


def test_public_bind_without_token_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("MONITOR_ALLOW_INSECURE_SCREENER", "1")
    monkeypatch.setenv("MONITOR_HOST", "0.0.0.0")
    monkeypatch.delenv("MONITOR_API_TOKEN", raising=False)
    monkeypatch.setenv("MONITOR_KEY_FILE", str(tmp_path / "k.json"))
    monkeypatch.setenv("MONITOR_DB", str(tmp_path / "m.db"))
    with pytest.raises(RuntimeError, match="non-loopback"):
        build_app()


def test_loopback_default_builds(monkeypatch, tmp_path):
    monkeypatch.setenv("MONITOR_ALLOW_INSECURE_SCREENER", "1")
    monkeypatch.delenv("MONITOR_HOST", raising=False)          # default loopback
    monkeypatch.delenv("MONITOR_API_TOKEN", raising=False)
    monkeypatch.setenv("MONITOR_KEY_FILE", str(tmp_path / "k.json"))
    monkeypatch.setenv("MONITOR_DB", str(tmp_path / "m.db"))
    assert build_app() is not None
