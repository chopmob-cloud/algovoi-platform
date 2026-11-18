"""Hub registration for the retention app (stdlib only, no extra dependency).

Self-registers with a Compliance Command Center live-service bridge (and/or the
substrate-2 control plane) so the service appears in the console's "Live service
health" panel. POST <hub>/v1/services with a Bearer token and a JSON body of
{name, type, base_url, health_path}. Best-effort: never raises, so an absent or
unreachable hub cannot stop the service from booting.
"""
from __future__ import annotations

import json
import os
import urllib.request


def _post_register(hub: str, token: str, *, name: str, self_url: str,
                   type_: str = "retention-app", health_path: str = "/health",
                   timeout: float = 5.0) -> bool:
    body = json.dumps({"name": name, "type": type_,
                       "base_url": self_url.rstrip("/"), "health_path": health_path}).encode()
    req = urllib.request.Request(
        hub.rstrip("/") + "/v1/services", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return 200 <= r.status < 300
    except Exception:
        return False


def register_into_ccc_from_env(*, timeout: float = 5.0) -> bool:
    """Register with a Compliance Command Center if CCC_HUB_* is configured."""
    hub = os.environ.get("CCC_HUB_URL", "").strip()
    tok = os.environ.get("CCC_HUB_TOKEN", "").strip()
    name = os.environ.get("CCC_HUB_NAME", "retention-app").strip() or "retention-app"
    self_url = os.environ.get("CCC_HUB_SELF_URL", "").strip()
    if not (hub and tok and self_url):
        return False
    return _post_register(hub, tok, name=name, self_url=self_url, timeout=timeout)


def register_into_s2_from_env(*, timeout: float = 5.0) -> bool:
    """Register with the substrate-2 control plane if S2_HUB_* is configured."""
    hub = os.environ.get("S2_HUB_URL", "").strip()
    tok = os.environ.get("S2_HUB_TOKEN", "").strip()
    name = os.environ.get("S2_HUB_NAME", "retention-app").strip() or "retention-app"
    self_url = os.environ.get("S2_HUB_SELF_URL", "http://retention-app:8097").strip()
    if not (hub and tok):
        return False
    return _post_register(hub, tok, name=name, self_url=self_url, timeout=timeout)
