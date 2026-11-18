"""hub_client — self-register the Compliance Gate with the Command Center's live
service bridge, so it shows in the console's "Live service health" panel alongside its
evidence posture. Best-effort: never raises, so a missing hub can't stop the gate booting.

    CCC_HUB_URL=http://command-center:8200  CCC_HUB_TOKEN=<service token>  \\
    CCC_HUB_NAME=compliance-gate  CCC_HUB_SELF_URL=http://compliance-gate:8086  python -m yourapp
"""
from __future__ import annotations

import json
import os
import urllib.request


def register(*, hub_url: str | None = None, token: str | None = None, name: str | None = None,
             self_url: str | None = None, type_: str = "product", health_path: str = "/health",
             timeout: float = 5.0) -> bool:
    hub = (hub_url if hub_url is not None else os.environ.get("CCC_HUB_URL", "")).strip()
    tok = (token if token is not None else os.environ.get("CCC_HUB_TOKEN", "")).strip()
    nm = (name if name is not None else os.environ.get("CCC_HUB_NAME", "compliance-gate")).strip()
    url = (self_url if self_url is not None else os.environ.get("CCC_HUB_SELF_URL", "")).strip()
    if not (hub and tok and nm and url):
        return False
    body = json.dumps({"name": nm, "type": type_, "base_url": url.rstrip("/"),
                       "health_path": health_path}).encode()
    req = urllib.request.Request(
        hub.rstrip("/") + "/v1/services", data=body, method="POST",
        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310  # nosec B310 - trusted URL (indexer constant / operator-config hub); scheme is fixed http(s)
            return 200 <= r.status < 300
    except Exception:
        return False


def register_from_env() -> bool:
    """Best-effort self-register from the CCC_HUB_* env vars. Safe to call on boot."""
    return register()
