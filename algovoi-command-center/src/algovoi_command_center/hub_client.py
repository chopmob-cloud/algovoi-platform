"""hub_client — the ~50 lines a product copies (or imports) to plug into the
Compliance Command Center's live service bridge.

On boot, with the CCC_HUB_* env vars set, a product self-registers with the
Command Center so it appears in the console's "Live service health" panel. The
Command Center then polls the product's /health on demand. This adds *live health*
alongside the *evidence posture* a product already exports — the evidence path is
unchanged.

    CCC_HUB_URL=http://command-center:8200  CCC_HUB_TOKEN=<service token>  \
    CCC_HUB_NAME=records-vault  CCC_HUB_SELF_URL=http://records-vault:8000  python -m yourapp

A non-Python product makes the same single call: POST /v1/services with a Bearer
token and a JSON body of {name, type, base_url, health_path}. Registration is
best-effort: it never raises, so a missing or unreachable Command Center cannot
stop the product from booting.
"""
from __future__ import annotations

import json
import os
import urllib.request


def register(*, hub_url: str | None = None, token: str | None = None, name: str | None = None,
             self_url: str | None = None, type_: str = "product", health_path: str = "/health",
             timeout: float = 5.0) -> bool:
    """Self-register this product with the Command Center. Arguments fall back to the
    CCC_HUB_URL / CCC_HUB_TOKEN / CCC_HUB_NAME / CCC_HUB_SELF_URL env vars. Returns
    True on a 2xx, False otherwise (including when not configured). Never raises."""
    hub = (hub_url if hub_url is not None else os.environ.get("CCC_HUB_URL", "")).strip()
    tok = (token if token is not None else os.environ.get("CCC_HUB_TOKEN", "")).strip()
    nm = (name if name is not None else os.environ.get("CCC_HUB_NAME", "")).strip()
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
    """Best-effort self-register from the CCC_HUB_* env vars. Safe to call on boot:
    does nothing and returns False if the env vars are not set."""
    return register()
