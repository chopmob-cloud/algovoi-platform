"""hub_client — self-register Records Vault with the Compliance Command Center.

A standalone, stdlib-only (~50 line) copy of the Command Center's hub_client: with
the CCC_HUB_* env vars set, Records Vault registers itself with the console on boot
so it shows up in the "Live service health" panel, and the console then polls this
service's /health on demand. This adds *live health* alongside the *evidence* the
vault already exports — the evidence path is unchanged.

    CCC_HUB_URL=http://command-center:8200  CCC_HUB_TOKEN=<service token>  \
    CCC_HUB_NAME=records-vault  CCC_HUB_SELF_URL=http://records-vault:8000

Carried as its own copy (not imported from the Command Center package) so the vault
depends only on algovoi-doc-archive. Registration is best-effort and never raises,
so an absent or unreachable Command Center cannot stop the vault from booting.
"""
from __future__ import annotations

import json
import os
import urllib.request


def register(*, hub_url: str | None = None, token: str | None = None, name: str | None = None,
             self_url: str | None = None, type_: str = "records-vault", health_path: str = "/health",
             timeout: float = 5.0) -> bool:
    """Self-register this service with the Command Center. Arguments fall back to the
    CCC_HUB_URL / CCC_HUB_TOKEN / CCC_HUB_NAME / CCC_HUB_SELF_URL env vars. Returns
    True on a 2xx, False otherwise (including when not configured). Never raises."""
    hub = (hub_url if hub_url is not None else os.environ.get("CCC_HUB_URL", "")).strip()
    tok = (token if token is not None else os.environ.get("CCC_HUB_TOKEN", "")).strip()
    nm = (name if name is not None else os.environ.get("CCC_HUB_NAME", "records-vault")).strip()
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
