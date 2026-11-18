"""Tiny client for the substrate-2 control plane hub. Standard library only — no
new dependencies, so the service stays self-contained.

  fetch_issuer_pks(hub_url)  -> {did: pk_b64}   live trust-pull from the CP
  self_register(hub_url, token, ...)            register this service in the CP

Drop-in usage: set ``S2_HUB_URL`` (and ``S2_HUB_TOKEN`` to self-register) and the
service pulls its issuer trust set from the control plane and announces itself.
"""
from __future__ import annotations

import json
import urllib.request


def fetch_issuer_pks(hub_url: str, *, timeout: float = 5.0) -> dict[str, str]:
    """GET ``<hub>/v1/issuer-pks`` and return the ``{did: pk_b64}`` trust map."""
    url = hub_url.rstrip("/") + "/v1/issuer-pks"
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (internal hub URL)
        data = json.loads(resp.read().decode("utf-8"))
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def self_register(hub_url: str, token: str, *, name: str, type_: str, base_url: str,
                  health_path: str = "/health", timeout: float = 5.0) -> bool:
    """POST ``<hub>/v1/services`` to register this service/addon with the control
    plane so it appears in the posture. Returns True on success, False otherwise."""
    body = json.dumps({
        "name": name, "type": type_, "base_url": base_url, "health_path": health_path,
    }).encode("utf-8")
    req = urllib.request.Request(
        hub_url.rstrip("/") + "/v1/services", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except Exception:
        return False
