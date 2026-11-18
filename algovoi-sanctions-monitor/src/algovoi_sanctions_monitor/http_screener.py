"""
HTTP screener for the appliance. POSTs ``{network, address}`` to your screening endpoint and maps the
response to a verdict, so the monitor uses any screening service (the AlgoVoi ``/compliance/screen``, a
commercial feed, your own) without bundling a sanctions list. Raises on transport failure so the sweep
skips that subject rather than flipping its verdict.
"""
from __future__ import annotations

import httpx

from algovoi_sanctions_monitor.screener import SCREEN_RESULTS, ScreenResult


class HTTPScreener:
    def __init__(self, *, url: str, token: str | None = None,
                 provider_did: str = "did:web:screener", timeout: float = 8.0) -> None:
        self.url = url
        self.token = token
        self.provider_did = provider_did
        self.timeout = timeout

    async def screen(self, *, network: str, address: str, context: dict | None = None) -> ScreenResult:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        async with httpx.AsyncClient(timeout=self.timeout) as c:           # raises on network error -> sweep skips
            r = await c.post(self.url, json={"network": network, "address": address, "context": context or {}},
                             headers=headers)
            r.raise_for_status()
            d = r.json()
        result = str(d.get("result", "")).upper()
        if result not in SCREEN_RESULTS:
            result = "REFER"
        return ScreenResult(
            result=result,
            provider_did=d.get("provider_did") or d.get("screen_provider_did") or self.provider_did,
            risk_score=d.get("risk_score"),
            reasons=d.get("reasons"),
        )
