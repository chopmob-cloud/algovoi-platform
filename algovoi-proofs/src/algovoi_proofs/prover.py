"""
Async client for an external Bulletproofs range-proof service (URL injected).

The proof math (commitment + range proof that score >= threshold) is produced by a stateless
service — point this at your own. Compatible with the ATB Bulletproofs service
(transcript ``ATB-RangeProof-v1``, Ristretto255, scores in milliunits 0..1000).
"""
from __future__ import annotations

import httpx


class ProverUnavailable(RuntimeError):
    """Raised when the range-proof service is unreachable or returns an error."""


class ProverClient:
    def __init__(self, base_url: str, *, timeout: float = 8.0) -> None:
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    async def prove(self, score_milliunits: int, threshold_milliunits: int) -> dict:
        """Return ``{commitment_b64, proof_b64, ...}``. Raises ProverUnavailable."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(f"{self.base}/prove", json={
                    "score_milliunits": score_milliunits, "threshold_milliunits": threshold_milliunits})
                r.raise_for_status()
                return r.json()
        except Exception as e:  # noqa: BLE001
            raise ProverUnavailable(str(e)) from e

    async def verify_range(self, commitment_b64: str, proof_b64: str, threshold_milliunits: int) -> dict:
        """Return ``{valid: bool, ...}``. Raises ProverUnavailable on transport error."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(f"{self.base}/verify", json={
                    "commitment_b64": commitment_b64, "proof_b64": proof_b64,
                    "threshold_milliunits": threshold_milliunits})
                r.raise_for_status()
                return r.json()
        except Exception as e:  # noqa: BLE001
            raise ProverUnavailable(str(e)) from e

    async def health(self) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(f"{self.base}/health")
            r.raise_for_status()
            return r.json()
