"""
Hub key resolution — fetch and cache public keys from /.well-known/atb-keys.json.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_KEY_CACHE: dict[str, dict] = {}


async def fetch_hub_keys(keys_url: str) -> dict | None:
    """Fetch the ATB hub keys document from a /.well-known/atb-keys.json URL.

    Returns the parsed document (cached in-process) or None on failure.
    """
    if keys_url in _KEY_CACHE:
        return _KEY_CACHE[keys_url]
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(keys_url)
            resp.raise_for_status()
            doc = resp.json()
            _KEY_CACHE[keys_url] = doc
            return doc
    except Exception as exc:
        logger.warning("hub_resolver.fetch_failed", extra={"url": keys_url, "err": str(exc)})
        return None


def clear_key_cache() -> None:
    """Clear the in-process key cache (useful for testing or key rotation)."""
    _KEY_CACHE.clear()
