"""
substrate2.atb_credential_verifier — consumer-side ATB reputation credential verifier.

From atb-reputation-credential.mdx + atb-hub-conformance.mdx + the v1 verifier contract.
Reads an X-ATB-Credential / X-ATB-ZK-Credential header (a base64url Falcon-1024 envelope),
verifies it against the issuer's public key, and returns an ATBVerifyResult. Never raises;
returns valid=False on any failure. Phase 1 surfaces the cleartext score; Phase 2 surfaces
the ZKP commitment/proof/threshold.

Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .canon import canonicalize_bytes
from . import pqc

_ALG = "Falcon-1024"
_DEFAULT_ISSUER = "did:web:agent-trust-bench.algovoi.co.uk"
_DEFAULT_KEYS_URL = "https://agent-trust-bench.algovoi.co.uk/.well-known/atb-keys.json"

_KEY_CACHE: dict = {}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


@dataclass
class ATBVerifyResult:
    valid: bool
    passed: bool
    score: float | None
    expires_at: datetime | None
    kid: str | None
    failure_reason: str | None = None
    commitment_b64: str | None = None
    proof_b64: str | None = None
    threshold_milliunits: int | None = None

    @property
    def grants_discount(self) -> bool:
        return self.valid and self.passed

    @property
    def has_zkp(self) -> bool:
        return self.commitment_b64 is not None and self.proof_b64 is not None


def fetch_hub_keys(keys_url: str = _DEFAULT_KEYS_URL) -> dict:
    """Fetch and cache a hub's kid -> public_key_b64 map. (Network; cached per URL.)"""
    if keys_url in _KEY_CACHE:
        return _KEY_CACHE[keys_url]
    import urllib.request

    with urllib.request.urlopen(keys_url, timeout=10) as resp:  # noqa: S310
        doc = json.loads(resp.read().decode("utf-8"))
    keys = {k["kid"]: k["public_key_b64"] for k in doc.get("keys", [])}
    _KEY_CACHE[keys_url] = keys
    return keys


def clear_key_cache() -> None:
    _KEY_CACHE.clear()


class ATBCredentialVerifier:
    def __init__(
        self,
        issuer_did: str = _DEFAULT_ISSUER,
        public_key_b64: str | None = None,
        keys_url: str = _DEFAULT_KEYS_URL,
        cache_size: int = 1000,
        cache_ttl_s: int = 3600,
    ):
        self.issuer_did = issuer_did
        self.public_key_b64 = public_key_b64
        self.keys_url = keys_url
        self.cache_size = cache_size
        self.cache_ttl_s = cache_ttl_s
        self._result_cache: dict = {}

    def _fail(self, reason: str) -> ATBVerifyResult:
        return ATBVerifyResult(False, False, None, None, None, reason)

    def _resolve_key(self, kid: str) -> bytes | None:
        if self.public_key_b64:
            try:
                return base64.b64decode(self.public_key_b64)
            except Exception:
                return None
        try:
            keys = fetch_hub_keys(self.keys_url)
            pk_b64 = keys.get(kid)
            return base64.b64decode(pk_b64) if pk_b64 else None
        except Exception:
            return None

    def verify(self, header_value: str | None) -> ATBVerifyResult:
        key = header_value.strip() if isinstance(header_value, str) else header_value
        if isinstance(key, str) and key and key in self._result_cache:
            cached = self._result_cache[key]
            # Re-check expiry on every cache hit: a credential cached while valid must stop granting
            # the moment its own expires_at passes. Otherwise an expired credential keeps returning
            # valid=True (and grants_discount) until size-based eviction.
            if not (cached.valid and cached.expires_at is not None
                    and cached.expires_at < datetime.now(timezone.utc)):
                return cached
            self._result_cache.pop(key, None)
        result = self._do_verify(header_value)
        if isinstance(key, str) and key:
            if len(self._result_cache) >= self.cache_size:
                self._result_cache.pop(next(iter(self._result_cache)))
            self._result_cache[key] = result
        return result

    def _do_verify(self, header_value: str | None) -> ATBVerifyResult:
        if not header_value or not header_value.strip():
            return self._fail("missing_header")
        try:
            envelope = json.loads(_b64url_decode(header_value.strip()))
            payload = envelope["payload"]
            sig = _b64url_decode(envelope["sig"])
        except Exception:
            return self._fail("envelope_decode")
        if envelope.get("alg") != _ALG:
            return self._fail("alg_mismatch")
        kid = envelope.get("kid")
        pk = self._resolve_key(kid)
        if pk is None:
            return self._fail("no_public_key")
        if kid != hashlib.sha256(pk).hexdigest()[:16]:
            return self._fail("kid_mismatch")
        if not pqc.verify_falcon_1024(pk, canonicalize_bytes(payload), sig):
            return self._fail("sig_invalid")
        if payload.get("bench_issuer") != self.issuer_did:
            return self._fail("untrusted_issuer")
        try:
            exp = datetime.strptime(payload.get("expires_at", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except Exception:
            return self._fail("expires_malformed")
        if exp < datetime.now(timezone.utc):
            return self._fail("expired")
        return ATBVerifyResult(
            valid=True,
            passed=bool(payload.get("passed")),
            score=payload.get("score"),
            expires_at=exp,
            kid=kid,
            commitment_b64=payload.get("commitment_b64"),
            proof_b64=payload.get("proof_b64"),
            threshold_milliunits=payload.get("threshold_milliunits"),
        )

    async def verify_zkp_async(self, header_value: str | None, zkp_service_url: str) -> ATBVerifyResult:
        """Phase 2: structural verify locally; reject a Phase-1 (cleartext) cert as not_phase2."""
        result = self.verify(header_value)
        if result.valid and not result.has_zkp:
            return ATBVerifyResult(False, False, None, result.expires_at, result.kid, "not_phase2_cert")
        return result


__all__ = ["ATBCredentialVerifier", "ATBVerifyResult", "fetch_hub_keys", "clear_key_cache"]
