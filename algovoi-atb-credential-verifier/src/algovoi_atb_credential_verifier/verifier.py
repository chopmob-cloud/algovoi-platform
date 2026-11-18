"""
Core ATB credential verifier.

Supports:
  - Phase 1 (X-ATB-Credential): Falcon-1024 signed, cleartext score
  - Phase 2 (X-ATB-ZK-Credential): Falcon-1024 envelope + Bulletproofs
    range proof (score >= threshold, score not revealed)

Phase 2 verification is fully OFFLINE when the native algovoi_bpverify extension
is installed (the [verify] extra): both the Falcon-1024 signature and the
Bulletproofs range proof are checked locally — no ZKP microservice, no network.
Use verify_zkp() (sync) for an air-gapped path, or verify_zkp_async() which
prefers offline verification and only falls back to the ZKP service when
bpverify is absent.

Design:
  - Never raises — every failure returns ATBVerifyResult(valid=False, ...)
  - LRU cache keyed on (sig_hash, kid), configurable TTL
  - Pinned key OR auto-fetch from /.well-known/atb-keys.json
  - Multi-hub via allowlist of (issuer_did, pk_b64) pairs
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import rfc8785

logger = logging.getLogger(__name__)

# Offline Bulletproofs range-proof verifier (native extension; reuses the exact
# dalek crates/generators/transcript as the ATB ZKP prover). When present, Phase-2
# ZKP credentials are verified fully offline — no ZKP microservice, no network.
try:
    import algovoi_bpverify as _bpverify
    _HAS_BPVERIFY = True
except ImportError:
    _bpverify = None
    _HAS_BPVERIFY = False

_DEFAULT_ISSUER = "did:web:agent-trust-bench.algovoi.co.uk"
_DEFAULT_KEYS_URL = (
    "https://agent-trust-bench.algovoi.co.uk"
    "/agent-trust-bench/.well-known/atb-keys.json"
)


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class ATBVerifyResult:
    """Result of verifying an ATB Pass Certificate header."""
    valid: bool
    passed: bool
    score: float | None                   # None for Phase 2 (ZKP)
    expires_at: datetime | None
    kid: str | None
    failure_reason: str | None
    # Phase 2 fields — populated only for ZKP certs
    commitment_b64: str | None = None
    proof_b64: str | None = None
    threshold_milliunits: int | None = None

    @property
    def grants_discount(self) -> bool:
        """True when the cert should trigger a gateway discount."""
        return self.valid and self.passed

    @property
    def has_zkp(self) -> bool:
        """True when this result carries ZKP binding data (Phase 2)."""
        return bool(self.commitment_b64 and self.proof_b64)


def _neg(reason: str) -> ATBVerifyResult:
    return ATBVerifyResult(
        valid=False, passed=False, score=None,
        expires_at=None, kid=None, failure_reason=reason,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad and pad < 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _parse_expires(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _verify_range_offline(commitment_b64: str, proof_b64: str, threshold_milliunits: int) -> tuple[bool, str | None]:
    """Offline Bulletproofs range-proof verification via algovoi_bpverify.

    Returns (ok, failure_reason). ok=False with reason if the proof is invalid,
    malformed, or the native verifier is unavailable (fail closed).
    """
    if not _HAS_BPVERIFY:
        return False, "bpverify_unavailable"
    try:
        cb = base64.b64decode(commitment_b64)
        pb = base64.b64decode(proof_b64)
    except Exception:
        return False, "zkp_b64_decode"
    try:
        if not _bpverify.verify_range_proof(cb, pb, int(threshold_milliunits)):
            return False, "proof_invalid"
    except Exception:
        return False, "proof_invalid"
    return True, None


# ── ATBCredentialVerifier ─────────────────────────────────────────────────────

class ATBCredentialVerifier:
    """Verify X-ATB-Credential and X-ATB-ZK-Credential headers.

    Parameters
    ----------
    issuer_did:
        Expected `bench_issuer` DID. Defaults to AlgoVoi's reference bench.
    public_key_b64:
        Base64-encoded Falcon-1024 public key (1793 bytes, PQClean format).
        If omitted, the key is auto-fetched from `keys_url` on first use.
    keys_url:
        URL of the hub's /.well-known/atb-keys.json. Ignored if
        `public_key_b64` is provided.
    trusted_hubs:
        Optional list of (issuer_did, public_key_b64) pairs for multi-hub
        deployments. When set, the verifier resolves the cert's issuer DID
        against this list before verifying the signature.
    cache_ttl_secs:
        How long to cache verified results in seconds. Default: 300.
    cache_max_size:
        Maximum cache entries before eviction. Default: 512.
    """

    def __init__(
        self,
        issuer_did: str = _DEFAULT_ISSUER,
        public_key_b64: str | None = None,
        keys_url: str = _DEFAULT_KEYS_URL,
        trusted_hubs: list[tuple[str, str]] | None = None,
        cache_ttl_secs: int = 300,
        cache_max_size: int = 512,
    ) -> None:
        self._issuer_did = issuer_did
        self._pk_b64 = public_key_b64
        self._keys_url = keys_url
        self._cache_ttl = cache_ttl_secs
        self._cache_max = cache_max_size
        self._cache: dict[tuple[str, str], tuple[ATBVerifyResult, float]] = {}
        # Multi-hub map: issuer_did → pk_bytes
        self._hub_pks: dict[str, bytes] = {}
        if trusted_hubs:
            for did, pk_b64 in trusted_hubs:
                try:
                    self._hub_pks[did] = base64.b64decode(pk_b64)
                except Exception:
                    logger.warning("atb_verifier.bad_hub_pk", extra={"did": did})
        if public_key_b64:
            try:
                self._hub_pks[issuer_did] = base64.b64decode(public_key_b64)
            except Exception:
                logger.warning("atb_verifier.bad_primary_pk")

    # ── Key resolution ────────────────────────────────────────────────────────

    def _pk_bytes(self, issuer_did: str | None = None) -> bytes | None:
        did = issuer_did or self._issuer_did
        pk = self._hub_pks.get(did)
        if pk is not None:
            return pk
        if self._pk_b64 and did == self._issuer_did:
            try:
                pk = base64.b64decode(self._pk_b64)
                self._hub_pks[did] = pk
                return pk
            except Exception:
                return None
        return None

    async def _pk_bytes_async(self, issuer_did: str | None = None) -> bytes | None:
        did = issuer_did or self._issuer_did
        pk = self._hub_pks.get(did)
        if pk is not None:
            return pk
        # Auto-fetch from /.well-known/atb-keys.json
        from algovoi_atb_credential_verifier.hub_resolver import fetch_hub_keys
        url = self._keys_url if did == self._issuer_did else None
        if url is None:
            return None
        keys_doc = await fetch_hub_keys(url)
        if not keys_doc:
            return None
        keys = keys_doc.get("keys", [])
        if not keys:
            return None
        pk_b64 = keys[0].get("public_key_b64", "")
        if not pk_b64:
            return None
        try:
            pk = base64.b64decode(pk_b64)
            self._hub_pks[did] = pk
            return pk
        except Exception:
            return None

    # ── Cache ─────────────────────────────────────────────────────────────────

    def _cache_get(self, sig_hash: str, kid: str) -> ATBVerifyResult | None:
        entry = self._cache.get((sig_hash, kid))
        if not entry:
            return None
        result, exp = entry
        if time.time() >= exp:
            self._cache.pop((sig_hash, kid), None)
            return None
        return result

    def _cache_put(self, sig_hash: str, kid: str, result: ATBVerifyResult) -> None:
        if len(self._cache) >= self._cache_max:
            now = time.time()
            expired = [k for k, (_, e) in self._cache.items() if e <= now]
            for k in expired:
                self._cache.pop(k, None)
            if len(self._cache) >= self._cache_max:
                soonest = min(self._cache, key=lambda k: self._cache[k][1])
                self._cache.pop(soonest, None)
        ttl = self._cache_ttl
        if result.expires_at:
            secs = (result.expires_at - datetime.now(timezone.utc)).total_seconds()
            ttl = min(ttl, max(0, int(secs)))
        if ttl <= 0:
            return
        self._cache[(sig_hash, kid)] = (result, time.time() + ttl)

    # ── Signature verification ────────────────────────────────────────────────

    def _falcon_verify(self, pk_bytes: bytes, canonical: bytes, sig_bytes: bytes) -> bool:
        """Verify a Falcon-1024 signature over JCS-canonical bytes.

        Uses pqcrypto (PQClean) directly — the same implementation the bench uses.
        Requires `pip install algovoi-atb-credential-verifier[verify]` which
        pulls in `algovoi-substrate-pqc` (pqcrypto + rfc8785).
        """
        try:
            from pqcrypto.sign.falcon_1024 import verify  # type: ignore[import]
            return bool(verify(pk_bytes, canonical, sig_bytes))
        except ImportError:
            logger.warning(
                "atb_verifier.falcon_unavailable — "
                "install with [verify] extras: "
                "pip install algovoi-atb-credential-verifier[verify]"
            )
            return False
        except Exception:
            return False

    # ── Envelope parsing ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_envelope(header_value: str) -> tuple[dict, str, str, str] | None:
        """Returns (payload, sig_b64, alg, kid) or None on parse failure."""
        try:
            envelope = json.loads(_b64url_decode(header_value.strip().strip('"').strip("'")))
        except Exception:
            return None
        payload = envelope.get("payload")
        sig_b64 = envelope.get("sig")
        alg = envelope.get("alg")
        kid = envelope.get("kid")
        if (
            not isinstance(payload, dict)
            or not isinstance(sig_b64, str)
            or alg != "Falcon-1024"
            or not isinstance(kid, str)
        ):
            return None
        return payload, sig_b64, alg, kid

    # ── Phase 1 verify (sync) ─────────────────────────────────────────────────

    def verify(self, header_value: str | None) -> ATBVerifyResult:
        """Verify an X-ATB-Credential header (Phase 1, Falcon-1024, sync).

        Returns ATBVerifyResult. Never raises.
        """
        if not header_value or not header_value.strip():
            return _neg("missing_header")

        parsed = self._parse_envelope(header_value)
        if parsed is None:
            return _neg("envelope_decode")
        payload, sig_b64, _alg, kid = parsed

        sig_hash = hashlib.sha256(sig_b64.encode()).hexdigest()[:32]
        cached = self._cache_get(sig_hash, kid)
        if cached is not None:
            return cached

        issuer_did = payload.get("bench_issuer", self._issuer_did)
        pk_bytes = self._pk_bytes(issuer_did)
        if pk_bytes is None:
            return _neg("no_public_key")

        # Kid check
        expected_kid = hashlib.sha256(pk_bytes).hexdigest()[:16]
        if kid != expected_kid:
            result = _neg("kid_mismatch")
            self._cache_put(sig_hash, kid, result)
            return result

        # Issuer check
        if issuer_did not in (self._issuer_did, *self._hub_pks.keys()):
            result = _neg("untrusted_issuer")
            self._cache_put(sig_hash, kid, result)
            return result

        # Falcon-1024 signature
        try:
            sig_bytes = _b64url_decode(sig_b64)
        except Exception:
            result = _neg("sig_decode")
            self._cache_put(sig_hash, kid, result)
            return result

        canonical = rfc8785.dumps(payload)
        if not self._falcon_verify(pk_bytes, canonical, sig_bytes):
            result = _neg("sig_invalid")
            self._cache_put(sig_hash, kid, result)
            return result

        # Expiry
        expires_at = _parse_expires(payload.get("expires_at", ""))
        if expires_at is None:
            result = _neg("expires_at_malformed")
            self._cache_put(sig_hash, kid, result)
            return result
        if expires_at < datetime.now(timezone.utc):
            result = ATBVerifyResult(
                valid=False, passed=False, score=None,
                expires_at=expires_at, kid=kid, failure_reason="expired",
            )
            self._cache_put(sig_hash, kid, result)
            return result

        score = payload.get("score")
        passed = bool(payload.get("passed", False))
        result = ATBVerifyResult(
            valid=True, passed=passed,
            score=float(score) if isinstance(score, (int, float)) else None,
            expires_at=expires_at, kid=kid, failure_reason=None,
        )
        self._cache_put(sig_hash, kid, result)
        return result

    # ── Phase 2 verify (async, requires ZKP service) ─────────────────────────

    async def verify_zkp_async(
        self,
        header_value: str | None,
        zkp_service_url: str = "http://localhost:8091",
    ) -> ATBVerifyResult:
        """Verify an X-ATB-ZK-Credential header (Phase 2, Bulletproofs ZKP).

        Requires a running algovoi-zkp-service (Rust) at `zkp_service_url`.
        If the service is unreachable, returns valid=False with
        failure_reason="zkp_service_unavailable".

        Returns ATBVerifyResult with score=None (score is never revealed).
        """
        if not header_value or not header_value.strip():
            return _neg("missing_header")

        parsed = self._parse_envelope(header_value)
        if parsed is None:
            return _neg("envelope_decode")
        payload, sig_b64, _alg, kid = parsed

        if payload.get("atb_cert_version") != "2":
            return _neg("not_phase2_cert")

        sig_hash = hashlib.sha256(sig_b64.encode()).hexdigest()[:32]
        cached = self._cache_get(sig_hash, kid)
        if cached is not None:
            return cached

        issuer_did = payload.get("bench_issuer", self._issuer_did)
        pk_bytes = await self._pk_bytes_async(issuer_did)
        if pk_bytes is None:
            return _neg("no_public_key")

        expected_kid = hashlib.sha256(pk_bytes).hexdigest()[:16]
        if kid != expected_kid:
            result = _neg("kid_mismatch")
            self._cache_put(sig_hash, kid, result)
            return result

        try:
            sig_bytes = _b64url_decode(sig_b64)
        except Exception:
            result = _neg("sig_decode")
            self._cache_put(sig_hash, kid, result)
            return result

        canonical = rfc8785.dumps(payload)
        if not self._falcon_verify(pk_bytes, canonical, sig_bytes):
            result = _neg("sig_invalid")
            self._cache_put(sig_hash, kid, result)
            return result

        expires_at = _parse_expires(payload.get("expires_at", ""))
        if expires_at is None:
            result = _neg("expires_at_malformed")
            self._cache_put(sig_hash, kid, result)
            return result
        if expires_at < datetime.now(timezone.utc):
            result = ATBVerifyResult(
                valid=False, passed=False, score=None,
                expires_at=expires_at, kid=kid, failure_reason="expired",
            )
            self._cache_put(sig_hash, kid, result)
            return result

        commitment_b64 = payload.get("commitment_b64", "")
        proof_b64 = payload.get("proof_b64", "")
        threshold_milliunits = int(payload.get("threshold_milliunits", 700))

        if not commitment_b64 or not proof_b64:
            result = _neg("missing_zkp_fields")
            self._cache_put(sig_hash, kid, result)
            return result

        # Verify the Bulletproofs range proof. Prefer fully-offline verification via
        # the native algovoi_bpverify extension (no network); fall back to the ZKP
        # microservice only when bpverify is not installed.
        if _HAS_BPVERIFY:
            ok, zkp_reason = _verify_range_offline(commitment_b64, proof_b64, threshold_milliunits)
            if not ok:
                result = _neg(f"zkp_invalid:{zkp_reason}")
                self._cache_put(sig_hash, kid, result)
                return result
        else:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(
                        f"{zkp_service_url.rstrip('/')}/verify",
                        json={
                            "commitment_b64": commitment_b64,
                            "proof_b64": proof_b64,
                            "threshold_milliunits": threshold_milliunits,
                        },
                    )
                zkp_data = resp.json()
                if not bool(zkp_data.get("valid", False)):
                    result = _neg(f"zkp_invalid:{zkp_data.get('failure_reason') or 'unknown'}")
                    self._cache_put(sig_hash, kid, result)
                    return result
            except Exception as exc:
                logger.warning("atb_verifier.zkp_service_error", extra={"err": str(exc)})
                return _neg("zkp_service_unavailable")

        result = ATBVerifyResult(
            valid=True,
            passed=True,       # proven by range proof
            score=None,        # never revealed
            expires_at=expires_at,
            kid=kid,
            failure_reason=None,
            commitment_b64=commitment_b64,
            proof_b64=proof_b64,
            threshold_milliunits=threshold_milliunits,
        )
        self._cache_put(sig_hash, kid, result)
        return result

    # ── Phase 2 verify (sync, fully offline — no ZKP service) ─────────────────

    def verify_zkp(self, header_value: str | None) -> ATBVerifyResult:
        """Verify an X-ATB-ZK-Credential header (Phase 2) fully OFFLINE.

        Falcon-1024 signature AND the Bulletproofs range proof are both verified
        locally via the native ``algovoi_bpverify`` extension — no ZKP microservice
        and no network (given a pinned or cached issuer key). Air-gap friendly.
        Requires the [verify] extra (algovoi-bpverify). Never raises; returns
        ``ATBVerifyResult(valid=False, failure_reason="bpverify_unavailable")`` if
        the native verifier is not installed.
        """
        if not _HAS_BPVERIFY:
            return _neg("bpverify_unavailable")
        if not header_value or not header_value.strip():
            return _neg("missing_header")

        parsed = self._parse_envelope(header_value)
        if parsed is None:
            return _neg("envelope_decode")
        payload, sig_b64, _alg, kid = parsed

        if payload.get("atb_cert_version") != "2":
            return _neg("not_phase2_cert")

        sig_hash = hashlib.sha256(sig_b64.encode()).hexdigest()[:32]
        cached = self._cache_get(sig_hash, kid)
        if cached is not None:
            return cached

        issuer_did = payload.get("bench_issuer", self._issuer_did)
        pk_bytes = self._pk_bytes(issuer_did)
        if pk_bytes is None:
            return _neg("no_public_key")

        expected_kid = hashlib.sha256(pk_bytes).hexdigest()[:16]
        if kid != expected_kid:
            result = _neg("kid_mismatch")
            self._cache_put(sig_hash, kid, result)
            return result

        try:
            sig_bytes = _b64url_decode(sig_b64)
        except Exception:
            result = _neg("sig_decode")
            self._cache_put(sig_hash, kid, result)
            return result

        if not self._falcon_verify(pk_bytes, rfc8785.dumps(payload), sig_bytes):
            result = _neg("sig_invalid")
            self._cache_put(sig_hash, kid, result)
            return result

        expires_at = _parse_expires(payload.get("expires_at", ""))
        if expires_at is None:
            result = _neg("expires_at_malformed")
            self._cache_put(sig_hash, kid, result)
            return result
        if expires_at < datetime.now(timezone.utc):
            result = ATBVerifyResult(
                valid=False, passed=False, score=None,
                expires_at=expires_at, kid=kid, failure_reason="expired",
            )
            self._cache_put(sig_hash, kid, result)
            return result

        commitment_b64 = payload.get("commitment_b64", "")
        proof_b64 = payload.get("proof_b64", "")
        threshold_milliunits = int(payload.get("threshold_milliunits", 700))
        if not commitment_b64 or not proof_b64:
            result = _neg("missing_zkp_fields")
            self._cache_put(sig_hash, kid, result)
            return result

        ok, zkp_reason = _verify_range_offline(commitment_b64, proof_b64, threshold_milliunits)
        if not ok:
            result = _neg(f"zkp_invalid:{zkp_reason}")
            self._cache_put(sig_hash, kid, result)
            return result

        result = ATBVerifyResult(
            valid=True, passed=True, score=None,
            expires_at=expires_at, kid=kid, failure_reason=None,
            commitment_b64=commitment_b64,
            proof_b64=proof_b64,
            threshold_milliunits=threshold_milliunits,
        )
        self._cache_put(sig_hash, kid, result)
        return result
