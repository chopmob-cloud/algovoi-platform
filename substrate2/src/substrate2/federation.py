"""
substrate2.federation — cross-issuer ZKP federation (no shared trust root).

From draft-hopley-x402-federation-zkp-00. Each PQC credential is verified independently
against its issuer's Falcon-1024 key; the verified commitments are composed into a single
commitment (SHA-256 over the ordered commitments + nonce) and bound into an HMAC-signed
federation token. Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from .canon import canonicalize_bytes
from . import pqc

# Offline Bulletproofs range-proof verification (native extension; reuses the exact
# dalek crates/generators/transcript as the ATB ZKP prover). Each federated credential
# must prove score >= threshold, not merely carry a well-shaped blob. Fails closed.
try:
    import algovoi_bpverify as _bpverify
    _HAS_BPVERIFY = True
except ImportError:  # pragma: no cover
    _bpverify = None
    _HAS_BPVERIFY = False

_FED_TOKEN_LABEL = b"AlgoVoi-FederationToken-v1"
_ALG = "Falcon-1024"
_COMMITMENT_BYTES = 32
_PROOF_MIN_BYTES = 200
_PROOF_MAX_BYTES = 900
_FALCON1024_PK_LEN = 1793


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


@dataclass
class IssuerEntry:
    did: str
    kid: str
    alg: str = _ALG

    def as_dict(self) -> dict:
        return {"did": self.did, "kid": self.kid, "alg": self.alg}


@dataclass
class CredentialVerifyResult:
    valid: bool
    issuer_did: str | None = None
    kid: str | None = None
    alg: str | None = None
    commitment_b64: str | None = None
    failure_reason: str | None = None

    def __bool__(self) -> bool:
        return self.valid


@dataclass
class FederationToken:
    raw: str
    fed_commitment_hex: str
    fed_nonce_hex: str
    issuers: list
    expires_at: str


@dataclass
class FederationResult:
    valid: bool
    token: FederationToken | None = None
    failure_reason: str | None = None
    credential_results: list = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.valid


def compose_commitments(commitment_bytes_list: Sequence[bytes], nonce: bytes) -> bytes:
    """Composite commitment = SHA-256(c0 || c1 || ... || nonce). Order-sensitive."""
    h = hashlib.sha256()
    for c in commitment_bytes_list:
        h.update(c)
    h.update(nonce)
    return h.digest()


def verify_pqc_credential(envelope_b64url: str, pk_b64: str, *, verify_range: bool = True) -> CredentialVerifyResult:
    """Independently verify one PQC (Falcon-1024) credential envelope against an issuer key.

    When ``verify_range`` is True (default) the Bulletproofs range proof is also
    cryptographically verified offline via ``algovoi_bpverify`` (score >= threshold),
    failing closed if the proof is invalid or the verifier is unavailable."""
    try:
        pk = base64.b64decode(pk_b64) if isinstance(pk_b64, str) else pk_b64
    except Exception:
        return CredentialVerifyResult(False, failure_reason="pk_decode")
    if len(pk) != _FALCON1024_PK_LEN:
        return CredentialVerifyResult(False, failure_reason="pk_length")
    try:
        envelope = json.loads(_b64url_decode(envelope_b64url))
        payload = envelope["payload"]
        sig = _b64url_decode(envelope["sig"])
    except Exception as exc:
        return CredentialVerifyResult(False, failure_reason=f"decode:{exc}")
    if envelope.get("alg") != _ALG:
        return CredentialVerifyResult(False, failure_reason="alg")
    if envelope.get("kid") != hashlib.sha256(pk).hexdigest()[:16]:
        return CredentialVerifyResult(False, failure_reason="kid")
    if not pqc.verify_falcon_1024(pk, canonicalize_bytes(payload), sig):
        return CredentialVerifyResult(False, failure_reason="sig")
    commitment_b64 = payload.get("commitment_b64")
    try:
        commitment_bytes = base64.b64decode(commitment_b64)
    except Exception:
        return CredentialVerifyResult(False, failure_reason="commitment_decode")
    if len(commitment_bytes) != _COMMITMENT_BYTES:
        return CredentialVerifyResult(False, failure_reason="commitment_size")
    # Cryptographically verify the range proof (score >= threshold) — fail closed.
    if verify_range:
        try:
            proof_bytes = base64.b64decode(payload.get("proof_b64", ""))
        except Exception:
            return CredentialVerifyResult(False, failure_reason="proof_decode")
        if not (_PROOF_MIN_BYTES <= len(proof_bytes) <= _PROOF_MAX_BYTES):
            return CredentialVerifyResult(False, failure_reason="proof_size")
        try:
            threshold_mu = int(payload.get("threshold_milliunits"))
        except (TypeError, ValueError):
            return CredentialVerifyResult(False, failure_reason="threshold_malformed")
        if not (0 <= threshold_mu <= 1000):
            return CredentialVerifyResult(False, failure_reason="threshold_range")
        if not _HAS_BPVERIFY:
            return CredentialVerifyResult(False, failure_reason="bpverify_unavailable")
        if not _bpverify.verify_range_proof(commitment_bytes, proof_bytes, threshold_mu):
            return CredentialVerifyResult(False, failure_reason="proof_invalid")
    return CredentialVerifyResult(
        True,
        issuer_did=payload.get("bench_issuer"),
        kid=envelope.get("kid"),
        alg=_ALG,
        commitment_b64=commitment_b64,
    )


def _token_payload(issuers, fed_hex, nonce_hex, expires_at, kid) -> dict:
    return {
        "expires_at": expires_at,
        "fed_commitment_hex": fed_hex,
        "fed_nonce_hex": nonce_hex,
        "issuers": [i.as_dict() if isinstance(i, IssuerEntry) else i for i in issuers],
        "kid": kid,
    }


def issue_federation_token(issuers, commitment_bytes_list, nonce, expires_at, validator_secret) -> FederationToken:
    fed = compose_commitments(commitment_bytes_list, nonce)
    kid = hashlib.sha256(validator_secret).hexdigest()[:16]
    payload = _token_payload(issuers, fed.hex(), nonce.hex(), expires_at, kid)
    canonical = canonicalize_bytes(payload)
    sig = hmac.new(validator_secret, _FED_TOKEN_LABEL + canonical, hashlib.sha256).digest()
    envelope = {"payload": payload, "sig": _b64url_encode(sig)}
    raw = _b64url_encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))
    return FederationToken(raw, fed.hex(), nonce.hex(), payload["issuers"], expires_at)


def verify_federation_token(token_b64url: str, validator_secret: bytes) -> FederationResult:
    try:
        envelope = json.loads(_b64url_decode(token_b64url))
        payload = envelope["payload"]
        received = _b64url_decode(envelope["sig"])
    except Exception as exc:
        return FederationResult(False, failure_reason=f"decode:{exc}")
    expected = hmac.new(validator_secret, _FED_TOKEN_LABEL + canonicalize_bytes(payload), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, received):
        return FederationResult(False, failure_reason="hmac")
    try:
        exp = datetime.strptime(payload.get("expires_at", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return FederationResult(False, failure_reason="expires_malformed")
    if exp < datetime.now(timezone.utc):
        return FederationResult(False, failure_reason="expired")
    token = FederationToken(token_b64url, payload["fed_commitment_hex"], payload["fed_nonce_hex"], payload["issuers"], payload["expires_at"])
    return FederationResult(True, token=token)


class FederationValidator:
    """Compose 2+ independently-verified cross-issuer credentials into a federation token."""

    def __init__(self, validator_secret: bytes, issuer_pks: dict, min_credentials: int = 2):
        self.validator_secret = validator_secret
        self.issuer_pks = issuer_pks  # kid -> pk_b64
        self.min_credentials = min_credentials

    def compose(self, credentials: Sequence[str], *, nonce: bytes, expires_at: str) -> FederationResult:
        results = []
        commitments = []
        issuers = []
        seen_kids: set = set()
        for cred in credentials:
            try:
                env = json.loads(_b64url_decode(cred))
                kid = env.get("kid")
            except Exception:
                results.append(CredentialVerifyResult(False, failure_reason="decode"))
                continue
            pk_b64 = self.issuer_pks.get(kid)
            if pk_b64 is None:
                results.append(CredentialVerifyResult(False, kid=kid, failure_reason="unknown_issuer"))
                continue
            r = verify_pqc_credential(cred, pk_b64)
            results.append(r)
            if r.valid:
                # Federation is a CROSS-issuer quorum: the same issuer's credential (or a byte-identical
                # credential resubmitted) must not count twice toward the threshold, else one issuer can
                # masquerade as a quorum. Count each distinct kid at most once.
                if kid in seen_kids:
                    continue
                seen_kids.add(kid)
                commitments.append(base64.b64decode(r.commitment_b64))
                issuers.append(IssuerEntry(r.issuer_did or "", kid))
        if len(issuers) < self.min_credentials:
            return FederationResult(False, failure_reason="insufficient_valid_credentials", credential_results=results)
        token = issue_federation_token(issuers, commitments, nonce, expires_at, self.validator_secret)
        return FederationResult(True, token=token, credential_results=results)


__all__ = [
    "IssuerEntry", "CredentialVerifyResult", "FederationToken", "FederationResult",
    "FederationValidator", "compose_commitments", "verify_pqc_credential",
    "issue_federation_token", "verify_federation_token",
]
