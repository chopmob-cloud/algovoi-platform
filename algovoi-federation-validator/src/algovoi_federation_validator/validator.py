"""FederationValidator — compose independent PQC credentials into a single token.

Usage::

    from algovoi_federation_validator import FederationValidator

    validator = FederationValidator(
        validator_secret=b"...",    # HMAC key (32+ random bytes)
        issuer_pks={
            "did:algovoi:bench:prod": "<falcon1024-pk-base64>",
            "did:algovoi:bench:eu":   "<falcon1024-pk-base64>",
        },
        min_credentials=2,
    )

    result = validator.compose([cert_a_b64url, cert_b_b64url])
    if result.valid:
        print(result.token.raw)   # present this as X-Fed-Credential

Full signature verification requires extras::

    pip install algovoi-federation-validator[verify]

IETF anchors:
  draft-hopley-x402-pqc-credential-binding-00
  draft-hopley-x402-federation-zkp-00
"""
from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from typing import Sequence

from algovoi_federation_validator._crypto import (
    issue_federation_token,
    verify_pqc_credential,
)
from algovoi_federation_validator.models import (
    CredentialVerifyResult,
    FederationResult,
    FederationToken,
    IssuerEntry,
)

__all__ = ["FederationValidator"]


class FederationValidator:
    """Compose independently-issued PQC credentials into a federation token.

    No shared trust root is required. Each credential is verified against its
    own issuer's public key (supplied via ``issuer_pks``). The composite token
    is signed by the validator itself.

    Args:
        validator_secret: HMAC-SHA256 key for signing federation tokens.
            Should be >= 32 random bytes and held only by the validator.
            Not shared with any credential issuer.
        issuer_pks: Mapping of issuer DID → Falcon-1024 public key (base64
            standard, from ``/.well-known/atb-keys.json``).
        min_credentials: Minimum number of credentials required to compose a
            token. Default 2. Raise to require broader issuer coverage.

    Example::

        validator = FederationValidator(
            validator_secret=os.urandom(32),
            issuer_pks={"did:algovoi:bench:prod": "<pk_b64>"},
            min_credentials=1,   # single-issuer mode for testing
        )
    """

    def __init__(
        self,
        validator_secret: bytes,
        issuer_pks: dict[str, str],
        *,
        min_credentials: int = 2,
    ) -> None:
        if len(validator_secret) < 32:
            raise ValueError("validator_secret must be at least 32 bytes")
        if min_credentials < 1:
            raise ValueError("min_credentials must be >= 1")

        self._secret = validator_secret
        self._issuer_pks = issuer_pks
        self._min_credentials = min_credentials

    def compose(self, credentials: Sequence[str]) -> FederationResult:
        """Compose a list of PQC credential envelopes into a federation token.

        Each credential must:
        - Be a Falcon-1024-signed Phase 2 ATB ZKP cert (atb_cert_version=2).
        - Claim an issuer DID present in ``self.issuer_pks``.
        - Pass Falcon-1024 signature verification (requires [verify] extras).
        - Pass Bulletproofs range-proof verification — the committed score must
          actually meet the threshold (requires [verify]; fails closed otherwise).
        - Not be expired.

        Two DISTINCT credentials from the SAME issuer are accepted — the
        composition is still valid, but the federation token will contain
        duplicate issuer entries and the composite commitment still binds both
        independently. For cross-issuer independence, supply certs from distinct
        issuers. The SAME credential presented more than once is rejected
        (``duplicate_credential``) so a replay cannot satisfy ``min_credentials``.

        Args:
            credentials: Sequence of base64url ATB ZKP credential envelopes.

        Returns:
            :class:`FederationResult` — check ``.valid``. If valid, ``.token``
            contains the signed federation token envelope.
        """
        if len(credentials) < self._min_credentials:
            return FederationResult(
                valid=False,
                failure_reason=(
                    f"insufficient_credentials:{len(credentials)} "
                    f"(min {self._min_credentials})"
                ),
            )

        # SECURITY (2026-08-19): reject a replayed credential up front. The same attestation presented
        # more than once must NOT satisfy ``min_credentials`` — it is one attestation, not N independent
        # ones. An attestation is identified by (issuer_did, kid, commitment) read from the signed payload;
        # the Pedersen commitment is randomised per issuance, so two genuinely-independent certs differ
        # while an exact replay collides. Padding a composition with replays is refused here.
        seen: set[tuple[str, str, str]] = set()
        for ident in (self._extract_identity(c) for c in credentials):
            if ident is not None:
                if ident in seen:
                    return FederationResult(valid=False, failure_reason="duplicate_credential")
                seen.add(ident)

        verified: list[CredentialVerifyResult] = []
        for i, cred in enumerate(credentials):
            issuer_did = self._extract_issuer_did(cred)
            if issuer_did is None:
                result = CredentialVerifyResult(
                    valid=False,
                    failure_reason=f"credential[{i}]:envelope_decode_or_no_issuer",
                )
                verified.append(result)
                continue

            pk_b64 = self._issuer_pks.get(issuer_did)
            if pk_b64 is None:
                result = CredentialVerifyResult(
                    valid=False,
                    issuer_did=issuer_did,
                    failure_reason=f"credential[{i}]:unknown_issuer:{issuer_did}",
                )
                verified.append(result)
                continue

            result = verify_pqc_credential(cred, pk_b64)
            if not result.valid:
                result = CredentialVerifyResult(
                    valid=False,
                    issuer_did=result.issuer_did,
                    kid=result.kid,
                    expires_at=result.expires_at,
                    failure_reason=f"credential[{i}]:{result.failure_reason}",
                )
            verified.append(result)

        failed = [r for r in verified if not r.valid]
        if failed:
            reasons = "; ".join(r.failure_reason or "unknown" for r in failed)
            return FederationResult(
                valid=False,
                failure_reason=reasons,
                credential_results=verified,
            )

        # All credentials verified — assemble composite token.
        commitment_bytes_list = [
            base64.b64decode(r.commitment_b64)  # type: ignore[arg-type]
            for r in verified
        ]
        issuers = [
            IssuerEntry(
                did=r.issuer_did or "",
                kid=r.kid or "",
                alg=r.alg or "Falcon-1024",
            )
            for r in verified
        ]

        # expires_at = min across all certs (most restrictive)
        expires_at: datetime = min(
            r.expires_at for r in verified  # type: ignore[type-var]
            if r.expires_at is not None
        )
        if expires_at < datetime.now(timezone.utc):
            return FederationResult(
                valid=False,
                failure_reason="all_credentials_expired",
                credential_results=verified,
            )

        nonce = os.urandom(32)
        token = issue_federation_token(
            issuers=issuers,
            commitment_bytes_list=commitment_bytes_list,
            nonce=nonce,
            expires_at=expires_at,
            validator_secret=self._secret,
        )

        return FederationResult(
            valid=True,
            token=token,
            credential_results=verified,
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_issuer_did(envelope_b64url: str) -> str | None:
        """Extract bench_issuer DID from a credential envelope without full verification."""
        import json

        pad = 4 - (len(envelope_b64url) % 4)
        if pad and pad < 4:
            envelope_b64url = envelope_b64url + "=" * pad
        try:
            envelope = json.loads(base64.urlsafe_b64decode(envelope_b64url))
            return envelope.get("payload", {}).get("bench_issuer") or None
        except Exception:
            return None

    @staticmethod
    def _extract_identity(envelope_b64url: str) -> tuple[str, str, str] | None:
        """Extract the (issuer_did, kid, commitment) attestation identity without full verification.

        Used only for replay de-duplication — the values come from the signed payload, so they are stable
        across envelope re-encodings, and full signature/proof verification still runs afterwards.
        """
        import json

        s = envelope_b64url
        pad = 4 - (len(s) % 4)
        if pad and pad < 4:
            s = s + "=" * pad
        try:
            envelope = json.loads(base64.urlsafe_b64decode(s))
            payload = envelope.get("payload", {})
            did = payload.get("bench_issuer")
            kid = envelope.get("kid")
            commitment = payload.get("commitment_b64")
            if did and kid and commitment:
                return (str(did), str(kid), str(commitment))
            return None
        except Exception:
            return None
