"""
substrate2.vc — express substrate credentials as W3C Verifiable Credentials 2.0.

Implemented from the W3C **Verifiable Credentials Data Model 2.0**, a W3C Recommendation
(ratified 2025-05-15), and the OAuth WG Internet-Draft **SD-JWT VC**
(draft-ietf-oauth-sd-jwt-vc, tracking draft 17). Not derived from v1 source. See PROVENANCE.md.

## Why this module exists

substrate2's cryptographic primitives are ratified standards, but its credential SEMANTICS
were self-authored: the ATB reputation credential is a bespoke Falcon envelope shaped by
`draft-hopley-x402-atb-reputation-credential-00`. To a regulated buyer whose job is checking
conformance to *other people's* standards, a bespoke credential format is a liability no
matter how sound it is. This module re-expresses the same attested facts in the ratified W3C
model, so the credential a customer hands to their auditor is a `VerifiableCredential`, not an
AlgoVoi shape.

## Additive, and why no digest moves

This is a PRESENTATION mapping. `build_atb_envelope_b64` and the Falcon signature it produces
are untouched; the VC is a second view of the same facts, derived from the already-signed
payload. Nothing that was ever anchored changes, so no content hash moves. The chain of trust
still runs through the Falcon envelope; the VC carries a reference back to it.

## The timestamp exception, stated on purpose

Everywhere else in substrate2, times are integer milliseconds (Substrate Rule 2) because they
are folded into content-addressed preimages. A VC is NOT content-addressed — VC 2.0 mandates
`validFrom`/`validUntil` as XSD dateTime STRINGS (RFC 3339). So this module deliberately emits
string timestamps. That is correct here and wrong anywhere a ref is computed; the two rules do
not conflict because they govern different artifacts. The ATB payload already carries RFC 3339
`issued_at`/`expires_at`, so the values pass straight through.

## Ratified vs draft — do not blur these

- **VC 2.0 Data Model**: ratified W3C Recommendation. `to_vc()` output IS a conformant VC 2.0
  credential and may be described as such.
- **SD-JWT VC**: an IETF Internet-Draft, NOT an RFC. `to_sd_jwt_vc()` tracks draft 17 and is
  labelled a draft everywhere. Never describe its output as standards-conformant; the whole
  point of this work is replacing self-authored drafts with ratified standards, and adopting
  someone else's unratified draft as if settled would repeat the mistake in other colours.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

from .digest import sha256_jcs

# The one non-negotiable VC 2.0 value: the first @context entry MUST be exactly this.
VC2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
# Our credential-type context, a stable URL under the docs domain (not dereferenced here).
ALGOVOI_CONTEXT = "https://docs.algovoi.co.uk/ns/credentials/v1"

ATB_CREDENTIAL_TYPE = "AgentTrustBenchCredential"
# SD-JWT VC type identifier (vct). A collision-resistant name per RFC 7515 section 2.
ATB_VCT = "https://docs.algovoi.co.uk/vct/agent-trust-bench/v1"

SD_JWT_VC_DRAFT = "draft-ietf-oauth-sd-jwt-vc-17"  # tracked draft; NOT an RFC


class VcError(ValueError):
    """Raised when a payload cannot be expressed as, or verified as, a VC 2.0 credential."""


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _require_rfc3339(field: str, value: Any) -> str:
    """VC 2.0 validity dates are XSD dateTime strings. Accept what the ATB payload carries;
    reject an integer, which would silently produce an invalid VC."""
    if not isinstance(value, str) or "T" not in value:
        raise VcError(f"{field} must be an RFC 3339 date-time string, got {value!r}")
    return value


def to_vc(atb_payload: dict, *, credential_id: str | None = None) -> dict:
    """Express an ATB reputation-credential payload as a W3C VC 2.0 credential.

    The output is a conformant VerifiableCredential (unsecured / data-model form). Secure it
    with :func:`secure_vc_jose` for an enveloped EdDSA proof, exactly as the ATB envelope is
    signed with Falcon -- the two are parallel, not competing.

    The subject is bound to the exact ATB facts, and `algovoiEnvelopeRef` carries the
    content hash of the original signed payload so a verifier can tie the VC back to the
    Falcon-signed source of truth.
    """
    if not isinstance(atb_payload, dict):
        raise VcError("atb_payload must be a dict")
    for required in ("bench_issuer", "issued_at", "expires_at", "agent_id_hash", "score", "passed"):
        if required not in atb_payload:
            raise VcError(f"ATB payload missing required field {required!r}")

    valid_from = _require_rfc3339("issued_at", atb_payload["issued_at"])
    valid_until = _require_rfc3339("expires_at", atb_payload["expires_at"])

    # A stable, content-addressed reference back to the signed ATB payload. This is the
    # cryptographic link: the VC asserts nothing the Falcon envelope did not already sign.
    envelope_ref = "sha256:" + sha256_jcs(atb_payload)

    subject = {
        "id": f"urn:algovoi:agent:{atb_payload['agent_id_hash']}",
        "type": ATB_CREDENTIAL_TYPE,
        "trustScore": atb_payload["score"],
        "passed": atb_payload["passed"],
        "algovoiEnvelopeRef": envelope_ref,
    }
    for optional in ("threshold", "score_components", "profile_set_hash", "atb_cert_version",
                     "ietf_anchor", "bench_kid"):
        if optional in atb_payload:
            subject[optional] = atb_payload[optional]

    vc = {
        "@context": [VC2_CONTEXT, ALGOVOI_CONTEXT],
        "type": ["VerifiableCredential", ATB_CREDENTIAL_TYPE],
        "issuer": atb_payload["bench_issuer"],
        "validFrom": valid_from,
        "validUntil": valid_until,
        "credentialSubject": subject,
    }
    if credential_id is not None:
        if not isinstance(credential_id, str) or ":" not in credential_id:
            raise VcError("credential_id must be a URI (VC 2.0: id MUST be a single URL)")
        vc["id"] = credential_id
    return vc


def is_vc2(doc: Any) -> bool:
    """True iff `doc` satisfies the VC 2.0 REQUIRED structure: the exact first @context entry,
    a type set including VerifiableCredential, an issuer, and a credentialSubject."""
    if not isinstance(doc, dict):
        return False
    ctx = doc.get("@context")
    if not isinstance(ctx, list) or not ctx or ctx[0] != VC2_CONTEXT:
        return False
    types = doc.get("type")
    if not isinstance(types, list) or "VerifiableCredential" not in types:
        return False
    return bool(doc.get("issuer")) and isinstance(doc.get("credentialSubject"), dict)


def verify_vc_binding(vc: dict, atb_payload: dict) -> bool:
    """A VC is only as trustworthy as its link to the signed source. Confirm the VC's
    `algovoiEnvelopeRef` recomputes from `atb_payload`, so a VC cannot be re-pointed at a
    different (or tampered) ATB payload than the one the issuer actually signed."""
    if not is_vc2(vc):
        return False
    ref = vc.get("credentialSubject", {}).get("algovoiEnvelopeRef")
    return ref == "sha256:" + sha256_jcs(atb_payload)


def secure_vc_jose(vc: dict, *, private_key: Any, kid: str | None = None) -> str:
    """Secure a VC 2.0 credential as an enveloped EdDSA JWS (the VC-JOSE-COSE companion form).

    Reuses substrate2.jws.sign_receipt so the signing base and kid convention are identical to
    every other JWS this package emits. Returns a compact JWS whose payload is the VC.
    """
    if not is_vc2(vc):
        raise VcError("not a VC 2.0 credential; build it with to_vc() first")
    from .jws import sign_receipt

    return sign_receipt(vc, private_key=private_key, kid=kid)


# ---------------------------------------------------------------------------
# SD-JWT VC — DRAFT (draft-ietf-oauth-sd-jwt-vc-17), not an RFC. Labelled everywhere.
# ---------------------------------------------------------------------------

def _disclosure(name: str, value: Any) -> tuple[str, str]:
    """Build one SD-JWT disclosure ``base64url(JSON([salt, name, value]))`` and its digest.

    The digest is ``base64url(sha256(ascii(disclosure)))`` per the SD-JWT spec -- over the
    disclosure STRING, not the decoded array, which is the same signed-bytes discipline that
    jws_anchor_v1 pins.
    """
    salt = _b64url(secrets.token_bytes(16))
    disclosure = _b64url(json.dumps([salt, name, value], separators=(",", ":")).encode())
    digest = _b64url(hashlib.sha256(disclosure.encode("ascii")).digest())
    return disclosure, digest


def to_sd_jwt_vc(atb_payload: dict, *, private_key: Any, kid: str | None = None,
                 selective: tuple[str, ...] = ("trustScore", "threshold", "score_components")) -> str:
    """Issue the ATB credential as an SD-JWT VC issuance form. **DRAFT format.**

    Tracks ``draft-ietf-oauth-sd-jwt-vc-17``. This is deliberately additive and clearly a
    draft: the caller opts in, and nothing describes the output as a ratified standard. The
    selectively-disclosable claims are hashed into ``_sd`` and their disclosures appended
    after the JWT, tilde-separated, which is the issuance form
    ``<JWT>~<disclosure-1>~...~``.

    The signed JWT is produced by substrate2.jws.sign_receipt, so its bytes are anchored by
    exactly the rule in jws_anchor_v1: anchor the issuer JWT, never a re-canonicalised
    payload.
    """
    from .jws import sign_receipt

    vc = to_vc(atb_payload)
    subject = dict(vc["credentialSubject"])

    disclosures: list[str] = []
    sd_digests: list[str] = []
    for claim in selective:
        if claim in subject:
            disc, dig = _disclosure(claim, subject.pop(claim))
            disclosures.append(disc)
            sd_digests.append(dig)

    # SD-JWT VC JWT claims: vct + the always-disclosed subject, with _sd holding the hidden ones.
    jwt_claims = {
        "vct": ATB_VCT,
        "iss": vc["issuer"],
        "iat_str": vc["validFrom"],       # keep the RFC 3339 form; VC validity is a string
        "exp_str": vc["validUntil"],
        "_sd_alg": "sha-256",
        "credentialSubject": subject,
    }
    if sd_digests:
        jwt_claims["_sd"] = sorted(sd_digests)   # order carries no meaning; sort for determinism

    jwt = sign_receipt(jwt_claims, private_key=private_key, kid=kid)
    return jwt + "~" + "".join(d + "~" for d in disclosures)


def sd_jwt_vc_issuer_jwt(sd_jwt: str) -> str:
    """Return the issuer-signed JWT segment (before the first ``~``).

    This is the disclosure-invariant anchor from jws_anchor_v1: stable across every
    presentation derived from the credential. Anchor this, not a presentation.
    """
    return sd_jwt.split("~", 1)[0]


__all__ = [
    "VcError",
    "VC2_CONTEXT",
    "ALGOVOI_CONTEXT",
    "ATB_CREDENTIAL_TYPE",
    "ATB_VCT",
    "SD_JWT_VC_DRAFT",
    "to_vc",
    "is_vc2",
    "verify_vc_binding",
    "secure_vc_jose",
    "to_sd_jwt_vc",
    "sd_jwt_vc_issuer_jwt",
]
