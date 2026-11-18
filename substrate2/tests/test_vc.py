"""Tests for substrate2.vc — W3C VC 2.0 (ratified) and SD-JWT VC (draft).

Two things are protected:

1. That the mapping is ADDITIVE. A VC is a presentation view of an already-signed ATB
   payload; producing one must not touch the ATB envelope or any content hash. The subject
   binds back to the signed payload by a content-addressed ref, and a VC re-pointed at a
   different payload must fail that binding.
2. That the ratified/draft line is kept. `to_vc` output is a conformant VC 2.0 credential;
   `to_sd_jwt_vc` output tracks an Internet-Draft and is exercised as such.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from substrate2 import atb_credential as atb
from substrate2 import vc
from substrate2.conformance._paths import ATB_ENVELOPE_B64

SEED = bytes(range(32))


@pytest.fixture(scope="module")
def atb_payload() -> dict:
    return atb.decode_payload(ATB_ENVELOPE_B64.read_text(encoding="utf-8").strip())


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


# ── VC 2.0 data model conformance ─────────────────────────────────────────────────────

def test_output_is_a_conformant_vc2_credential(atb_payload):
    doc = vc.to_vc(atb_payload)
    # the one non-negotiable rule: first @context entry is exactly the VC 2.0 URL
    assert doc["@context"][0] == vc.VC2_CONTEXT
    assert doc["type"][0] == "VerifiableCredential"
    assert doc["issuer"] == atb_payload["bench_issuer"]
    assert isinstance(doc["credentialSubject"], dict)
    assert vc.is_vc2(doc)


def test_validity_dates_are_rfc3339_strings(atb_payload):
    """VC 2.0 mandates XSD dateTime strings for validFrom/validUntil. This is the one place
    the substrate's integer-ms rule is deliberately NOT applied, because a VC is not
    content-addressed."""
    doc = vc.to_vc(atb_payload)
    assert doc["validFrom"] == atb_payload["issued_at"]
    assert doc["validUntil"] == atb_payload["expires_at"]
    assert isinstance(doc["validFrom"], str) and "T" in doc["validFrom"]


def test_integer_timestamp_is_rejected(atb_payload):
    bad = {**atb_payload, "issued_at": 1721030000000}
    with pytest.raises(vc.VcError):
        vc.to_vc(bad)


def test_missing_required_field_is_rejected(atb_payload):
    for drop in ("bench_issuer", "score", "passed", "expires_at"):
        bad = {k: v for k, v in atb_payload.items() if k != drop}
        with pytest.raises(vc.VcError):
            vc.to_vc(bad)


def test_credential_id_must_be_a_uri(atb_payload):
    with pytest.raises(vc.VcError):
        vc.to_vc(atb_payload, credential_id="not-a-uri")
    doc = vc.to_vc(atb_payload, credential_id="urn:algovoi:cred:1")
    assert doc["id"] == "urn:algovoi:cred:1"


# ── the binding back to the signed source ─────────────────────────────────────────────

def test_binding_recomputes_from_the_signed_payload(atb_payload):
    doc = vc.to_vc(atb_payload)
    assert vc.verify_vc_binding(doc, atb_payload)


def test_binding_fails_against_a_tampered_payload(atb_payload):
    """THE control. A VC asserts nothing the Falcon envelope did not sign; if it verified
    against a changed payload, the VC could launder an unsigned claim."""
    doc = vc.to_vc(atb_payload)
    assert not vc.verify_vc_binding(doc, {**atb_payload, "score": 0.5})
    assert not vc.verify_vc_binding(doc, {**atb_payload, "passed": False})


def test_additive_atb_envelope_is_untouched(atb_payload):
    """Producing a VC must not change the signed ATB envelope or its content hash."""
    from substrate2.digest import sha256_jcs

    before = sha256_jcs(atb_payload)
    vc.to_vc(atb_payload)
    vc.to_sd_jwt_vc(atb_payload, private_key=SEED)
    after = sha256_jcs(atb_payload)
    assert before == after


# ── VC-JOSE-COSE enveloped proof ──────────────────────────────────────────────────────

def test_jose_secured_vc_carries_the_credential(atb_payload):
    doc = vc.to_vc(atb_payload)
    token = vc.secure_vc_jose(doc, private_key=SEED)
    header, payload, _sig = token.split(".")
    assert json.loads(_b64d(header))["alg"] == "EdDSA"
    assert json.loads(_b64d(payload))["@context"][0] == vc.VC2_CONTEXT


def test_secure_refuses_a_non_vc(atb_payload):
    with pytest.raises(vc.VcError):
        vc.secure_vc_jose({"not": "a vc"}, private_key=SEED)


# ── SD-JWT VC — DRAFT ─────────────────────────────────────────────────────────────────

def test_sd_jwt_vc_issuance_form(atb_payload):
    sd = vc.to_sd_jwt_vc(atb_payload, private_key=SEED)
    assert sd.endswith("~")                       # issuance form ends with a trailing ~
    parts = [p for p in sd.split("~") if p]
    jwt, disclosures = parts[0], parts[1:]
    claims = json.loads(_b64d(jwt.split(".")[1]))
    assert claims["vct"] == vc.ATB_VCT
    assert claims["_sd_alg"] == "sha-256"
    assert len(disclosures) >= 1


def test_selective_claims_are_hidden_and_bound(atb_payload):
    """Each disclosed claim is removed from the JWT and its digest appears in _sd -- over the
    disclosure STRING, the same signed-bytes discipline as jws_anchor_v1."""
    sd = vc.to_sd_jwt_vc(atb_payload, private_key=SEED, selective=("trustScore", "threshold"))
    parts = [p for p in sd.split("~") if p]
    jwt, disclosures = parts[0], parts[1:]
    claims = json.loads(_b64d(jwt.split(".")[1]))

    assert "trustScore" not in claims["credentialSubject"]
    sd_set = set(claims["_sd"])
    for d in disclosures:
        digest = base64.urlsafe_b64encode(hashlib.sha256(d.encode("ascii")).digest()).decode().rstrip("=")
        assert digest in sd_set
        _salt, name, _value = json.loads(_b64d(d))
        assert name in ("trustScore", "threshold")


def test_issuer_jwt_anchor_is_disclosure_invariant(atb_payload):
    """The anchor is the segment before the first ~, and it is stable across every
    presentation derived from the credential (jws_anchor_v1 I2)."""
    sd = vc.to_sd_jwt_vc(atb_payload, private_key=SEED)
    parts = [p for p in sd.split("~") if p]
    jwt, disclosures = parts[0], parts[1:]
    presentation = jwt + "~" + disclosures[0] + "~"           # a subset
    assert vc.sd_jwt_vc_issuer_jwt(sd) == vc.sd_jwt_vc_issuer_jwt(presentation) == jwt


def test_draft_marker_is_present():
    """Guard against the draft ever being mislabelled as ratified in the code itself."""
    assert "draft-ietf-oauth-sd-jwt-vc" in vc.SD_JWT_VC_DRAFT
