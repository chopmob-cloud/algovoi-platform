"""Property-based fuzzing of the untrusted-input parsers.

The parsers (PDF ByteRange, CMS, artifact verify) sit on a trust boundary and
must NEVER crash on hostile bytes - they may only return "not verified". These
tests throw structured-but-adversarial and random bytes at them and assert the
no-crash / never-false-positive invariants.
"""
from __future__ import annotations

import base64
import json
import os
import sys

from hypothesis import given, settings, strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from algovoi_reseal import build_attestation_payload, verify_artifact  # noqa: E402
from algovoi_reseal import classical  # noqa: E402

_settings = settings(max_examples=300, deadline=None)


@_settings
@given(st.binary(max_size=4096))
def test_inspect_never_crashes(blob):
    payload = build_attestation_payload(blob, "fuzz.bin")
    assert payload["subject"]["size"] == len(blob)


@_settings
@given(st.binary(min_size=5, max_size=4096))
def test_pdf_parser_never_crashes(body):
    blob = b"%PDF-" + body
    payload = build_attestation_payload(blob, "fuzz.pdf")
    # If it claims a verified signature, that is a false positive on garbage.
    for sig in payload["classical"].get("signatures", []):
        if sig.get("verified"):
            raise AssertionError("false-positive verification on fuzzed PDF")


@_settings
@given(st.binary(max_size=4096))
def test_cms_parser_never_crashes(blob):
    payload = build_attestation_payload(blob, "fuzz.p7s")
    for sig in payload["classical"].get("signatures", []):
        assert sig.get("verified") is not True


@_settings
@given(st.text(max_size=256))
def test_verify_arbitrary_attestation_field(att):
    artifact = {"format": "algovoi-reseal/2",
                "attestation": att, "signer": {"falcon_pk": "AAAA"}}
    report = verify_artifact(artifact)
    assert report["ok"] is False


@_settings
@given(st.dictionaries(st.text(max_size=16), st.integers(), max_size=8))
def test_verify_arbitrary_dict(d):
    report = verify_artifact(d)
    assert report["ok"] is False


@_settings
@given(st.binary(max_size=2048))
def test_verify_b64_json_payloads(raw):
    att = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    artifact = {"format": "algovoi-reseal/2", "attestation": att,
                "signer": {"falcon_pk": "AAAA"}}
    report = verify_artifact(artifact)
    assert report["ok"] is False
