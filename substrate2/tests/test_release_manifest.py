"""
Adversarial tests for substrate2.release.

The happy path is one test. The rest are attacks, because a verifier that has only ever
been shown valid input is untested. Each attack below is a way a substituted or replayed
wheel could reach a customer, and each must come back not-ok with a reason.
"""
from __future__ import annotations

import copy

import pytest

pytest.importorskip("pqcrypto")

from substrate2 import pqc  # noqa: E402
from substrate2.release import (  # noqa: E402
    ManifestError,
    build_release_payload,
    build_sbom,
    build_signed_release,
    describe_artifact,
    sign_release,
    verify_release,
)
from substrate2.release._common import ALG  # noqa: E402

REPORT_DIGEST = "428e59873889e5ca86d8f2240561932ac147687578a6572a54bacd4c352ba4ad"
NOW_MS = 1_784_000_000_000


@pytest.fixture(scope="module")
def keys() -> tuple[bytes, bytes]:
    pk, sk = pqc.generate_falcon_1024_keypair()
    return pk, sk


@pytest.fixture
def release(tmp_path, keys):
    """A signed release over two real files on disk."""
    pk, sk = keys
    wheel = tmp_path / "substrate2-2.0.0-py3-none-any.whl"
    wheel.write_bytes(b"PK\x03\x04 pretend wheel bytes")
    bundled = tmp_path / "algovoi_bpverify-0.1.0-py3-none-any.whl"
    bundled.write_bytes(b"PK\x03\x04 pretend bpverify bytes")

    sbom = build_sbom("substrate2")
    envelope = build_signed_release(
        package_version="2.0.0",
        artifact_paths=[(wheel, "primary"), (bundled, "bundled-dependency")],
        sbom=sbom,
        report_digest=REPORT_DIGEST,
        secret_key=sk,
        public_key=pk,
        version=3,
        now_ms=NOW_MS,
    )
    return envelope, sbom, tmp_path


# --------------------------------------------------------------------------- happy path


def test_honest_release_verifies_fully(release, keys):
    envelope, sbom, tmp_path = release
    pk, _ = keys
    result = verify_release(
        envelope,
        pk,
        artifact_dir=tmp_path,
        sbom=sbom,
        expected_report_digest=REPORT_DIGEST,
        min_version=3,
        now_ms=NOW_MS + 1000,
    )
    assert result.ok, result.reason
    assert result.payload["package_version"] == "2.0.0"
    assert len(result.payload["artifacts"]) == 2


# ------------------------------------------------------------------------------ attacks


def test_tampered_payload_is_rejected(release, keys):
    envelope, _, tmp_path = release
    pk, _ = keys
    forged = copy.deepcopy(envelope)
    forged["payload"]["artifacts"][0]["sha256"] = "0" * 64
    result = verify_release(forged, pk, artifact_dir=tmp_path, now_ms=NOW_MS)
    assert not result.ok
    assert "signature" in result.reason


def test_tampered_signature_is_rejected(release, keys):
    envelope, _, _ = release
    pk, _ = keys
    forged = copy.deepcopy(envelope)
    forged["sig"] = "A" + forged["sig"][1:]
    assert not verify_release(forged, pk, now_ms=NOW_MS).ok


def test_wrong_public_key_is_rejected(release):
    envelope, _, _ = release
    other_pk, _ = pqc.generate_falcon_1024_keypair()
    result = verify_release(envelope, other_pk, now_ms=NOW_MS)
    assert not result.ok
    assert "kid" in result.reason


def test_algorithm_confusion_is_rejected(release, keys):
    """`alg` must never select a verifier. Swapping it is refused outright."""
    envelope, _, _ = release
    pk, _ = keys
    forged = copy.deepcopy(envelope)
    forged["alg"] = "ML-DSA-65"
    result = verify_release(forged, pk, now_ms=NOW_MS)
    assert not result.ok
    assert "alg" in result.reason


def test_unsigned_envelope_is_rejected(release, keys):
    envelope, _, _ = release
    pk, _ = keys
    forged = copy.deepcopy(envelope)
    del forged["sig"]
    assert not verify_release(forged, pk, now_ms=NOW_MS).ok


def test_rollback_to_superseded_release_is_rejected(release, keys):
    """A correctly signed but older release is the patched-vulnerability replay."""
    envelope, _, tmp_path = release
    pk, _ = keys
    result = verify_release(envelope, pk, artifact_dir=tmp_path, min_version=4, now_ms=NOW_MS)
    assert not result.ok
    assert "rollback" in result.reason


def test_expired_manifest_is_rejected(release, keys):
    envelope, _, _ = release
    pk, _ = keys
    far_future = envelope["payload"]["expires_at_ms"] + 1
    result = verify_release(envelope, pk, min_version=3, now_ms=far_future)
    assert not result.ok
    assert "expired" in result.reason


def test_not_yet_valid_manifest_is_rejected(release, keys):
    envelope, _, _ = release
    pk, _ = keys
    result = verify_release(envelope, pk, min_version=3, now_ms=NOW_MS - 1)
    assert not result.ok
    assert "not yet valid" in result.reason


def test_wrong_package_is_rejected(release, keys):
    envelope, _, _ = release
    pk, _ = keys
    result = verify_release(envelope, pk, expected_package="something-else", now_ms=NOW_MS)
    assert not result.ok
    assert "package" in result.reason


def test_unknown_artifact_role_is_refused_not_skipped(keys, tmp_path):
    """An unrecognised role may be load-bearing; skipping it is how files get past."""
    pk, sk = keys
    artifact = describe_artifact(_write(tmp_path, "x.whl", b"x"), role="primary")
    payload = build_release_payload(
        package_version="2.0.0",
        artifacts=[artifact],
        sbom=build_sbom("substrate2"),
        report_digest=REPORT_DIGEST,
        public_key=pk,
        now_ms=NOW_MS,
    )
    payload["artifacts"][0]["role"] = "surprise"
    envelope = sign_release(payload, sk, pk)
    result = verify_release(envelope, pk, now_ms=NOW_MS)
    assert not result.ok
    assert "unknown role" in result.reason


def test_substituted_artifact_on_disk_is_rejected(release, keys):
    """The attack the whole subpackage exists to stop."""
    envelope, _, tmp_path = release
    pk, _ = keys
    (tmp_path / "substrate2-2.0.0-py3-none-any.whl").write_bytes(b"PK\x03\x04 malicious bytes")
    result = verify_release(envelope, pk, artifact_dir=tmp_path, min_version=3, now_ms=NOW_MS)
    assert not result.ok
    assert "does not match the signed digest" in result.reason


def test_missing_artifact_is_rejected(release, keys):
    envelope, _, tmp_path = release
    pk, _ = keys
    (tmp_path / "algovoi_bpverify-0.1.0-py3-none-any.whl").unlink()
    result = verify_release(envelope, pk, artifact_dir=tmp_path, min_version=3, now_ms=NOW_MS)
    assert not result.ok
    assert "missing" in result.reason


def test_swapped_sbom_is_rejected(release, keys):
    envelope, sbom, _ = release
    pk, _ = keys
    doctored = copy.deepcopy(sbom)
    doctored["components"].append(
        {"type": "library", "name": "evil", "version": "1.0", "purl": "pkg:pypi/evil@1.0"}
    )
    result = verify_release(envelope, pk, sbom=doctored, min_version=3, now_ms=NOW_MS)
    assert not result.ok
    assert "sbom" in result.reason


def test_conformance_digest_mismatch_is_rejected(release, keys):
    """Ties the file on disk to the build that actually passed GA."""
    envelope, _, _ = release
    pk, _ = keys
    result = verify_release(envelope, pk, expected_report_digest="f" * 64, min_version=3, now_ms=NOW_MS)
    assert not result.ok
    assert "report_digest" in result.reason


def test_malformed_envelopes_never_raise(keys):
    pk, _ = keys
    for junk in (None, "", 42, [], {}, {"payload": "not-an-object"}, {"payload": {}}):
        result = verify_release(junk, pk, now_ms=NOW_MS)
        assert not result.ok


# ------------------------------------------------------------------- builder guardrails


def test_sbom_is_deterministic():
    assert build_sbom("substrate2") == build_sbom("substrate2")


def test_sbom_skips_a_marker_gated_dependency_that_is_absent():
    """Caught on a clean Linux container: `typing-extensions` is gated on python_version
    and is simply not installed on 3.11+. Absence is the marker's answer, not an error."""
    from substrate2.release.sbom import _split_requirement

    name, extra, conditional = _split_requirement('typing-extensions>=4; python_version < "3.11"')
    assert (name, extra, conditional) == ("typing-extensions", None, True)
    # An unconditional requirement must still be distinguishable from a gated one.
    assert _split_requirement("rfc8785>=0.1.4") == ("rfc8785", None, False)
    assert _split_requirement("pqcrypto>=0.4.0; extra == 'pqc'") == ("pqcrypto", "pqc", False)


def test_sbom_records_the_bundled_commercial_wheel():
    sbom = build_sbom("substrate2", bundled=[("algovoi-bpverify", "0.1.0")])
    names = {c["name"] for c in sbom["components"]}
    assert "algovoi-bpverify" in names


def test_manifest_requires_exactly_one_primary(keys, tmp_path):
    pk, _ = keys
    two = [
        describe_artifact(_write(tmp_path, "a.whl", b"a"), role="primary"),
        describe_artifact(_write(tmp_path, "b.whl", b"b"), role="primary"),
    ]
    with pytest.raises(ManifestError, match="primary"):
        build_release_payload(
            package_version="2.0.0",
            artifacts=two,
            sbom=build_sbom("substrate2"),
            report_digest=REPORT_DIGEST,
            public_key=pk,
            now_ms=NOW_MS,
        )


def test_signing_refuses_a_payload_bound_to_another_key(keys, tmp_path):
    pk, sk = keys
    other_pk, _ = pqc.generate_falcon_1024_keypair()
    payload = build_release_payload(
        package_version="2.0.0",
        artifacts=[describe_artifact(_write(tmp_path, "a.whl", b"a"))],
        sbom=build_sbom("substrate2"),
        report_digest=REPORT_DIGEST,
        public_key=other_pk,
        now_ms=NOW_MS,
    )
    with pytest.raises(ManifestError, match="signer_kid"):
        sign_release(payload, sk, pk)


def test_envelope_uses_the_estate_wide_shape(release):
    envelope, _, _ = release
    assert set(envelope) == {"payload", "sig", "alg", "kid"}
    assert envelope["alg"] == ALG


def _write(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path
