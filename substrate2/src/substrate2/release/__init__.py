"""
substrate2.release — signed release manifests: proving the artifact, not just its contents.

substrate2 makes tamper-evident, recomputable evidence about payments. Until now it
shipped as a bare wheel, so the one thing a customer could not verify was substrate2
itself. This subpackage closes that: a Falcon-1024 envelope binding the wheel's digest,
the SBOM's digest and the GA conformance `REPORT_DIGEST` into one artifact the customer
verifies offline, before install, with the key pinned.

Build side (AlgoVoi):

    from substrate2.release import build_sbom, build_signed_release
    sbom = build_sbom("substrate2", extras=["pqc"], bundled=[("algovoi-bpverify", "0.1.0")])
    env = build_signed_release(
        package_version="2.0.0",
        artifact_paths=[("dist/substrate2-2.0.0-py3-none-any.whl", "primary")],
        sbom=sbom, report_digest=REPORT_DIGEST,
        secret_key=sk, public_key=pk, version=1,
    )

Verify side (customer, offline):

    from substrate2.release import verify_release
    result = verify_release(env, PINNED_PK, artifact_dir="dist", min_version=1)
    if not result.ok:
        raise SystemExit(f"refusing to install: {result.reason}")
"""
from __future__ import annotations

from ._common import ALG, MANIFEST_TYPE
from .manifest import (
    ROLE_BUNDLED,
    ROLE_PRIMARY,
    ManifestError,
    build_release_payload,
    build_signed_release,
    describe_artifact,
    sign_release,
)
from .sbom import SbomError, build_sbom
from .verify import ReleaseVerifyResult, verify_release

__all__ = [
    "ALG",
    "MANIFEST_TYPE",
    "ROLE_PRIMARY",
    "ROLE_BUNDLED",
    "ManifestError",
    "SbomError",
    "ReleaseVerifyResult",
    "build_sbom",
    "describe_artifact",
    "build_release_payload",
    "sign_release",
    "build_signed_release",
    "verify_release",
]
