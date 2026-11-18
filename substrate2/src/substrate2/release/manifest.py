"""
substrate2.release.manifest — build and sign the `substrate2_release_v1` manifest.

The gap this closes: every artifact substrate2 *produces* is signed and recomputable, but
the wheel that carries it shipped as a bare file. Perimeter controls (edge-sentinel,
substrate-guard-pro, fail2ban) all defend the serving side; none of them say anything
about whether the bytes a customer installed are the bytes AlgoVoi built. A substituted
wheel arrives through the legitimate channel and every perimeter control is irrelevant.

The manifest binds, in one Falcon-signed envelope:

  * the sha256 and size of each shipped artifact (the wheel, plus bundled wheels),
  * the sha256 of the CycloneDX SBOM,
  * the conformance `REPORT_DIGEST` the build was proven against.

That last binding is the commercially load-bearing one. GA-CRITERIA proves a *build*
passes eight criteria; without the manifest there is nothing tying the file on the
customer's disk to the build that was proven. With it, "this wheel is the wheel that
passed GA" is a claim the customer verifies offline, themselves.
"""
from __future__ import annotations

import os
import time
from typing import Any, Iterable, Sequence

from .. import pqc
from ..canon import canonicalize_bytes
from ..digest import sha256_jcs
from ._common import ALG, DEFAULT_VALIDITY_MS, MANIFEST_TYPE, b64url, sha256_file

# Roles are a closed enum: a verifier that meets an unknown role should not have to guess
# whether it is load-bearing. Extend deliberately, the way the receipt enums are extended.
ROLE_PRIMARY = "primary"
ROLE_BUNDLED = "bundled-dependency"
ROLES = frozenset({ROLE_PRIMARY, ROLE_BUNDLED})


class ManifestError(ValueError):
    """Raised when a manifest cannot be built from the inputs given."""


def describe_artifact(
    path: str | os.PathLike[str], *, role: str = ROLE_PRIMARY, name: str | None = None
) -> dict[str, Any]:
    """Hash a release artifact into its manifest row."""
    if role not in ROLES:
        raise ManifestError(f"unknown artifact role: {role!r}")
    digest, size = sha256_file(path)
    return {
        "name": name or os.path.basename(os.fspath(path)),
        "role": role,
        "sha256": digest,
        "size": size,
    }


def build_release_payload(
    *,
    package_version: str,
    artifacts: Sequence[dict[str, Any]],
    sbom: dict[str, Any],
    report_digest: str,
    public_key: bytes,
    version: int = 1,
    package: str = "substrate2",
    now_ms: int | None = None,
    validity_ms: int = DEFAULT_VALIDITY_MS,
) -> dict[str, Any]:
    """Assemble the unsigned manifest payload.

    `version` is monotonic per package and is what a verifier pins against to refuse a
    rollback to a superseded release -- the same protection `mesh_revocation_v1` gives the
    CRL. Bump it on every signed release, never reuse it.
    """
    if not artifacts:
        raise ManifestError("a release manifest must cover at least one artifact")
    if version < 1:
        raise ManifestError(f"version must be >= 1, got {version}")
    if sum(1 for a in artifacts if a.get("role") == ROLE_PRIMARY) != 1:
        raise ManifestError("exactly one artifact must carry role 'primary'")

    names = [a["name"] for a in artifacts]
    if len(set(names)) != len(names):
        raise ManifestError("artifact names must be unique within a manifest")

    issued = int(time.time() * 1000) if now_ms is None else int(now_ms)
    kid = pqc.falcon_kid(public_key)

    return {
        "type": MANIFEST_TYPE,
        "version": version,
        "package": package,
        "package_version": package_version,
        "issued_at_ms": issued,
        "expires_at_ms": issued + int(validity_ms),
        # Sorted so a rebuild over the same inputs yields byte-identical canonical bytes.
        "artifacts": sorted(artifacts, key=lambda a: a["name"]),
        "sbom": {"format": f"CycloneDX-{sbom['specVersion']}", "sha256": sha256_jcs(sbom)},
        "conformance": {"report_digest": report_digest},
        # Binds the payload to the signing key, so an envelope cannot be re-wrapped under
        # a different key without the mismatch being visible inside the signed bytes.
        "signer_kid": kid,
    }


def sign_release(payload: dict[str, Any], secret_key: bytes, public_key: bytes) -> dict[str, Any]:
    """Wrap a payload in the `{payload, sig, alg, kid}` envelope used estate-wide."""
    kid = pqc.falcon_kid(public_key)
    if payload.get("signer_kid") != kid:
        raise ManifestError("payload signer_kid does not match the signing key")
    sig = pqc.sign_falcon_1024(secret_key, canonicalize_bytes(payload))
    return {"payload": payload, "sig": b64url(sig), "alg": ALG, "kid": kid}


def build_signed_release(
    *,
    package_version: str,
    artifact_paths: Iterable[tuple[str | os.PathLike[str], str]],
    sbom: dict[str, Any],
    report_digest: str,
    secret_key: bytes,
    public_key: bytes,
    version: int = 1,
    now_ms: int | None = None,
) -> dict[str, Any]:
    """Hash, assemble and sign in one step. `artifact_paths` is (path, role) pairs."""
    artifacts = [describe_artifact(path, role=role) for path, role in artifact_paths]
    payload = build_release_payload(
        package_version=package_version,
        artifacts=artifacts,
        sbom=sbom,
        report_digest=report_digest,
        public_key=public_key,
        version=version,
        now_ms=now_ms,
    )
    return sign_release(payload, secret_key, public_key)


__all__ = [
    "ROLE_PRIMARY",
    "ROLE_BUNDLED",
    "ROLES",
    "ManifestError",
    "describe_artifact",
    "build_release_payload",
    "sign_release",
    "build_signed_release",
]
