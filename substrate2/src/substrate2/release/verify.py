"""
substrate2.release.verify — offline verification of a signed substrate2 release.

This is the half the customer runs, before install, on a box with no network. It answers
one question: are the bytes on this disk the bytes AlgoVoi signed?

Posture, inherited deliberately from the AV-MESH-ENT CRL verifier because that posture was
adversarially validated:

  * STRICT. An unsigned or malformed envelope is refused, never downgraded.
  * NO algorithm agility. `alg` must equal the compiled-in constant. It never selects a
    verifier -- that is the classic algorithm-confusion foothold.
  * NO kid-based key resolution. The caller pins the public key; `kid` is checked against
    it rather than used to look one up.
  * Signature FIRST. No payload field is trusted, compared or reported before the
    signature over the canonical bytes has verified.
  * FAIL-CLOSED. Every unexpected condition returns not-ok. The function does not raise,
    so a caller cannot turn a crash into an accidental pass by catching broadly.
"""
from __future__ import annotations

import hmac
import os
import time
from dataclasses import dataclass
from typing import Any

from .. import pqc
from ..canon import CanonicalizationError, canonicalize_bytes
from ..digest import sha256_jcs
from ._common import ALG, MANIFEST_TYPE, b64url_dec, sha256_file
from .manifest import ROLES


@dataclass(frozen=True)
class ReleaseVerifyResult:
    """Outcome of a verification. `payload` is populated only when `ok` is True."""

    ok: bool
    reason: str
    payload: dict[str, Any] | None = None

    def __bool__(self) -> bool:  # pragma: no cover - convenience only
        return self.ok


def _fail(reason: str) -> ReleaseVerifyResult:
    return ReleaseVerifyResult(False, reason)


def verify_release(
    envelope: Any,
    public_key: bytes,
    *,
    expected_package: str = "substrate2",
    min_version: int = 1,
    now_ms: int | None = None,
    artifact_dir: str | os.PathLike[str] | None = None,
    sbom: dict[str, Any] | None = None,
    expected_report_digest: str | None = None,
) -> ReleaseVerifyResult:
    """Verify a `substrate2_release_v1` envelope against a pinned public key.

    `artifact_dir`, when given, is where the shipped files live; every artifact named in
    the manifest must be present there and hash to its recorded digest. Passing it is what
    turns "this manifest is authentic" into "these files are the released files".

    `min_version` is the highest release version this installation has already seen.
    Refusing anything below it stops an attacker replaying a correctly signed but
    superseded release -- the one with the vulnerability you just patched.
    """
    # --- envelope shape, before any crypto -------------------------------------------
    if not isinstance(envelope, dict):
        return _fail("envelope: not an object")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return _fail("envelope: payload missing or not an object")
    if envelope.get("alg") != ALG:
        return _fail(f"envelope: alg {envelope.get('alg')!r} != {ALG!r}")

    expected_kid = pqc.falcon_kid(public_key)
    if envelope.get("kid") != expected_kid:
        return _fail("envelope: kid does not match the pinned public key")

    try:
        sig = b64url_dec(envelope["sig"])
    except (KeyError, TypeError, ValueError):
        return _fail("envelope: sig missing or not base64url")

    # --- signature, before any payload field is trusted -------------------------------
    try:
        signed_bytes = canonicalize_bytes(payload)
    except (CanonicalizationError, TypeError, ValueError) as exc:
        return _fail(f"payload: not canonicalisable ({exc})")
    if not pqc.verify_falcon_1024(public_key, signed_bytes, sig):
        return _fail("signature: rejected")

    # --- everything below is now inside the signature ---------------------------------
    if payload.get("type") != MANIFEST_TYPE:
        return _fail(f"payload: type {payload.get('type')!r} != {MANIFEST_TYPE!r}")
    if payload.get("signer_kid") != expected_kid:
        return _fail("payload: signer_kid does not match the pinned public key")
    if payload.get("package") != expected_package:
        return _fail(f"payload: package {payload.get('package')!r} != {expected_package!r}")

    version = payload.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        return _fail("payload: version is not an integer")
    if version < min_version:
        return _fail(f"payload: version {version} < pinned minimum {min_version} (rollback)")

    issued = payload.get("issued_at_ms")
    expires = payload.get("expires_at_ms")
    if not isinstance(issued, int) or not isinstance(expires, int):
        return _fail("payload: issued_at_ms/expires_at_ms are not integers")
    now = int(time.time() * 1000) if now_ms is None else int(now_ms)
    if now < issued:
        return _fail("payload: not yet valid")
    if now >= expires:
        return _fail("payload: expired")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return _fail("payload: artifacts missing or empty")
    for row in artifacts:
        if not isinstance(row, dict):
            return _fail("artifacts: row is not an object")
        if row.get("role") not in ROLES:
            # A role this verifier does not know may be load-bearing. Refuse rather than
            # skip: skipping is how an attacker gets a file past an old verifier.
            return _fail(f"artifacts: unknown role {row.get('role')!r}")
        if not isinstance(row.get("sha256"), str) or not isinstance(row.get("size"), int):
            return _fail("artifacts: malformed sha256/size")

    if sbom is not None:
        declared = (payload.get("sbom") or {}).get("sha256")
        if not isinstance(declared, str) or not hmac.compare_digest(sha256_jcs(sbom), declared):
            return _fail("sbom: does not match the digest bound in the manifest")

    if expected_report_digest is not None:
        got = (payload.get("conformance") or {}).get("report_digest")
        if not isinstance(got, str) or not hmac.compare_digest(got, expected_report_digest):
            return _fail("conformance: report_digest does not match the expected build")

    if artifact_dir is not None:
        for row in artifacts:
            path = os.path.join(os.fspath(artifact_dir), row["name"])
            if not os.path.isfile(path):
                return _fail(f"artifact {row['name']!r}: missing from {artifact_dir}")
            digest, size = sha256_file(path)
            # Constant-time even though these are public values: the habit is what stops
            # a timing leak the day one of these covers something that is not public.
            if size != row["size"] or not hmac.compare_digest(digest, row["sha256"]):
                return _fail(f"artifact {row['name']!r}: does not match the signed digest")

    return ReleaseVerifyResult(True, "ok", payload=payload)


__all__ = ["ReleaseVerifyResult", "verify_release"]
