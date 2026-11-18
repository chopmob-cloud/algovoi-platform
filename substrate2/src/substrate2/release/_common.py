"""
substrate2.release._common — constants and helpers shared by the builder and the verifier.

Release engineering, not a protocol surface: nothing here is derived from a draft or from
v1 source. The envelope shape deliberately matches the one already used by
`atb_credential` and by the AV-MESH-ENT `mesh_revocation_v1` CRL, so an operator who can
read one signed AlgoVoi artifact can read all of them.
"""
from __future__ import annotations

import base64
import hashlib
import os

# Hardcoded, never read from the envelope. See verify.verify_release for why: an `alg`
# field that selects the verifier is an algorithm-confusion foothold, so `alg` is treated
# as a label that must MATCH this constant, never as a dispatch key.
ALG = "Falcon-1024"

MANIFEST_TYPE = "substrate2_release_v1"

# Releases are long-lived artifacts, not session credentials. A year keeps the freshness
# check meaningful (a manifest for a withdrawn build eventually stops verifying) without
# forcing a re-sign on customers running an air-gapped install.
DEFAULT_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000

_CHUNK = 1024 * 1024


def b64url(raw: bytes) -> str:
    """Unpadded base64url, matching the ATB/CRL envelope convention."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256_file(path: str | os.PathLike[str]) -> tuple[str, int]:
    """Return (lowercase hex sha256, size in bytes) for a file, read in chunks.

    Chunked because release artifacts are wheels and bundles, not payloads that should
    be held in memory just to be hashed.
    """
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            size += len(block)
            h.update(block)
    return h.hexdigest(), size


__all__ = [
    "ALG",
    "MANIFEST_TYPE",
    "DEFAULT_VALIDITY_MS",
    "b64url",
    "b64url_dec",
    "sha256_file",
]
