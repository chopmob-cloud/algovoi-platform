"""Absolute paths to the local conformance assets. Nothing here reaches the network.

Resolution: the conformance gate is fully self-contained when the vector mirror is
bundled inside the installer (``_bundled_vectors/`` with a ``manifest.json``). In that
case every asset resolves to the bundled copy and the gate runs from first boot with
zero external files. When the bundle is absent (e.g. a source checkout that did not
ship it), assets fall back to the external corpus under ALGOVOI_ASSET_ROOT:
  1. ALGOVOI_ASSET_ROOT env var — set this on any non-standard layout.
  2. Platform default: C:\\algo on Windows, /opt/algovoi on Linux/macOS.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _asset_root() -> Path:
    env = os.environ.get("ALGOVOI_ASSET_ROOT")
    if env:
        return Path(env)
    return Path(r"C:\algo") if sys.platform == "win32" else Path("/opt/algovoi")


_ROOT = _asset_root()

# Vectors shipped INSIDE the installer. A complete mirror (manifest + all anchor sets +
# schema examples + ATB verifier + retention vectors) makes the gate self-contained.
BUNDLED_VECTORS_DIR = Path(__file__).resolve().parent / "_bundled_vectors"
_HAVE_BUNDLE = (BUNDLED_VECTORS_DIR / "manifest.json").exists()

# External corpus (used only when the bundle is absent).
_CORPUS = _ROOT / "algovoi-jcs-conformance-vectors"
_ATB_BASE = Path(r"C:\algo\platform\.deploy_tmp") if sys.platform == "win32" else _ROOT / "platform" / ".deploy_tmp"
_CORPUS_ATB = _ATB_BASE / "atb_conformance_vectors"
_CORPUS_RETENTION = _ROOT / "platform" / "algovoi-retention-chain" / "vectors"

if _HAVE_BUNDLE:
    # Fully self-contained: everything resolves inside the installer.
    JCS_VECTORS_ROOT = BUNDLED_VECTORS_DIR
    JCS_MANIFEST = BUNDLED_VECTORS_DIR / "manifest.json"
    JCS_VECTORS_DIR = BUNDLED_VECTORS_DIR
    JCS_SCHEMA_EXAMPLES = BUNDLED_VECTORS_DIR / "schemas" / "examples"
    ATB_VECTORS_ROOT = BUNDLED_VECTORS_DIR / "_atb"
    _RETENTION_DIR = BUNDLED_VECTORS_DIR / "_retention"
else:
    JCS_VECTORS_ROOT = _CORPUS
    JCS_MANIFEST = _CORPUS / "manifest.json"
    JCS_VECTORS_DIR = _CORPUS / "vectors"
    JCS_SCHEMA_EXAMPLES = _CORPUS / "schemas" / "examples"
    ATB_VECTORS_ROOT = _CORPUS_ATB
    _RETENTION_DIR = _CORPUS_RETENTION

# ATB conformance vectors + the gold-standard external (stdlib+rfc8785+pqcrypto) verifier.
ATB_ENVELOPE_B64 = ATB_VECTORS_ROOT / "envelope.b64"
ATB_PUBKEY_B64 = ATB_VECTORS_ROOT / "pubkey.b64"
ATB_CERT_RESPONSE = ATB_VECTORS_ROOT / "cert_response.json"
VERIFY_FROM_SPEC = ATB_VECTORS_ROOT / "verify_from_spec.py"

# RFC 9421 signed retention-chain link vectors (Section 8b).
RETENTION_RFC9421_VECTORS = _RETENTION_DIR / "retention-chain-rfc9421-v1.json"


def vector_set_path(set_name: str, primary_file: str) -> Path:
    """Resolve a vector-set primary file, preferring the bundled mirror.

    With a complete bundle present, JCS_VECTORS_DIR already points at the bundle, so
    this returns the bundled copy; otherwise it falls back to the external corpus.
    """
    bundled = BUNDLED_VECTORS_DIR / set_name / primary_file
    if bundled.exists():
        return bundled
    return JCS_VECTORS_DIR / set_name / primary_file
