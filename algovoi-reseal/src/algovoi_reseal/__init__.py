# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
# Copyright (c) 2026 AlgoVoi. All rights reserved.
"""algovoi_reseal — re-anchor classically signed evidence under post-quantum seals.

This is the proprietary sealing half of AlgoVoi Reseal. It holds the parts that
MINT an attestation: key generation and the Falcon-1024 + ML-DSA-65 signing
engine. Everything to do with INSPECTING classical signatures and VERIFYING a
sealed attestation lives in the open, Apache-2.0 ``algovoi-reseal-verify``
package and is re-exported here, so this package's tests and callers see one
namespace and the two halves share the exact same verification code.

The problem this solves: a document signed with RSA or ECDSA stays provable only
while those algorithms stay unforgeable. Records on decade-long retention clocks
outlive that window; once quantum forges the classical signature, the original
cannot be told from a tamper. The rescue is only possible NOW, while the
classical signature still verifies - which is what ``seal`` captures.
"""
from __future__ import annotations

import json
import os

import rfc8785

# Re-export the open verifier/inspector core so callers use one namespace.
from algovoi_reseal_verify import (  # noqa: F401
    FORMAT, ATTESTATION_TYPE, CANON_VERSION, _HAVE_MLDSA,
    _b64u, _b64u_dec, sha256_jcs, _prefixed, _kid,
    build_attestation_payload, verify_artifact,
)
from algovoi_reseal_verify import classical, trust, tsa  # noqa: F401

from .licensing import require_license, verify_license_offline, LicenseError  # noqa: F401

# The SIGNING primitives are what make this package proprietary.
from pqcrypto.sign.falcon_1024 import (
    generate_keypair as _falcon_keygen,
    sign as _falcon_sign,
)

# Second-signature signers by algorithm name. ML-DSA-65 (NIST L3, the default,
# for parity with the AlgoVoi estate) and ML-DSA-87 (NIST L5, matching
# Falcon-1024's level) are both offered; the choice is recorded in the keys and
# in the signed sealed_with, so the verifier dispatches on it.
_MLDSA_SIGNERS: dict = {}
try:
    from pqcrypto.sign.ml_dsa_65 import (
        generate_keypair as _g65, sign as _s65,
    )
    _MLDSA_SIGNERS["ML-DSA-65"] = (_g65, _s65)
except ImportError:  # pragma: no cover
    pass
try:
    from pqcrypto.sign.ml_dsa_87 import (
        generate_keypair as _g87, sign as _s87,
    )
    _MLDSA_SIGNERS["ML-DSA-87"] = (_g87, _s87)
except ImportError:  # pragma: no cover
    pass

DEFAULT_MLDSA_ALG = "ML-DSA-65"


# ── key management ───────────────────────────────────────────────────────────

def generate_keys(keys_dir: str, mldsa_alg: str = DEFAULT_MLDSA_ALG) -> dict:
    """Generate a Falcon-1024 (+ ML-DSA) signing identity.

    ``mldsa_alg`` selects the second signature: "ML-DSA-65" (NIST L3, default)
    or "ML-DSA-87" (NIST L5, matches Falcon-1024). The choice is recorded in the
    key file so seal and verify agree. Written 0600: the holder runs their own
    keys, so nothing of AlgoVoi's sits in the trust path of what they produce.
    """
    if mldsa_alg not in _MLDSA_SIGNERS:
        raise ValueError(f"unsupported ML-DSA algorithm {mldsa_alg!r}; "
                         f"available: {sorted(_MLDSA_SIGNERS)}")
    os.makedirs(keys_dir, exist_ok=True)
    falcon_pk, falcon_sk = _falcon_keygen()
    out = {"falcon_pk": _b64u(falcon_pk), "falcon_sk": _b64u(falcon_sk)}
    mldsa_keygen, _ = _MLDSA_SIGNERS[mldsa_alg]
    mldsa_pk, mldsa_sk = mldsa_keygen()
    out.update({"mldsa_pk": _b64u(mldsa_pk), "mldsa_sk": _b64u(mldsa_sk),
                "mldsa_alg": mldsa_alg})
    path = os.path.join(keys_dir, "reseal-keys.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(out, fh)
    return {"path": path, "falcon_kid": _kid(falcon_pk),
            "mldsa_alg": mldsa_alg, "mldsa_kid": _kid(mldsa_pk)}


def load_keys(keys_dir: str) -> dict:
    with open(os.path.join(keys_dir, "reseal-keys.json"), encoding="utf-8") as fh:
        return json.load(fh)


# ── attestation minting (proprietary) ────────────────────────────────────────

def seal_payload(payload: dict, keys: dict) -> dict:
    """Sign the payload into the estate envelope. Returns the artifact dict.

    The SET of signing algorithms and their kids is written into the payload
    (``sealed_with``) BEFORE signing, so it is covered by every signature. A
    verifier can then detect a stripped or downgraded signature: an attacker
    who removes the ML-DSA signature leaves a payload that still declares it,
    and verification fails. Without this, the dual signature would be pure
    theatre - the whole point of pairing a draft algorithm (Falcon-1024) with
    a finalized one (ML-DSA-65) is that neither can be silently dropped.

    Minting is the licensed action: this raises ``LicenseError`` unless a valid
    AlgoVoi licence is present (``ALGOVOI_LICENSE_KEY``). Inspection and
    verification are free and live in the open ``algovoi-reseal-verify`` package,
    so gating here never blocks anyone checking what a seal proves."""
    require_license()
    falcon_pk = _b64u_dec(keys["falcon_pk"])
    falcon_sk = _b64u_dec(keys["falcon_sk"])
    mldsa_alg = keys.get("mldsa_alg", DEFAULT_MLDSA_ALG)
    have_mldsa = bool(keys.get("mldsa_sk")) and mldsa_alg in _MLDSA_SIGNERS

    algs = ["Falcon-1024"]
    kids = [_kid(falcon_pk)]
    if have_mldsa:
        mldsa_pk = _b64u_dec(keys["mldsa_pk"])
        algs.append(mldsa_alg)
        kids.append(_kid(mldsa_pk))
    payload = {**payload, "sealed_with": {"algs": algs, "kids": kids}}

    msg = rfc8785.dumps(payload)
    env = {
        "payload": payload,
        "alg": "Falcon-1024",
        "kid": _kid(falcon_pk),
        "sig": _b64u(_falcon_sign(falcon_sk, msg)),
    }
    if have_mldsa:
        _, mldsa_sign = _MLDSA_SIGNERS[mldsa_alg]
        env["alg2"] = mldsa_alg
        env["kid2"] = _kid(mldsa_pk)
        env["sig2"] = _b64u(mldsa_sign(_b64u_dec(keys["mldsa_sk"]), msg))
    artifact = {
        "format": FORMAT,
        "attestation": _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()),
        "attestation_hash": _prefixed(payload),
        "signer": {"falcon_pk": keys["falcon_pk"]},
    }
    if have_mldsa:
        artifact["signer"]["mldsa_pk"] = keys["mldsa_pk"]
    return artifact


def attach_rfc3161(artifact: dict, tsa_url: str) -> dict:
    """Stamp the attestation hash at an independent RFC 3161 authority.

    The TSA sees only a hash (messageImprint), never content: no-PII holds.
    Failure raises; the caller decides whether an unstamped seal is acceptable.
    """
    digest_hex = artifact["attestation_hash"].split(":", 1)[1]
    token = tsa.timestamp_digest(bytes.fromhex(digest_hex), tsa_url)
    artifact["rfc3161"] = token
    return artifact
