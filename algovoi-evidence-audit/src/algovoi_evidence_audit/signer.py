# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
# Copyright (c) 2026 AlgoVoi. All rights reserved.
"""Sign an audit report as a reseal-envelope attestation.

The report file is the subject: we build a reseal payload over the report bytes
and sign it with the auditor's Falcon-1024 (+ ML-DSA) key. The result is a
``.reseal.json`` the FREE ``algovoi-reseal-verify`` verifies unchanged, so an
auditor's report is tamper-evident and independently checkable, with the auditor
anchored via ``--expect-kid``.

Self-contained on purpose: the Evidence Auditor is its own licensed product and
must not require the separate sealer's licence to sign its own reports.
"""
from __future__ import annotations

import json
import os

import rfc8785

from algovoi_reseal_verify import (
    build_attestation_payload, _b64u, _b64u_dec, _kid, _prefixed, FORMAT,
)

from pqcrypto.sign.falcon_1024 import (
    generate_keypair as _falcon_keygen, sign as _falcon_sign,
)
_MLDSA: dict = {}
try:
    from pqcrypto.sign.ml_dsa_65 import generate_keypair as _g65, sign as _s65
    _MLDSA["ML-DSA-65"] = (_g65, _s65)
except ImportError:  # pragma: no cover
    pass
try:
    from pqcrypto.sign.ml_dsa_87 import generate_keypair as _g87, sign as _s87
    _MLDSA["ML-DSA-87"] = (_g87, _s87)
except ImportError:  # pragma: no cover
    pass

DEFAULT_MLDSA_ALG = "ML-DSA-65"


def generate_keys(keys_dir: str, mldsa_alg: str = DEFAULT_MLDSA_ALG) -> dict:
    """Generate the auditor's Falcon-1024 (+ ML-DSA) identity, 0600."""
    if mldsa_alg not in _MLDSA:
        raise ValueError(f"unsupported ML-DSA algorithm {mldsa_alg!r}; available: {sorted(_MLDSA)}")
    os.makedirs(keys_dir, exist_ok=True)
    fpk, fsk = _falcon_keygen()
    out = {"falcon_pk": _b64u(fpk), "falcon_sk": _b64u(fsk)}
    g, _ = _MLDSA[mldsa_alg]
    mpk, msk = g()
    out.update({"mldsa_pk": _b64u(mpk), "mldsa_sk": _b64u(msk), "mldsa_alg": mldsa_alg})
    path = os.path.join(keys_dir, "audit-keys.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(out, fh)
    return {"path": path, "falcon_kid": _kid(fpk), "mldsa_alg": mldsa_alg, "mldsa_kid": _kid(mpk)}


def load_keys(keys_dir: str) -> dict:
    with open(os.path.join(keys_dir, "audit-keys.json"), encoding="utf-8") as fh:
        return json.load(fh)


def sign_bytes(report_bytes: bytes, keys: dict, filename: str = "audit-report.json") -> dict:
    """Return a reseal-envelope artifact over ``report_bytes`` (the subject)."""
    payload = build_attestation_payload(report_bytes, filename)
    fpk = _b64u_dec(keys["falcon_pk"])
    fsk = _b64u_dec(keys["falcon_sk"])
    mldsa_alg = keys.get("mldsa_alg", DEFAULT_MLDSA_ALG)
    have = bool(keys.get("mldsa_sk")) and mldsa_alg in _MLDSA

    algs, kids = ["Falcon-1024"], [_kid(fpk)]
    if have:
        mpk = _b64u_dec(keys["mldsa_pk"])
        algs.append(mldsa_alg)
        kids.append(_kid(mpk))
    payload = {**payload, "sealed_with": {"algs": algs, "kids": kids}}
    msg = rfc8785.dumps(payload)
    env = {"payload": payload, "alg": "Falcon-1024", "kid": _kid(fpk),
           "sig": _b64u(_falcon_sign(fsk, msg))}
    if have:
        _, sign = _MLDSA[mldsa_alg]
        env["alg2"] = mldsa_alg
        env["kid2"] = _kid(mpk)
        env["sig2"] = _b64u(sign(_b64u_dec(keys["mldsa_sk"]), msg))
    artifact = {"format": FORMAT,
                "attestation": _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()),
                "attestation_hash": _prefixed(payload),
                "signer": {"falcon_pk": keys["falcon_pk"]}}
    if have:
        artifact["signer"]["mldsa_pk"] = keys["mldsa_pk"]
    return artifact
