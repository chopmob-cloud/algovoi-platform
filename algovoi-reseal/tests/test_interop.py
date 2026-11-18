# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""Cross-library interop: our signatures verify under liboqs (Open Quantum Safe).

Independent-implementation proof that our Falcon-1024 and ML-DSA-65 signatures
are standard-conformant, at BOTH the raw-primitive and the sealed-artifact level.

Skipped automatically where liboqs is not installed (it needs a C build); run in
an environment with liboqs-python + a built liboqs to exercise it.
"""
from __future__ import annotations

import base64
import json
import os
import sys

import pytest
import rfc8785

oqs = pytest.importorskip("oqs")
try:
    _MECHS = oqs.get_enabled_sig_mechanisms()
except Exception:  # noqa: BLE001 - shared lib not loadable
    pytest.skip("liboqs shared library not available", allow_module_level=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqcrypto.sign import falcon_1024 as PF, ml_dsa_65 as PM  # noqa: E402
try:
    from pqcrypto.sign import ml_dsa_87 as PM87
except ImportError:  # pragma: no cover
    PM87 = None
from algovoi_reseal import (  # noqa: E402
    build_attestation_payload, seal_payload, generate_keys, load_keys, _b64u_dec,
)

CONTENT = b"a payload whose canonical bytes both libraries must agree on\n"

_RAW = [("ML-DSA-65", PM, "ML-DSA-65"), ("Falcon-1024", PF, "Falcon-1024")]
if PM87 is not None and "ML-DSA-87" in _MECHS:
    _RAW.append(("ML-DSA-87", PM87, "ML-DSA-87"))


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("k"))
    generate_keys(d)
    return load_keys(d)


@pytest.mark.parametrize("label,P,mech", _RAW)
class TestRawInterop:
    def test_pqcrypto_sign_liboqs_verify(self, label, P, mech):
        pk, sk = P.generate_keypair()
        sig = P.sign(sk, CONTENT)
        with oqs.Signature(mech) as v:
            assert v.verify(CONTENT, sig, pk)
            assert not v.verify(CONTENT + b"x", sig, pk)

    def test_liboqs_sign_pqcrypto_verify(self, label, P, mech):
        with oqs.Signature(mech) as s:
            pk = s.generate_keypair()
            sig = s.sign(CONTENT)
        assert P.verify(pk, CONTENT, sig)
        assert not P.verify(pk, CONTENT, sig[:-1] + bytes([sig[-1] ^ 1]))


class TestSealedArtifactInterop:
    """The strongest check: a real reseal artifact's PQ signatures verify under
    liboqs against the exact JCS canonical bytes."""

    def test_artifact_signatures_verify_under_liboqs(self, keys):
        art = seal_payload(build_attestation_payload(CONTENT, "contract.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        msg = rfc8785.dumps(env["payload"])

        with oqs.Signature("Falcon-1024") as v:
            assert v.verify(msg, _b64u_dec(env["sig"]),
                            _b64u_dec(art["signer"]["falcon_pk"]))
        with oqs.Signature("ML-DSA-65") as v:
            assert v.verify(msg, _b64u_dec(env["sig2"]),
                            _b64u_dec(art["signer"]["mldsa_pk"]))

    def test_liboqs_rejects_tampered_artifact_payload(self, keys):
        art = seal_payload(build_attestation_payload(CONTENT, "contract.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        env["payload"]["subject"]["sha256"] = "0" * 64  # tamper
        msg = rfc8785.dumps(env["payload"])
        with oqs.Signature("Falcon-1024") as v:
            assert not v.verify(msg, _b64u_dec(env["sig"]),
                                _b64u_dec(art["signer"]["falcon_pk"]))

    @pytest.mark.skipif(PM87 is None or "ML-DSA-87" not in _MECHS,
                        reason="ML-DSA-87 not available in pqcrypto and/or liboqs build")
    def test_mldsa87_artifact_verifies_under_liboqs(self, tmp_path):
        d = str(tmp_path / "k87")
        generate_keys(d, mldsa_alg="ML-DSA-87")
        art = seal_payload(build_attestation_payload(CONTENT, "c.txt"), load_keys(d))
        env = json.loads(_b64u_dec(art["attestation"]))
        msg = rfc8785.dumps(env["payload"])
        with oqs.Signature("ML-DSA-87") as v:
            assert v.verify(msg, _b64u_dec(env["sig2"]),
                            _b64u_dec(art["signer"]["mldsa_pk"]))
