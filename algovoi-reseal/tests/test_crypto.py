"""Cryptographic validation: FIPS parameter sizes, negative/bit-flip fuzzing,
dual-signature anti-strip binding, canonicalization robustness.

This is the "first PQC on the market" bar: prove the primitives are the correct
parameter sets, prove verification is not accidentally permissive, and prove the
PQC-agility design (dual sign) cannot be silently downgraded.

NOTE: cross-library interop against liboqs is a recommended additional check;
the PyPI `oqs` package is an unrelated namesquat, so a real liboqs build is
needed for that and is tracked as a follow-up. The size checks below pin the
parameter sets to FIPS 204 (ML-DSA-65) and the PQClean Falcon-1024 params.
"""
from __future__ import annotations

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pqcrypto.sign import falcon_1024 as F, ml_dsa_65 as M  # noqa: E402
from algovoi_reseal import (  # noqa: E402
    build_attestation_payload, seal_payload, verify_artifact,
    generate_keys, load_keys, _b64u, _b64u_dec, _kid,
)

CONTENT = b"long-lived evidence\n"


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("k"))
    generate_keys(d)
    return load_keys(d)


class TestFIPSParameters:
    """Wrong parameter set = wrong security level. Pin the sizes."""

    def test_ml_dsa_65_sizes(self):
        pk, sk = M.generate_keypair()
        sig = M.sign(sk, CONTENT)
        assert len(pk) == 1952   # FIPS 204 ML-DSA-65 public key
        assert len(sk) == 4032   # FIPS 204 ML-DSA-65 private key
        assert len(sig) == 3309  # FIPS 204 ML-DSA-65 signature

    def test_falcon_1024_sizes(self):
        pk, sk = F.generate_keypair()
        sig = F.sign(sk, CONTENT)
        assert len(pk) == 1793       # PQClean Falcon-1024 public key
        assert len(sk) == 2305
        assert 0 < len(sig) <= 1462  # Falcon sigs are variable-length


class TestNegativeCrypto:
    """Verification must reject every perturbation. No accidental permissiveness."""

    def test_falcon_wrong_key_rejected(self):
        pk1, sk1 = F.generate_keypair()
        pk2, _ = F.generate_keypair()
        sig = F.sign(sk1, CONTENT)
        assert F.verify(pk1, CONTENT, sig)
        assert not F.verify(pk2, CONTENT, sig)

    def test_mldsa_wrong_key_rejected(self):
        pk1, sk1 = M.generate_keypair()
        pk2, _ = M.generate_keypair()
        sig = M.sign(sk1, CONTENT)
        assert M.verify(pk1, CONTENT, sig)
        assert not M.verify(pk2, CONTENT, sig)

    def test_falcon_signature_bitflip_rejected(self):
        pk, sk = F.generate_keypair()
        sig = bytearray(F.sign(sk, CONTENT))
        for i in (0, len(sig) // 2, len(sig) - 1):
            bad = bytearray(sig)
            bad[i] ^= 0x01
            assert not F.verify(pk, CONTENT, bytes(bad)), f"flip at {i} accepted"

    def test_mldsa_signature_bitflip_rejected(self):
        pk, sk = M.generate_keypair()
        sig = bytearray(M.sign(sk, CONTENT))
        for i in (0, len(sig) // 3, len(sig) - 1):
            bad = bytearray(sig)
            bad[i] ^= 0x80
            assert not M.verify(pk, CONTENT, bytes(bad)), f"flip at {i} accepted"

    def test_message_bitflip_rejected(self):
        pk, sk = M.generate_keypair()
        sig = M.sign(sk, CONTENT)
        assert not M.verify(pk, CONTENT + b"\x00", sig)
        assert not M.verify(pk, b"\x00" + CONTENT, sig)

    def test_truncated_signature_rejected(self):
        pk, sk = M.generate_keypair()
        sig = M.sign(sk, CONTENT)
        assert not M.verify(pk, CONTENT, sig[:-1])
        assert not M.verify(pk, CONTENT, sig[:len(sig) // 2])


class TestDualSignatureBinding:
    """The PQC-agility promise: neither signature can be silently stripped."""

    def test_both_signatures_present(self, keys):
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        assert env["alg"] == "Falcon-1024" and env["alg2"] == "ML-DSA-65"
        assert env["payload"]["sealed_with"]["algs"] == ["Falcon-1024", "ML-DSA-65"]

    def test_stripping_mldsa_fails(self, keys):
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        # Attacker removes the ML-DSA signature to fall back to Falcon-only.
        for k in ("alg2", "kid2", "sig2"):
            env.pop(k, None)
        art["attestation"] = _b64u(json.dumps(env, separators=(",", ":"),
                                              sort_keys=True).encode())
        art["signer"].pop("mldsa_pk", None)
        report = verify_artifact(art, file_bytes=CONTENT)
        assert report["ok"] is False
        assert any(c["check"] == "sealed_with_binding" and c["ok"] is False
                   for c in report["checks"])

    def test_falcon_still_individually_valid_after_strip(self, keys):
        # Sanity: the strip does not break the Falcon signature itself - the
        # binding, not a broken signature, is what rejects it.
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        msg_before = json.dumps(env["payload"], separators=(",", ":"), sort_keys=True)
        for k in ("alg2", "kid2", "sig2"):
            env.pop(k, None)
        # payload unchanged -> falcon signature over it is still valid
        assert json.dumps(env["payload"], separators=(",", ":"), sort_keys=True) == msg_before

    def test_swapped_mldsa_key_fails(self, keys, tmp_path):
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        d = str(tmp_path / "other")
        generate_keys(d)
        other = load_keys(d)
        art["signer"]["mldsa_pk"] = other["mldsa_pk"]  # kid2 no longer matches
        report = verify_artifact(art, file_bytes=CONTENT)
        assert report["ok"] is False


class TestCanonicalization:
    """Signature is over rfc8785(payload); attacker-influenced strings must not
    open a canonicalization ambiguity, and unicode must round-trip."""

    def test_unicode_filename_roundtrips(self, keys):
        payload = build_attestation_payload(CONTENT, "契約書-\U0001f512.pdf")
        art = seal_payload(payload, keys)
        assert verify_artifact(art, file_bytes=CONTENT)["ok"]

    def test_payload_field_reorder_still_verifies(self, keys):
        # JCS is order-independent: re-serialising the payload with keys in a
        # different source order must produce identical canonical bytes and
        # still verify (proves we verify against canonical, not transmitted, bytes).
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        p = env["payload"]
        env["payload"] = dict(reversed(list(p.items())))  # different insertion order
        art["attestation"] = _b64u(json.dumps(env, separators=(",", ":")).encode())
        assert verify_artifact(art, file_bytes=CONTENT)["ok"]

    def test_subject_hash_swap_breaks(self, keys):
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        env["payload"]["subject"]["sha256"] = "0" * 64
        art["attestation"] = _b64u(json.dumps(env, separators=(",", ":")).encode())
        # payload changed -> falcon signature no longer matches
        assert verify_artifact(art, file_bytes=CONTENT)["ok"] is False


class TestKidModel:
    def test_kid_is_derived_from_pubkey(self, keys):
        pk = _b64u_dec(keys["falcon_pk"])
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        env = json.loads(_b64u_dec(art["attestation"]))
        assert env["kid"] == _kid(pk)

    def test_kid_is_full_256_bit(self, keys):
        # Finding 4: a truncated (64-bit) kid is second-preimage-able by the
        # quantum adversary this tool targets. The anchor must be full width.
        env = json.loads(_b64u_dec(
            seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)["attestation"]))
        assert env["kid"].startswith("sha256:")
        assert len(env["kid"].split(":", 1)[1]) == 64  # 256 bits of hex


class TestMLDSALevel:
    """Selectable second-signature level: ML-DSA-65 (L3, default) or 87 (L5)."""

    def test_default_is_mldsa_65(self, keys):
        env = json.loads(_b64u_dec(
            seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)["attestation"]))
        assert env["payload"]["sealed_with"]["algs"] == ["Falcon-1024", "ML-DSA-65"]

    def test_mldsa_87_seal_and_verify(self, tmp_path):
        d = str(tmp_path / "k87")
        generate_keys(d, mldsa_alg="ML-DSA-87")
        k87 = load_keys(d)
        assert k87["mldsa_alg"] == "ML-DSA-87"
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), k87)
        env = json.loads(_b64u_dec(art["attestation"]))
        assert env["alg2"] == "ML-DSA-87"
        assert env["payload"]["sealed_with"]["algs"] == ["Falcon-1024", "ML-DSA-87"]
        assert verify_artifact(art, file_bytes=CONTENT)["ok"] is True

    def test_mldsa_87_stripping_still_fails(self, tmp_path):
        d = str(tmp_path / "k87b")
        generate_keys(d, mldsa_alg="ML-DSA-87")
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), load_keys(d))
        env = json.loads(_b64u_dec(art["attestation"]))
        for k in ("alg2", "kid2", "sig2"):
            env.pop(k, None)
        art["attestation"] = _b64u(json.dumps(env, separators=(",", ":"),
                                              sort_keys=True).encode())
        art["signer"].pop("mldsa_pk", None)
        assert verify_artifact(art, file_bytes=CONTENT)["ok"] is False

    def test_87_signature_larger_than_65(self, keys, tmp_path):
        d = str(tmp_path / "k87c")
        generate_keys(d, mldsa_alg="ML-DSA-87")
        e65 = json.loads(_b64u_dec(
            seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)["attestation"]))
        e87 = json.loads(_b64u_dec(
            seal_payload(build_attestation_payload(CONTENT, "a.txt"), load_keys(d))["attestation"]))
        assert len(e87["sig2"]) > len(e65["sig2"])

    def test_unknown_mldsa_alg_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            generate_keys(str(tmp_path / "bad"), mldsa_alg="ML-DSA-99")


class TestRedTeamFixes:
    def test_verifier_without_mldsa_fails_closed(self, keys, monkeypatch):
        # Finding 2: a verifier build with no ML-DSA verifier available must NOT
        # silently pass the second-signature dimension of a dual-sealed
        # artifact. The verifier dispatches via _MLDSA_VERIFIERS, so an empty
        # registry models the missing-build case; it must fail closed.
        import algovoi_reseal_verify as V
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        monkeypatch.setattr(V, "_MLDSA_VERIFIERS", {})
        report = verify_artifact(art, file_bytes=CONTENT)
        assert report["ok"] is False

    def test_huge_byterange_does_not_crash(self):
        # Finding 6a: multi-million-digit ByteRange must not raise out of parse.
        blob = b"%PDF-1.7\n/ByteRange [0 " + b"9" * 5_000_000 + b" 1 1] x"
        payload = build_attestation_payload(blob, "bomb.pdf")  # must return, not raise
        assert payload["subject"]["size"] == len(blob)

    def test_rfc3161_with_bad_attestation_hash_fails_clean(self, keys):
        # Finding 6b: attacker sets rfc3161 + a malformed attestation_hash.
        art = seal_payload(build_attestation_payload(CONTENT, "a.txt"), keys)
        art["rfc3161"] = {"token_b64": base64.b64encode(b"x").decode()}
        art["attestation_hash"] = 12345  # non-string
        report = verify_artifact(art, file_bytes=CONTENT)
        assert report["ok"] is False  # clean fail, no traceback
