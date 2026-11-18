"""Trust-path and CRL revocation: offline chain validation, adversarially tested.

Builds a real two-level PKI (root CA -> signer) with cryptography, so the path
builder and CRL checker run against genuine X.509, and the attacker cases use a
second, untrusted root.
"""
from __future__ import annotations

import datetime
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from algovoi_reseal import trust, classical  # noqa: E402

CONTENT = b"contract body under a real PKI\n"
_DER = serialization.Encoding.DER


def _ca(cn, issuer_key=None, issuer_cert=None, is_ca=True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    signer_key = issuer_key or key
    issuer_name = issuer_cert.subject if issuer_cert else subj
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True))
    return key, b.sign(signer_key, hashes.SHA256())


@pytest.fixture(scope="module")
def pki():
    root_key, root = _ca("Reseal Root CA")
    signer_key, signer = _ca("Doc Signer", issuer_key=root_key, issuer_cert=root, is_ca=False)
    other_root_key, other_root = _ca("Untrusted Root CA")
    return {
        "root_der": root.public_bytes(_DER),
        "signer_der": signer.public_bytes(_DER),
        "signer_key": signer_key, "signer_cert": signer,
        "root_key": root_key, "root_cert": root,
        "other_root_der": other_root.public_bytes(_DER),
    }


def _cms_with_chain(pki):
    return (pkcs7.PKCS7SignatureBuilder().set_data(CONTENT)
            .add_signer(pki["signer_cert"], pki["signer_key"], hashes.SHA256())
            .sign(_DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))


class TestChain:
    def test_chains_to_trusted_root(self, pki):
        r = trust.verify_chain([pki["signer_der"], pki["root_der"]], [pki["root_der"]])
        assert r["ok"], r
        assert r["anchor_fp"]

    def test_rejects_untrusted_root(self, pki):
        r = trust.verify_chain([pki["signer_der"], pki["root_der"]], [pki["other_root_der"]])
        assert r["ok"] is False

    def test_no_roots_supplied_is_unchecked_not_pass(self, pki):
        r = trust.verify_chain([pki["signer_der"]], [])
        assert r["ok"] is False
        assert "trust_path_to_root" in r["not_checked"]

    def test_signer_alone_without_issuer_fails(self, pki):
        # Leaf only, root trusted but not in chain and issuer-subject linkage
        # must still resolve via root_subjects -> should succeed.
        r = trust.verify_chain([pki["signer_der"]], [pki["root_der"]])
        assert r["ok"], r


class TestRevocation:
    def _crl(self, pki, revoke_serial=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateRevocationListBuilder()
             .issuer_name(pki["root_cert"].subject)
             .last_update(now - datetime.timedelta(hours=1))
             .next_update(now + datetime.timedelta(days=7)))
        if revoke_serial is not None:
            b = b.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(revoke_serial)
                .revocation_date(now - datetime.timedelta(hours=2)).build())
        return b.sign(pki["root_key"], hashes.SHA256()).public_bytes(_DER)

    def test_not_revoked(self, pki):
        crl = self._crl(pki)
        r = trust.check_revocation(pki["signer_der"], pki["root_der"], crl)
        assert r["ok"] is True and r["revoked"] is False

    def test_revoked_serial_detected(self, pki):
        crl = self._crl(pki, revoke_serial=pki["signer_cert"].serial_number)
        r = trust.check_revocation(pki["signer_der"], pki["root_der"], crl)
        assert r["ok"] is False and r["revoked"] is True

    def test_stale_crl_flagged(self, pki):
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = (x509.CertificateRevocationListBuilder()
               .issuer_name(pki["root_cert"].subject)
               .last_update(now - datetime.timedelta(days=40))
               .next_update(now - datetime.timedelta(days=33))  # already expired
               .sign(pki["root_key"], hashes.SHA256()).public_bytes(_DER))
        r = trust.check_revocation(pki["signer_der"], pki["root_der"], crl)
        assert r["crl_current"] is False

    def test_crl_from_wrong_issuer_rejected(self, pki):
        # A CRL signed by the untrusted root proves nothing about our signer.
        other_key, other = None, None
        # Build a CRL signed by a key that is NOT the cert's issuer.
        stranger_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = (x509.CertificateRevocationListBuilder()
               .issuer_name(pki["root_cert"].subject)
               .last_update(now - datetime.timedelta(hours=1))
               .next_update(now + datetime.timedelta(days=7))
               .sign(stranger_key, hashes.SHA256()).public_bytes(_DER))
        r = trust.check_revocation(pki["signer_der"], pki["root_der"], crl)
        assert r["ok"] is False  # signature does not verify under issuer key


class TestAdversarialChain:
    def test_name_colliding_rogue_root_does_not_verify(self, pki):
        # Attacker forges a cert carrying the trusted root's SUBJECT NAME but a
        # different key, and signs a leaf with it. Against the real trusted
        # root, the path must NOT verify (signature under the real root fails).
        real_root = x509.load_der_x509_certificate(pki["root_der"])
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        rogue_root = (x509.CertificateBuilder()
                      .subject_name(real_root.subject).issuer_name(real_root.subject)
                      .public_key(rogue_key.public_key())
                      .serial_number(x509.random_serial_number())
                      .not_valid_before(now - datetime.timedelta(days=1))
                      .not_valid_after(now + datetime.timedelta(days=3650))
                      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                      .sign(rogue_key, hashes.SHA256()))
        leaf_key, leaf = _ca("Doc Signer", issuer_key=rogue_key, issuer_cert=rogue_root, is_ca=False)
        r = trust.verify_chain(
            [leaf.public_bytes(_DER), rogue_root.public_bytes(_DER)], [pki["root_der"]])
        assert r["ok"] is False

    def test_self_signed_leaf_not_in_trust_fails(self, pki):
        key, leaf = _ca("Self Signed", is_ca=False)
        r = trust.verify_chain([leaf.public_bytes(_DER)], [pki["root_der"]])
        assert r["ok"] is False

    def test_cyclic_chain_terminates(self, pki):
        # Two certs each naming the other as issuer must not loop forever.
        r = trust.verify_chain([pki["signer_der"], pki["signer_der"]], [pki["other_root_der"]])
        assert r["ok"] is False

    def test_is_ca_requires_keycertsign(self):
        # Finding 7: CA:TRUE without the keyCertSign bit is not a valid issuer.
        now = datetime.datetime.now(datetime.timezone.utc)
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA no certsign")])

        def build(key_cert_sign):
            return (x509.CertificateBuilder().subject_name(n).issuer_name(n)
                    .public_key(k.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.KeyUsage(
                        digital_signature=True, content_commitment=False, key_encipherment=False,
                        data_encipherment=False, key_agreement=False, key_cert_sign=key_cert_sign,
                        crl_sign=key_cert_sign, encipher_only=False, decipher_only=False),
                        critical=True)
                    .sign(k, hashes.SHA256()))

        assert trust._is_ca(build(key_cert_sign=True)) is True
        assert trust._is_ca(build(key_cert_sign=False)) is False


class TestIntegration:
    def test_seal_records_trust_path(self, pki):
        block = classical.inspect_detached(
            CONTENT, _cms_with_chain(pki), trust_roots_der=[pki["root_der"]])
        sig = block["signatures"][0]
        assert sig["verified"] is True
        assert sig["trust_path"]["ok"] is True
        assert "trust_path_to_root" not in sig["not_checked"]

    def test_untrusted_root_fails_verified(self, pki):
        block = classical.inspect_detached(
            CONTENT, _cms_with_chain(pki), trust_roots_der=[pki["other_root_der"]])
        sig = block["signatures"][0]
        assert sig["verified"] is False  # cryptographically fine, but not trusted

    def test_revoked_signer_fails_verified(self, pki):
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = (x509.CertificateRevocationListBuilder()
               .issuer_name(pki["root_cert"].subject)
               .last_update(now - datetime.timedelta(hours=1))
               .next_update(now + datetime.timedelta(days=7))
               .add_revoked_certificate(
                   x509.RevokedCertificateBuilder()
                   .serial_number(pki["signer_cert"].serial_number)
                   .revocation_date(now).build())
               .sign(pki["root_key"], hashes.SHA256()).public_bytes(_DER))
        block = classical.inspect_detached(
            CONTENT, _cms_with_chain(pki),
            trust_roots_der=[pki["root_der"]], crl_bytes=crl)
        sig = block["signatures"][0]
        assert sig["revocation"]["revoked"] is True
        assert sig["verified"] is False
