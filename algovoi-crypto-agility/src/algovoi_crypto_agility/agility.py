"""
Crypto-agility engine: classify an estate's keys against the post-quantum transition, and migrate
signing + encryption forward to PQC WITH PROVABLE CONTINUITY.

The hard part of PQC adoption is not the primitive, it is the migration: a corpus of artifacts signed
under a legacy (quantum-vulnerable) key must stay trustable after you rotate to a post-quantum key. This
engine re-signs each legacy-attested artifact forward under Falcon-1024 and emits a signed *migration
attestation* binding {legacy alg + kid, content hash, new PQC kid, migrated_at}, so a verifier trusts the
continuity without the legacy key. It also hybrid-signs during the transition window and re-wraps
encrypted-at-rest data to ML-KEM-1024.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from algovoi_crypto_agility import licensing, signing
from algovoi_crypto_agility.encryption import HybridPqcEncryptor
from algovoi_crypto_agility.models import Classification, KeyRecord

# Algorithm catalogue -----------------------------------------------------------------
_PQC_SIGN = {"Falcon-1024", "Falcon-512", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA"}
_PQC_KEM = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
_CLASSICAL_SIGN = {"Ed25519", "Ed448", "ECDSA-P256", "ECDSA-P384", "RSA-2048", "RSA-3072", "RSA-4096", "secp256k1"}
_CLASSICAL_KEM = {"X25519", "ECDH-P256", "ECDH-P384", "RSA-OAEP"}


class CryptoAgilityError(RuntimeError):
    """Raised on an invalid migration request."""


def classify(algorithm: str) -> Classification:
    """Classify an algorithm against the post-quantum transition."""
    a = algorithm.strip()
    if a in _PQC_SIGN:
        return Classification(algorithm=a, family="signature", kind="post-quantum", quantum_vulnerable=False)
    if a in _PQC_KEM:
        return Classification(algorithm=a, family="kem", kind="post-quantum", quantum_vulnerable=False)
    if a in _CLASSICAL_SIGN:
        return Classification(algorithm=a, family="signature", kind="classical", quantum_vulnerable=True)
    if a in _CLASSICAL_KEM:
        return Classification(algorithm=a, family="kem", kind="classical", quantum_vulnerable=True)
    if "+" in a:   # e.g. "X25519+ML-KEM-1024" hybrid KEM
        # SECURITY (2026-08-19): do NOT assume any "+"-joined name is quantum-safe. Classify EACH
        # component; the pair is non-vulnerable only if every component is a known primitive AND at least
        # one is post-quantum. Any unrecognized component fails closed (quantum_vulnerable=True / unknown),
        # so a bogus name like "Ed25519+x" or "RSA-1024+foo" can't masquerade as a safe hybrid and drop
        # off the migration to-do list.
        parts = [p.strip() for p in a.split("+") if p.strip()]
        comps = [classify(p) for p in parts]   # each part has no "+", so recursion terminates
        all_known = bool(comps) and all(c.kind != "unknown" for c in comps)
        has_pq = any(c.kind == "post-quantum" for c in comps)
        if all_known and has_pq:
            return Classification(algorithm=a, family="kem", kind="hybrid", quantum_vulnerable=False)
        return Classification(algorithm=a, family="kem" if all_known else "unknown",
                              kind="hybrid" if all_known else "unknown", quantum_vulnerable=True)
    return Classification(algorithm=a, family="unknown", kind="unknown", quantum_vulnerable=True)


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def verify_legacy_ed25519(*, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Convenience: verify a legacy Ed25519 signature (the most common classical signing key)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:  # noqa: BLE001
        return False


class CryptoAgility:
    """Crypto-agility registry + PQC migration engine.

    The injected Falcon-1024 keypair is the **new post-quantum authority key** that signs every migration
    attestation and hybrid envelope. Migration evidence binds into the Substrate 2 chain like every other
    suite receipt (`canon_version: jcs-rfc8785-v1`) and verifies offline.
    """

    def __init__(self, *, secret_key: bytes, public_key: bytes,
                 authority_did: str = "did:web:agility.example") -> None:
        licensing.require_license()        # fail-closed: no valid AlgoVoi suite licence -> refuse
        self.sk = secret_key
        self.pk = public_key
        self.authority_did = authority_did
        self.kid = signing.kid_for(public_key)     # the NEW PQC key id
        self._registry: dict[str, KeyRecord] = {}

    # ---- registry ----------------------------------------------------------------
    def register(self, *, kid: str, algorithm: str, role: str | None = None,
                 status: str = "active", note: str = "") -> KeyRecord:
        c = classify(algorithm)
        rec = KeyRecord(kid=kid, algorithm=algorithm, role=role or c.family,
                        status=status, classification=c, note=note)
        self._registry[kid] = rec
        return rec

    def inventory(self) -> dict:
        """Snapshot of the estate: which keys are still quantum-vulnerable and active (need migration)."""
        recs = list(self._registry.values())
        by_status: dict = {}
        for r in recs:
            by_status[r.status] = by_status.get(r.status, 0) + 1
        return {
            "total": len(recs),
            "quantum_vulnerable_active": [r.kid for r in recs
                                          if r.classification.quantum_vulnerable and r.status == "active"],
            "post_quantum": [r.kid for r in recs if r.classification.kind == "post-quantum"],
            "by_status": by_status,
            "keys": [r.model_dump() for r in recs],
        }

    # ---- signature migration (the continuity proof) -------------------------------
    def migrate_signature(self, *, content_hash: str, legacy_alg: str, legacy_kid: str,
                          legacy_signature_verified: bool | None = None,
                          legacy_public_key: bytes | None = None,
                          legacy_signature: bytes | None = None,
                          legacy_message: bytes | None = None,
                          note: str = "") -> dict:
        """Re-attest a legacy-signed artifact forward under the new PQC key.

        ``content_hash`` is sha256 of the artifact. There are two ways to establish that the legacy
        signature is genuine, and the attestation records WHICH was used so a relying party is never
        misled:

        * **In-engine (preferred, ``verification="in-engine"``):** pass ``legacy_public_key`` +
          ``legacy_signature`` + ``legacy_message`` (the exact bytes the legacy signature covers). The
          authority verifies the signature itself (dispatched on the validated ``legacy_alg``) and binds
          ``content_hash`` to ``sha256(legacy_message)``. Only Ed25519 is verifiable in-engine today.
        * **Caller-asserted (``verification="caller-asserted"``):** pass ``legacy_signature_verified=True``
          when you verified the legacy signature OUT OF BAND. The attestation is honest that the authority
          did not itself check the legacy signature, so a consumer that requires a cryptographic check can
          insist on ``verification == "in-engine"``.

        SECURITY (2026-08-19): the continuity claim must not rest on an unauthenticated boolean. The engine
        now verifies in-engine when given the material, and otherwise records the check as caller-asserted
        rather than stamping an unqualified ``signature_verified: True`` as if the authority had verified it.
        """
        lc = classify(legacy_alg)
        if legacy_public_key is not None and legacy_signature is not None:
            if legacy_message is None:
                raise CryptoAgilityError(
                    "in-engine verification requires legacy_message (the exact bytes the legacy signature covers)")
            import hashlib
            digest = hashlib.sha256(legacy_message).hexdigest()
            if content_hash not in (digest, f"sha256:{digest}"):
                raise CryptoAgilityError("content_hash does not match sha256(legacy_message)")
            if legacy_alg == "Ed25519":
                ok = verify_legacy_ed25519(message=legacy_message, signature=legacy_signature,
                                           public_key=legacy_public_key)
            else:
                raise CryptoAgilityError(
                    f"no in-engine verifier for legacy_alg {legacy_alg!r}; verify out of band and pass "
                    f"legacy_signature_verified=True (recorded as caller-asserted)")
            if not ok:
                raise CryptoAgilityError("refusing to migrate: in-engine legacy signature verification failed")
            verification = "in-engine"
        elif legacy_signature_verified:
            verification = "caller-asserted"
        else:
            raise CryptoAgilityError(
                "refusing to migrate: legacy signature not verified — supply legacy_public_key + "
                "legacy_signature + legacy_message for in-engine verification, or legacy_signature_verified="
                "True for an out-of-band-asserted attestation")
        att: dict = {
            "canon_version": "jcs-rfc8785-v1",
            "kind": "signature-migration",
            "content_hash": content_hash,
            "legacy": {"algorithm": legacy_alg, "kid": legacy_kid,
                       "quantum_vulnerable": lc.quantum_vulnerable,
                       "signature_verified": True, "verification": verification},
            "migrated_to": {"algorithm": "Falcon-1024", "kid": self.kid},
            "authority_did": self.authority_did,
            "migrated_at_ms": _now_ms(),
        }
        if note:
            att["note"] = note
        envelope = signing.make_envelope(att, self.sk, self.pk)
        if legacy_kid in self._registry:                       # reflect migration in the registry
            self._registry[legacy_kid].status = "migrated"
            self._registry[legacy_kid].migrated_to_kid = self.kid
        return {"attestation": att, "attestation_envelope": envelope,
                "attestation_hash": signing.payload_hash(att), "migrated_to_kid": self.kid}

    # ---- hybrid / dual signing (transition window) --------------------------------
    def hybrid_sign(self, *, payload: dict, legacy_alg: str | None = None,
                    legacy_signature: bytes | None = None,
                    legacy_public_key: bytes | None = None) -> dict:
        """Sign ``payload`` under the new PQC key, optionally carrying a legacy signature alongside.

        During a transition window verifiers on either side can check their own algorithm: the PQC
        envelope is authoritative, the legacy block lets not-yet-migrated verifiers keep working.

        SECURITY (2026-08-19): when ``legacy_public_key`` is supplied, the legacy signature is verified over
        the canonical payload BEFORE it is embedded (Ed25519), so this never emits an envelope claiming a
        classical co-signature that does not actually cover the payload. The legacy block still sits outside
        the PQC signature, so a hybrid-aware verifier must independently re-check it (pass ``legacy_public_key``
        to :func:`verify_hybrid_envelope`).
        """
        pqc_env = signing.make_envelope(payload, self.sk, self.pk)
        out: dict = {"canon_version": "jcs-rfc8785-v1", "payload": payload, "pqc": pqc_env}
        if legacy_alg and legacy_signature is not None:
            if legacy_public_key is not None:
                import rfc8785
                if legacy_alg != "Ed25519":
                    raise CryptoAgilityError(
                        f"no in-engine verifier for legacy_alg {legacy_alg!r}; cannot pre-verify the "
                        f"legacy co-signature before embedding")
                if not verify_legacy_ed25519(message=rfc8785.dumps(payload), signature=legacy_signature,
                                             public_key=legacy_public_key):
                    raise CryptoAgilityError("legacy co-signature does not verify over the payload")
            out["legacy"] = {"algorithm": legacy_alg, "kind": classify(legacy_alg).kind,
                             "sig": signing.b64u_encode(legacy_signature)}
        return out

    # ---- encryption re-wrap (KEM migration) ---------------------------------------
    def rewrap(self, *, plaintext: bytes, new_mlkem_pubkey: bytes, old_kid: str, old_alg: str,
               content_label: str = "") -> dict:
        """Re-encrypt plaintext (decrypted from a legacy KEM) to ML-KEM-1024 + emit a re-wrap attestation.

        The attestation records only the content hash and the old/new key ids -- never the plaintext.
        """
        sealed = HybridPqcEncryptor(new_mlkem_pubkey).encrypt(plaintext)
        att: dict = {
            "canon_version": "jcs-rfc8785-v1",
            "kind": "rewrap-migration",
            "content_hash": "sha256:" + hashlib.sha256(plaintext).hexdigest(),
            "content_label": content_label,
            "from": {"algorithm": old_alg, "kid": old_kid,
                     "quantum_vulnerable": classify(old_alg).quantum_vulnerable},
            "to": {"algorithm": "ML-KEM-1024", "kid": signing.kid_for(new_mlkem_pubkey)},
            "authority_did": self.authority_did,
            "rewrapped_at_ms": _now_ms(),
        }
        envelope = signing.make_envelope(att, self.sk, self.pk)
        return {"sealed_b64": signing.b64u_encode(sealed), "attestation": att,
                "attestation_envelope": envelope, "attestation_hash": signing.payload_hash(att)}
