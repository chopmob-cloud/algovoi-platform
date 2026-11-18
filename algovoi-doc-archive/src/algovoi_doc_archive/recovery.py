"""
Key recovery — Shamir k-of-n threshold custody for an archive's ML-KEM master secret.

The archive's ML-KEM secret key is the single master key that decrypts every stored document. Lose
it and stored documents are unrecoverable. This module protects it with **threshold custody**:

  1. A random 32-byte data key (DEK) seals the master secret with AES-256-GCM.
  2. The DEK is Shamir-split (SLIP-39, the audited SatoshiLabs reference implementation) into ``n``
     shares with a recovery threshold of ``k``. Any ``k`` shares reconstruct the DEK; ``k-1`` shares
     reveal **nothing**.

Custody model — honest by construction:

- **Default is self-custody.** All ``n`` shares are returned to you; **AlgoVoi holds nothing**.
- **Support-assisted recovery is OPT-IN.** With ``include_algovoi_support=True`` AlgoVoi holds
  **exactly one** share (encrypted to its published recovery key and embedded in the envelope). **One
  share decrypts nothing** — it is mathematically inert below the threshold. AlgoVoi can *contribute*
  its share to a recovery ceremony on a verified request, but **cannot unilaterally recover or read
  your data**. You still hold ``n-1`` shares and choose the threshold.

The *envelope* (wrapped secret + parameters + sentinel) is **not secret** — it cannot be opened
without ``k`` shares — so it can be stored alongside the archive. It is optionally Falcon-1024 signed
so its parameters and the support-share fingerprint are tamper-evident. A recovered master secret is
always checked against a sentinel before use.

This recovery facility is included for every Substrate 2 archive user at no additional charge.
"""
from __future__ import annotations

import hashlib
import json
import os

import shamir_mnemonic as _slip39

from algovoi_doc_archive import signing
from algovoi_doc_archive.encryption import AesGcmEncryptor, HybridPqcEncryptor

ENVELOPE_VERSION = "algovoi-recovery-2"
SHARE_SCHEME = "SLIP-39"
_SENTINEL = b"algovoi-doc-archive/recovery-sentinel/v1"
_DEK_BYTES = 32

#: AlgoVoi's published support recovery **public** key (ML-KEM-1024, base64url). Used only when an
#: operator opts in. The matching secret is held offline / in an HSM by AlgoVoi and is never
#: distributed. Even with it, AlgoVoi holds only ONE Shamir share. Verify the fingerprint vs docs.
ALGOVOI_SUPPORT_RECOVERY_PUBKEY_B64 = "xoBUgKFApqdKvxs2kigPGjgnPwsv39YzaBAB_vxBd4IG98dFBbRA7iAeRyJYfsLBMgoHidp5DPMWVGQKYCR1omxVXJjIAKpEnnG6HGJtSPqiRqc83tah4csOyLkp53BSHrt7q8phI2ZkBHVhKvkmeKZHBXKaXUMgFeGn1ZlTMPrFVqRNE-VLLUUpuTqLilGUDAQF6ykfo3ex2dwWHyCwpvSlt-y2C9AjqgVp4SxsBCVCTAiqE4gCo0B2SBdEg_KdBLMIdvZeURxxsClKypyDHUNREhNBTwQ31PhJjrGtdtkAnPWW8zFikWNWucVM8Wl_9QYm4Vy7TNiXscSrYmmjCIwOmneuUXmC2EADkkwE_BpvclltKsRTaWWwc3mK_VfMXCiyzbl6-oeyHQY545JrYILOuaZnb2HDHJQnvtmaTFuLEtY-alMNP4x0uQdKkDwIQAG3xkJQBXoVzCCEKKMgaDp9NpA3etPPUqpWcFsn9uvOmKXEtSYFwgeHWLIDwtTBNGoM_cJjX2p5trd2TnQy5dsonsNaNgQXXHFU6UoxOTiXcTkdTbIhO9dw2kWFYnC92Vc_nKdOfCEin5KQ8nFLLCMaGzSqA7uYIXqawZA4c2Q5F9qxfZUw7jab8sFBBAMhq3lP7KHB5pWC6jMnaoRe3lGPj6sqcmK3_sW5H1KVmVx5SXGouhrOfeo_HWAiFNUR0pS2KDaG00aV4WVCt8ehjrhQxjWGKOCVrUwHKCgTfHExNZfNxSDPM3eRcdWePTUNdQolByiEgthhRNGwMttoe0EQUrawB1dgNOt6fUF9qUICvEdFKXtpIzUDR-B-DtMK1vK-y8sZuzEQ3Iib_HQ66ypZnjB-e3QkmSqfgnsTgBVcP0ZM9TstooazNItSbtFXyIyGXvo_Q-Qwssy03rXPA7Us2uK5n8Uj6aTL6CPEkQdSrvxwJtAorRNwUnGVIIYODgN_7yiJuAwLP0Kik1t86mJOhddolVOA_QdApvyf5cMayxw1x0S6DJnKEKNzK3qlDiPCp9kwfNdX1UBZiAo2bvHOy3Vx40KgqBjDsdYBHAslCDSsnRF6pQhTd2RMywmDBtgeyUpBfcWZibqP3nOu7eMG4cbJPJBAduOrEDQ62zaWgmC2gbdBdSJb-MVHanhMA2ZwZGaQQdaAIhvDXbg0WseEg8Ryf0V91zPCzXRk2GYAjQI-ZIwyi0MFv3g_4OR51JKgoMl5raiw13jP-eduaZq27roG2ugUo-cEhYkWs4xRSssLGKZzboNJAM14IyxqV8U6dQudizzM0hQDnQfEcHPDH7oVbTqke2Mj1fc9o4UsNFeDIBSbJuGjC4oZ9ODILNpxOJetpTczy-ye7gbKqhEocTO7ZhNdnwMwy5qCUAfO7CQ-p2wBTxs57bKWnnoSrGxEFNBC3AG_k0yxj8SbYNKF7AIp5Ro2ojdoP3myozKmezlakpmiuEdfHmAuuwsASzAL1jwf7cGUVec26_LNtAprBNJpGxBYJul2LkayPepv-HRfutO-LKV329tOP2lFX6ZQXvFebMMbBgcHjWI36lg26DmY8NgI6Tx4eMB07GMVGgYF5kiXGmabpFpcxlKGPlS1FDAEr-i3zMPNbKwxYsE_aPSo9fesY5KtzLOOr6Eh6xBzs_cBdNy4xXACfJfLy_u3QJZYc2tYVOAYMcc99pFJZIynUUOONyMHSFYD7vcHGMii3CJHxWfDy-NLprtrDJUq_ApW3hEShuU5kYRt2QTG_MJraKkVNJAxbDzIFLk1_OF1R4PJfGs10dOW3vGmmgxIN-e92mlxIOAWGpE18OiIn8S0q4Y3E-hakzU6YUyAE2kUn2mOz1yUB5A3ovktEdd1CFOmFRQwPlhmnGUmFtSOycSp3cJDNhOb06cCQRkqRnMJi1vJMJw2xOcO31MjvRp04IlQYToM1hyf5dCLAxheENeZVdO9anOKZXqPJnB2rwdAj_BLAKfHlYpQGCI56kCUMUeovZthwdxA13tYz9LAkWiRr5SCLcQk-oGdHYu5_HIawfyykKUrPZLJFJYTALNRx-s3WyIWKyGxNeWGj88jxgXfV-yQ5Rda3tepkD0"

#: Publish/verify this against the docs before opting in to support-assisted recovery.
ALGOVOI_SUPPORT_RECOVERY_FINGERPRINT = "c8655d786306af53"


class RecoveryError(RuntimeError):
    """Malformed envelope, signature-invalid, insufficient/invalid shares, or sentinel mismatch."""


def fingerprint(public_key: bytes) -> str:
    """Short, stable fingerprint of an ML-KEM public key (sha256 hex, first 16 chars)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def _support_pubkey() -> bytes:
    b64 = os.environ.get("ALGOVOI_SUPPORT_RECOVERY_PUBKEY_B64", ALGOVOI_SUPPORT_RECOVERY_PUBKEY_B64)
    if not b64:
        raise RecoveryError("AlgoVoi support recovery public key is not configured")
    return signing.b64u_decode(b64)


def _canon(env: dict) -> bytes:
    body = {k: v for k, v in env.items() if k != "signature_b64"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def split_recovery(
    *,
    master_secret: bytes,
    archive_public_key: bytes | None = None,
    threshold_k: int,
    total_n: int,
    include_algovoi_support: bool = False,
    sign_secret_key: bytes | None = None,
    sign_public_key: bytes | None = None,
    note: str = "",
) -> tuple[dict, list[str]]:
    """Split the master secret into a (non-secret) recovery *envelope* + ``n`` SLIP-39 *shares*.

    Returns ``(envelope, client_shares)``. With ``include_algovoi_support=True``, exactly **one** of
    the ``n`` shares is encrypted to AlgoVoi's support key and embedded in the envelope, and only the
    remaining ``n-1`` shares are returned to you (the client). Any ``threshold_k`` shares — yours
    alone, or yours plus AlgoVoi's contributed one — reconstruct the key.
    """
    if not master_secret:
        raise RecoveryError("master_secret is required")
    if total_n < 2:
        raise RecoveryError("total_n must be >= 2")
    if not (2 <= threshold_k <= total_n):
        raise RecoveryError("require 2 <= threshold_k <= total_n (a 1-of-n threshold is no protection)")
    if include_algovoi_support and total_n - 1 < 1:
        raise RecoveryError("total_n must be >= 2 when AlgoVoi holds a share")

    # 1) DEK seals the master secret (AES-256-GCM).
    dek = os.urandom(_DEK_BYTES)
    wrapped_secret = AesGcmEncryptor(dek).encrypt(master_secret)

    # 2) Shamir-split the DEK (SLIP-39, one group, k-of-n).
    shares = _slip39.generate_mnemonics(
        group_threshold=1, groups=[(threshold_k, total_n)], master_secret=dek
    )[0]

    env: dict = {
        "version": ENVELOPE_VERSION,
        "scheme": SHARE_SCHEME,
        "dek_alg": AesGcmEncryptor.alg,
        "threshold_k": threshold_k,
        "total_n": total_n,
        "wrapped_secret_b64": signing.b64u_encode(wrapped_secret),
        "support_assisted": False,
        "note": note,
    }
    if archive_public_key is not None:
        # Archive-encryption-key mode: a sentinel sealed to the archive public key additionally proves
        # a recovered key is the genuine archive key (it decrypt-pairs with archive_public_key).
        env["kind"] = "archive-encryption-key"
        env["archive_enc_alg"] = HybridPqcEncryptor.alg
        env["archive_public_key_b64"] = signing.b64u_encode(archive_public_key)
        env["sentinel_b64"] = signing.b64u_encode(HybridPqcEncryptor(archive_public_key).encrypt(_SENTINEL))
    else:
        # Generic-secret mode: recover ANY key (e.g. a Falcon signing key). AES-256-GCM's auth tag
        # already guarantees the recovered secret is the original — a wrong DEK fails to decrypt — so
        # no extra sentinel is needed.
        env["kind"] = "generic-secret"

    client_shares = list(shares)
    if include_algovoi_support:
        algovoi_share = client_shares.pop()  # AlgoVoi holds exactly one share
        wrapped_share = HybridPqcEncryptor(_support_pubkey()).encrypt(algovoi_share.encode("utf-8"))
        env["support_assisted"] = True
        env["algovoi_support_share"] = {
            "fingerprint": fingerprint(_support_pubkey()),
            "wrapped_b64": signing.b64u_encode(wrapped_share),
        }
        env["client_share_count"] = len(client_shares)

    if sign_secret_key is not None and sign_public_key is not None:
        env["signer_kid"] = signing.kid_for(sign_public_key)
        env["signature_b64"] = signing.b64u_encode(signing.sign_bytes(sign_secret_key, _canon(env)))

    return env, client_shares


def verify_envelope(env: dict, public_key: bytes) -> bool:
    """True if the envelope carries a valid Falcon signature from ``public_key``."""
    sig_b64 = env.get("signature_b64")
    if not sig_b64:
        return False
    return signing.verify_bytes(public_key, _canon(env), signing.b64u_decode(sig_b64))


def algovoi_share_mnemonic(env: dict, support_secret_key: bytes) -> str:
    """AlgoVoi-side: unwrap AlgoVoi's single share with the offline support secret, to contribute it.

    Returns one SLIP-39 mnemonic. On its own it is below threshold and recovers nothing; it must be
    combined with the client's shares to reach ``threshold_k``.
    """
    share = env.get("algovoi_support_share")
    if not share:
        raise RecoveryError("this envelope has no AlgoVoi support share (self-custody only)")
    try:
        raw = HybridPqcEncryptor(b"", support_secret_key).decrypt(signing.b64u_decode(share["wrapped_b64"]))
    except Exception as exc:
        raise RecoveryError("could not unwrap AlgoVoi share (wrong key or tampered envelope)") from exc
    return raw.decode("utf-8")


def recover_from_shares(
    *,
    envelope: dict,
    shares: list[str],
    verify_public_key: bytes | None = None,
) -> bytes:
    """Reconstruct the archive master secret from ``threshold_k`` SLIP-39 shares.

    ``shares`` may be any mix of client shares and (if opted in) AlgoVoi's contributed share. If
    ``verify_public_key`` is given the envelope signature is checked first; the recovered key is
    always validated against the sentinel before return.
    """
    if verify_public_key is not None and not verify_envelope(envelope, verify_public_key):
        raise RecoveryError("envelope signature did not verify")
    if len(shares) < int(envelope.get("threshold_k", 0)):
        raise RecoveryError(
            f"need at least {envelope.get('threshold_k')} shares, got {len(shares)}"
        )
    try:
        dek = _slip39.combine_mnemonics(shares)
    except Exception as exc:
        # don't surface SLIP-39 library internals in the message; the cause is chained for logs
        raise RecoveryError("could not combine recovery shares (invalid, mismatched, or insufficient)") from exc

    try:
        master = AesGcmEncryptor(dek).decrypt(signing.b64u_decode(envelope["wrapped_secret_b64"]))
    except Exception as exc:
        raise RecoveryError("could not unwrap master secret with the reconstructed DEK") from exc

    # Archive-encryption-key mode adds an ML-KEM sentinel check; generic-secret mode relies on the
    # AES-GCM auth tag above (a wrong DEK would already have failed to decrypt).
    if "archive_public_key_b64" in envelope:
        archive_pk = signing.b64u_decode(envelope["archive_public_key_b64"])
        try:
            check = HybridPqcEncryptor(archive_pk, master).decrypt(signing.b64u_decode(envelope["sentinel_b64"]))
        except Exception as exc:
            raise RecoveryError("recovered key failed the sentinel check") from exc
        if check != _SENTINEL:
            raise RecoveryError("recovered key failed the sentinel check")
    return master


def restore_encryptor(envelope: dict, master_secret: bytes) -> HybridPqcEncryptor:
    """Rebuild a decrypt-capable encryptor for the archive from a recovered master secret.

    Only valid for archive-encryption-key envelopes; generic-secret envelopes carry no archive key.
    """
    pk_b64 = envelope.get("archive_public_key_b64")
    if not pk_b64:
        raise RecoveryError("restore_encryptor is only valid for an archive-encryption-key envelope")
    return HybridPqcEncryptor(signing.b64u_decode(pk_b64), master_secret)
