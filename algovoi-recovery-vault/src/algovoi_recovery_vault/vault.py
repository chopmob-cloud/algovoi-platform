"""
Recovery Vault — an encrypted-at-rest repository for a client's archive keys, with threshold recovery.

The vault is a sealed, client-deployed key repository. It holds the client's archive keypairs
(ML-KEM for encryption, Falcon for signing) **encrypted at rest** under a key derived from an unlock
secret the client controls (env / KMS / TPM). On top it provides **threshold recovery**: the archive
master secret is Shamir-split (k-of-n) so a lost vault never means lost data.

Custody is honest by construction (inherited from the threshold engine):

- Default and when AlgoVoi access is **disabled**: every share is the client's; AlgoVoi holds nothing.
- When AlgoVoi access is **enabled**: AlgoVoi holds **one** sub-threshold share — inert on its own; it
  can be *contributed* to a break-glass recovery but can never decrypt or recover alone.

The client can flip access off at any time (``set_algovoi_access(False)``) and **re-split** existing
archives (``resplit``) to drop AlgoVoi's share entirely — full revocation.

On-disk format: ``MAGIC | salt(16) | AES-256-GCM(nonce|ct)`` where the AES key is
``scrypt(unlock_secret, salt)``. Nothing readable is stored in the clear except the salt.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from algovoi_doc_archive import recovery, signing
from algovoi_doc_archive.encryption import AesGcmEncryptor, HybridPqcEncryptor, generate_mlkem_keypair

_MAGIC = b"AVRV1\n"
_SALT_BYTES = 16
_SCRYPT = dict(n=2**14, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)

#: Default recovery policy applied when an archive is created with auto-split enabled.
DEFAULT_THRESHOLD_K = 2
DEFAULT_TOTAL_N = 3


class VaultError(RuntimeError):
    """Vault is locked with the wrong secret, not initialised, or an operation is invalid."""


def _derive(unlock_secret: bytes, salt: bytes) -> bytes:
    if not unlock_secret:
        raise VaultError("an unlock secret is required")
    return hashlib.scrypt(unlock_secret, salt=salt, **_SCRYPT)


@dataclass
class ArchiveRecord:
    name: str
    archive_pub_b64: str
    archive_sk_b64: str           # the ML-KEM master secret (held encrypted-at-rest in the vault)
    falcon_pub_b64: str | None
    falcon_sk_b64: str | None
    envelope: dict | None         # latest recovery envelope (non-secret), if split


class Vault:
    """Encrypted-at-rest key repository. Construct via :meth:`create` or :meth:`open`."""

    def __init__(self, path: str, key: bytes, salt: bytes, state: dict) -> None:
        self._path = path
        self._key = key
        self._salt = salt
        self._state = state

    # ---- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, path: str, unlock_secret: bytes) -> "Vault":
        if os.path.exists(path):
            raise VaultError(f"vault already exists at {path}")
        salt = os.urandom(_SALT_BYTES)
        state = {"version": 1, "config": {"algovoi_access": True}, "archives": {}}
        v = cls(path, _derive(unlock_secret, salt), salt, state)
        v._save()
        return v

    @classmethod
    def open(cls, path: str, unlock_secret: bytes) -> "Vault":
        if not os.path.exists(path):
            raise VaultError(f"no vault at {path}")
        with open(path, "rb") as fh:
            blob = fh.read()
        if blob[: len(_MAGIC)] != _MAGIC:
            raise VaultError("not a recovery-vault file")
        salt = blob[len(_MAGIC) : len(_MAGIC) + _SALT_BYTES]
        body = blob[len(_MAGIC) + _SALT_BYTES :]
        key = _derive(unlock_secret, salt)
        try:
            state = json.loads(AesGcmEncryptor(key).decrypt(body))
        except Exception as exc:
            raise VaultError("could not unlock vault (wrong secret or corrupt file)") from exc
        return cls(path, key, salt, state)

    def _save(self) -> None:
        body = AesGcmEncryptor(self._key).encrypt(json.dumps(self._state).encode("utf-8"))
        tmp = self._path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(_MAGIC + self._salt + body)
        os.replace(tmp, self._path)

    # ---- access control ----------------------------------------------------
    def algovoi_access_enabled(self) -> bool:
        return bool(self._state["config"].get("algovoi_access", True))

    def set_algovoi_access(self, enabled: bool) -> None:
        """Enable/disable AlgoVoi assist for FUTURE splits. Existing envelopes keep their embedded
        share until re-split — call :meth:`resplit` to revoke an existing archive's share."""
        self._state["config"]["algovoi_access"] = bool(enabled)
        self._save()

    # ---- archive keys ------------------------------------------------------
    def generate_archive(self, name: str, *, auto_split: bool = False,
                         threshold_k: int = DEFAULT_THRESHOLD_K, total_n: int = DEFAULT_TOTAL_N) -> dict:
        """Generate a fresh archive keypair set, store it, return the public keys.

        With ``auto_split=True`` the master key is immediately split (default 2-of-3) so the operator
        gets recovery shares in the same step — no separate call to remember. The split honours the
        vault's AlgoVoi-access setting (an AlgoVoi share is included only while access is enabled).
        """
        if name in self._state["archives"]:
            raise VaultError(f"archive {name!r} already exists")
        apk, ask = generate_mlkem_keypair()
        fpk, fsk = signing.generate_keypair()
        self._state["archives"][name] = ArchiveRecord(
            name=name,
            archive_pub_b64=signing.b64u_encode(apk),
            archive_sk_b64=signing.b64u_encode(ask),
            falcon_pub_b64=signing.b64u_encode(fpk),
            falcon_sk_b64=signing.b64u_encode(fsk),
            envelope=None,
        ).__dict__
        self._save()
        out = {"name": name, "archive_pub_b64": signing.b64u_encode(apk),
               "falcon_pub_b64": signing.b64u_encode(fpk)}
        if auto_split:
            env, shares = self.split(name, threshold_k=threshold_k, total_n=total_n)
            out["envelope"] = env
            out["shares"] = shares
        return out

    def import_archive(self, name: str, *, archive_pk: bytes, archive_sk: bytes,
                       falcon_pk: bytes | None = None, falcon_sk: bytes | None = None) -> None:
        if name in self._state["archives"]:
            raise VaultError(f"archive {name!r} already exists")
        self._state["archives"][name] = ArchiveRecord(
            name=name,
            archive_pub_b64=signing.b64u_encode(archive_pk),
            archive_sk_b64=signing.b64u_encode(archive_sk),
            falcon_pub_b64=signing.b64u_encode(falcon_pk) if falcon_pk else None,
            falcon_sk_b64=signing.b64u_encode(falcon_sk) if falcon_sk else None,
            envelope=None,
        ).__dict__
        self._save()

    def _record(self, name: str) -> dict:
        rec = self._state["archives"].get(name)
        if rec is None:
            raise VaultError(f"no archive {name!r} in this vault")
        return rec

    # ---- threshold recovery ------------------------------------------------
    def split(self, name: str, *, threshold_k: int, total_n: int,
              include_algovoi_support: bool | None = None) -> tuple[dict, list[str]]:
        """Split an archive master secret into a stored envelope + client shares.

        ``include_algovoi_support`` defaults to the vault's access setting; if access is disabled,
        an AlgoVoi share is never added even if explicitly requested.
        """
        rec = self._record(name)
        want_support = self.algovoi_access_enabled() if include_algovoi_support is None else include_algovoi_support
        if want_support and not self.algovoi_access_enabled():
            raise VaultError("AlgoVoi access is disabled for this vault; cannot add an AlgoVoi share")

        falcon_sk = signing.b64u_decode(rec["falcon_sk_b64"]) if rec.get("falcon_sk_b64") else None
        falcon_pk = signing.b64u_decode(rec["falcon_pub_b64"]) if rec.get("falcon_pub_b64") else None
        env, shares = recovery.split_recovery(
            master_secret=signing.b64u_decode(rec["archive_sk_b64"]),
            archive_public_key=signing.b64u_decode(rec["archive_pub_b64"]),
            threshold_k=threshold_k,
            total_n=total_n,
            include_algovoi_support=want_support,
            sign_secret_key=falcon_sk,
            sign_public_key=falcon_pk,
            note=f"vault:{name}",
        )
        rec["envelope"] = env
        self._save()
        return env, shares

    def resplit(self, name: str, *, threshold_k: int, total_n: int,
                include_algovoi_support: bool | None = None) -> tuple[dict, list[str]]:
        """Re-split with a fresh DEK + shares — invalidates all previous shares for this archive.

        Use to revoke AlgoVoi's share (call with ``include_algovoi_support=False`` or after disabling
        access) or to rotate custodians. Old shares no longer reconstruct anything."""
        return self.split(name, threshold_k=threshold_k, total_n=total_n,
                           include_algovoi_support=include_algovoi_support)

    def recover(self, name: str, *, shares: list[str]) -> dict:
        """Reconstruct an archive master secret from >= k shares and store it back into the vault."""
        rec = self._record(name)
        env = rec.get("envelope")
        if env is None:
            raise VaultError(f"archive {name!r} has no recovery envelope; nothing to recover from")
        verify_pk = signing.b64u_decode(rec["falcon_pub_b64"]) if rec.get("falcon_pub_b64") else None
        master = recovery.recover_from_shares(envelope=env, shares=shares, verify_public_key=verify_pk)
        rec["archive_sk_b64"] = signing.b64u_encode(master)
        self._save()
        return {"name": name, "recovered": True, "archive_pub_b64": rec["archive_pub_b64"]}

    def export_archive_secret(self, name: str) -> bytes:
        """Return the stored ML-KEM master secret (to hand to the Archive SDK to decrypt documents)."""
        return signing.b64u_decode(self._record(name)["archive_sk_b64"])

    # ---- generic protected keys (any Substrate PQC key, e.g. Falcon signing keys) ----------
    def _key_record(self, name: str) -> dict:
        rec = self._state.setdefault("keys", {}).get(name)
        if rec is None:
            raise VaultError(f"no protected key {name!r} in this vault")
        return rec

    def generate_signing_key(self, name: str, *, auto_split: bool = False,
                             threshold_k: int = DEFAULT_THRESHOLD_K, total_n: int = DEFAULT_TOTAL_N) -> dict:
        """Generate + store a Falcon-1024 signing keypair (for any Substrate PQC signing product)."""
        keys = self._state.setdefault("keys", {})
        if name in keys:
            raise VaultError(f"protected key {name!r} already exists")
        pk, sk = signing.generate_keypair()
        keys[name] = {"name": name, "kind": "signing-falcon",
                      "secret_b64": signing.b64u_encode(sk), "public_b64": signing.b64u_encode(pk),
                      "envelope": None}
        self._save()
        out = {"name": name, "kind": "signing-falcon", "public_b64": signing.b64u_encode(pk)}
        if auto_split:
            env, shares = self.split_key(name, threshold_k=threshold_k, total_n=total_n)
            out["envelope"], out["shares"] = env, shares
        return out

    def import_key(self, name: str, *, secret: bytes, kind: str = "generic", public_b64: str | None = None) -> None:
        """Store an externally-generated key (any bytes) for threshold recovery."""
        keys = self._state.setdefault("keys", {})
        if name in keys:
            raise VaultError(f"protected key {name!r} already exists")
        keys[name] = {"name": name, "kind": kind, "secret_b64": signing.b64u_encode(secret),
                      "public_b64": public_b64, "envelope": None}
        self._save()

    def split_key(self, name: str, *, threshold_k: int, total_n: int,
                  include_algovoi_support: bool | None = None) -> tuple[dict, list[str]]:
        """Generic threshold-split of a protected key (no archive sentinel)."""
        rec = self._key_record(name)
        want = self.algovoi_access_enabled() if include_algovoi_support is None else include_algovoi_support
        if want and not self.algovoi_access_enabled():
            raise VaultError("AlgoVoi access is disabled for this vault; cannot add an AlgoVoi share")
        env, shares = recovery.split_recovery(
            master_secret=signing.b64u_decode(rec["secret_b64"]),
            archive_public_key=None,                       # generic-secret mode
            threshold_k=threshold_k, total_n=total_n,
            include_algovoi_support=want, note=f"vault-key:{name}:{rec['kind']}",
        )
        rec["envelope"] = env
        self._save()
        return env, shares

    def recover_key(self, name: str, *, shares: list[str]) -> dict:
        """Reconstruct a protected key from >= k shares and store it back into the vault."""
        rec = self._key_record(name)
        env = rec.get("envelope")
        if env is None:
            raise VaultError(f"protected key {name!r} has no recovery envelope")
        secret = recovery.recover_from_shares(envelope=env, shares=shares)
        rec["secret_b64"] = signing.b64u_encode(secret)
        self._save()
        return {"name": name, "kind": rec["kind"], "recovered": True}

    def export_key(self, name: str) -> bytes:
        """Return a stored protected key's secret bytes."""
        return signing.b64u_decode(self._key_record(name)["secret_b64"])

    # ---- introspection -----------------------------------------------------
    def status(self) -> dict:
        archives = {}
        for name, rec in self._state["archives"].items():
            env = rec.get("envelope")
            archives[name] = {
                "has_envelope": env is not None,
                "threshold_k": (env or {}).get("threshold_k"),
                "total_n": (env or {}).get("total_n"),
                "support_assisted": bool((env or {}).get("support_assisted")),
            }
        keys = {}
        for name, rec in self._state.get("keys", {}).items():
            env = rec.get("envelope")
            keys[name] = {
                "kind": rec.get("kind"),
                "has_envelope": env is not None,
                "threshold_k": (env or {}).get("threshold_k"),
                "total_n": (env or {}).get("total_n"),
                "support_assisted": bool((env or {}).get("support_assisted")),
            }
        return {
            "version": self._state.get("version"),
            "algovoi_access": self.algovoi_access_enabled(),
            "archives": archives,
            "keys": keys,
        }

    def get_envelope(self, name: str) -> dict | None:
        return self._record(name).get("envelope")
