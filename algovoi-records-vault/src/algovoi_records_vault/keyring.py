"""F7 — key archival + rotation proof (the 30-year, post-quantum-longevity story).

Records kept for decades outlive the keys that signed them. To stay verifiable across key rotations you
need a **provable, unbroken chain of custody between keys**: each rotation is a *cross-signed* proof —
the **old** key signs the binding ``old → new`` (authorising the successor) and the **new** key
counter-signs (accepting). Anyone holding only the original published public key can then walk the chain
forward and confirm every historical key was legitimately succeeded, with no trusted third party.

A ``keyring/`` :class:`_VaultStream` records two kinds of signed entry — ``key_record`` (kid, alg,
pubkey, validity window) and ``key_rotation_proof`` (the dual-signed binding). :func:`published_keys`
emits the ``/.well-known/pqc-keys.json`` structure (all historical keys + validity windows) a verifier
fetches once. Everything is Falcon-1024 + RFC 8785 — no new crypto.
"""
from __future__ import annotations

from datetime import datetime, timezone

import substrate2

from algovoi_doc_archive import signing

from algovoi_records_vault.vault import _VaultStream


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return _iso(datetime.now(timezone.utc).replace(microsecond=0))


_BINDING_KEYS = ("old_kid", "new_kid", "old_pubkey_b64", "new_pubkey_b64", "rotated_at")


def _binding(old_pk: bytes, new_pk: bytes, rotated_at: str) -> dict:
    return {
        "old_kid": signing.kid_for(old_pk),
        "new_kid": signing.kid_for(new_pk),
        "old_pubkey_b64": signing.public_key_b64(old_pk),
        "new_pubkey_b64": signing.public_key_b64(new_pk),
        "rotated_at": rotated_at,
    }


def make_rotation_proof(*, old_public_key: bytes, old_secret_key: bytes,
                        new_public_key: bytes, new_secret_key: bytes,
                        rotated_at: str | None = None) -> dict:
    """Dual-signed continuity proof: old key authorises new, new key counter-signs (both Falcon-1024)."""
    b = _binding(old_public_key, new_public_key, rotated_at or _now())
    msg = substrate2.canonicalize_bytes(b)
    return {
        **b,
        "old_sig": signing.b64u_encode(signing.sign_bytes(old_secret_key, msg)),
        "new_sig": signing.b64u_encode(signing.sign_bytes(new_secret_key, msg)),
    }


def verify_rotation_proof(proof: dict) -> bool:
    """Offline: both signatures valid AND each kid matches its embedded public key. Never raises."""
    try:
        b = {k: proof[k] for k in _BINDING_KEYS}
        msg = substrate2.canonicalize_bytes(b)
        old_pk = signing.load_key_b64(proof["old_pubkey_b64"])
        new_pk = signing.load_key_b64(proof["new_pubkey_b64"])
        if signing.kid_for(old_pk) != proof["old_kid"] or signing.kid_for(new_pk) != proof["new_kid"]:
            return False
        return (signing.verify_bytes(old_pk, msg, signing.b64u_decode(proof["old_sig"]))
                and signing.verify_bytes(new_pk, msg, signing.b64u_decode(proof["new_sig"])))
    except Exception:  # noqa: BLE001
        return False


def verify_key_chain(proofs: list[dict]) -> tuple[bool, str]:
    """Verify an ordered list of rotation proofs forms an unbroken old→new chain. Returns (ok, detail)."""
    prev_new: str | None = None
    for i, p in enumerate(proofs):
        if not verify_rotation_proof(p):
            return False, f"bad_proof@{i}"
        if prev_new is not None and p["old_kid"] != prev_new:
            return False, f"chain_break@{i} (expected old_kid={prev_new}, got {p['old_kid']})"
        prev_new = p["new_kid"]
    return True, f"{len(proofs)} rotations verified, current_kid={prev_new}"


class Keyring:
    """Signed ``keyring/`` stream of key records + cross-signed rotation proofs."""

    def __init__(self, *, stream: _VaultStream) -> None:
        self._stream = stream

    async def register_key(self, *, public_key: bytes, alg: str = "Falcon-1024",
                           valid_from: str | None = None, valid_to: str | None = None,
                           role: str = "signing") -> dict:
        """Record a key (typically the genesis/active identity key) with its validity window."""
        fields = {
            "key_event": "register", "key_kid": signing.kid_for(public_key), "alg": alg, "role": role,
            "pubkey_b64": signing.public_key_b64(public_key),
            "valid_from": valid_from or _now(), "valid_to": valid_to, "status": "active",
        }
        return await self._stream.append(fields)

    async def rotate(self, *, old_public_key: bytes, old_secret_key: bytes,
                     new_public_key: bytes, new_secret_key: bytes,
                     new_valid_to: str | None = None, rotated_at: str | None = None) -> dict:
        """Append a cross-signed rotation proof binding the old key to its successor."""
        proof = make_rotation_proof(old_public_key=old_public_key, old_secret_key=old_secret_key,
                                    new_public_key=new_public_key, new_secret_key=new_secret_key,
                                    rotated_at=rotated_at)
        fields = {"key_event": "rotate", "alg": "Falcon-1024", "new_valid_to": new_valid_to, **proof}
        return await self._stream.append(fields)

    async def _payloads(self) -> list[dict]:
        return await self._stream.list_payloads()

    async def rotation_proofs(self) -> list[dict]:
        return [p for p in await self._payloads() if p.get("key_event") == "rotate"]

    async def verify_key_chain(self) -> tuple[bool, str]:
        """Verify the signed chain, then the unbroken old→new rotation continuity.

        The signed ``keyring/`` chain is verified first, so a removed or reordered rotation entry is
        caught even when the surviving proofs are individually valid (parity with the other verifiers).
        """
        chain = await self._stream.verify_chain()
        if not chain.valid:
            return False, f"keyring chain failed verification: {chain.reason} (broken_at={chain.broken_at})"
        return verify_key_chain(await self.rotation_proofs())

    async def historical_kids(self) -> list[str]:
        """Every kid the keyring has ever bound, oldest→newest (genesis + each rotation target)."""
        kids: list[str] = []
        for p in await self._payloads():
            if p.get("key_event") == "register":
                if p["key_kid"] not in kids:
                    kids.append(p["key_kid"])
            elif p.get("key_event") == "rotate":
                for k in (p["old_kid"], p["new_kid"]):
                    if k not in kids:
                        kids.append(k)
        return kids

    async def published_keys(self, *, issuer_did: str | None = None) -> dict:
        """The ``/.well-known/pqc-keys.json`` document: all historical keys + validity windows.

        A verifier fetches this once and can then check any decades-old receipt against the key that was
        valid when it was signed, and confirm that key's lineage via the rotation proofs.
        """
        keys: dict[str, dict] = {}
        proofs: list[dict] = []
        for p in await self._payloads():
            if p.get("key_event") == "register":
                keys[p["key_kid"]] = {"kid": p["key_kid"], "alg": p["alg"], "pubkey_b64": p["pubkey_b64"],
                                      "valid_from": p.get("valid_from"), "valid_to": p.get("valid_to"),
                                      "role": p.get("role", "signing"), "status": p.get("status", "active")}
            elif p.get("key_event") == "rotate":
                # the old key's validity closes at rotation; the new key opens
                if p["old_kid"] in keys and keys[p["old_kid"]].get("valid_to") is None:
                    keys[p["old_kid"]]["valid_to"] = p["rotated_at"]
                    keys[p["old_kid"]]["status"] = "retired"
                keys.setdefault(p["new_kid"], {
                    "kid": p["new_kid"], "alg": p.get("alg", "Falcon-1024"),
                    "pubkey_b64": p["new_pubkey_b64"], "valid_from": p["rotated_at"],
                    "valid_to": p.get("new_valid_to"), "role": "signing", "status": "active"})
                proofs.append({k: p[k] for k in (*_BINDING_KEYS, "old_sig", "new_sig")})
        return {
            "type": "pqc_key_set", "version": "1",
            "issuer_did": issuer_did or self._stream.issuer_did,
            "alg": "Falcon-1024",
            "keys": list(keys.values()),
            "rotation_proofs": proofs,
        }

    async def verify_chain(self):
        """Whole ``keyring/`` stream integrity (the signed-entry chain), offline."""
        return await self._stream.verify_chain()
