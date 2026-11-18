"""Recovery Vault to Compliance Command Center evidence export (bolt-in adapter).

Emits the vault's custody posture as a signed, hash-linked chain in the common
evidence-pack format the Compliance Command Center ingests offline. This is the
bolt-in: Recovery Vault becomes one more verified stream in the hub, alongside
Records Vault and the rest, with no change to the console.

Each archive and each protected key in the vault becomes one custody-attestation
entry: what is under threshold protection, at what k-of-n, whether an AlgoVoi
support share is present, and whether a recovery envelope exists. The entries are
hash-linked and Falcon-1024 signed, so the chain is tamper-evident and verifiable
offline with only ``pqcrypto`` and ``rfc8785`` and the published public key.

The output is a directory with ``recovery_custody_chain.json`` and
``public_key.b64``. Drop it into the console's watched ingest directory, or hand
it to an auditor with the standalone verifier.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone

import substrate2

from algovoi_doc_archive import signing

ENTRY_TYPE = "recovery_vault_custody"
MANIFEST_TYPE = "recovery_vault_custody_manifest"
CHAIN_FILE = "recovery_custody_chain.json"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _payload_hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(substrate2.canonicalize_bytes(payload)).hexdigest()


def _envelope(payload: dict, secret_key: bytes, kid: str) -> str:
    sig = signing.sign_bytes(secret_key, substrate2.canonicalize_bytes(payload))
    return _b64u(json.dumps({"payload": payload, "sig": _b64u(sig), "kid": kid}).encode())


def _open_envelope(env_b64: str) -> tuple[dict, bytes]:
    obj = json.loads(_b64u_dec(env_b64))
    return obj["payload"], _b64u_dec(obj["sig"])


def _custody_entries(status: dict) -> list[dict]:
    """Flatten the vault status into one custody record per protected subject."""
    entries: list[dict] = []
    for name in sorted(status.get("archives", {})):
        a = status["archives"][name]
        entries.append({"subject": name, "subject_kind": "archive",
                        "threshold_k": a.get("threshold_k"), "total_n": a.get("total_n"),
                        "support_assisted": a.get("support_assisted"),
                        "has_envelope": a.get("has_envelope")})
    for name in sorted(status.get("keys", {})):
        k = status["keys"][name]
        entries.append({"subject": name, "subject_kind": k.get("kind"),
                        "threshold_k": k.get("threshold_k"), "total_n": k.get("total_n"),
                        "support_assisted": k.get("support_assisted"),
                        "has_envelope": k.get("has_envelope")})
    return entries


def export_evidence_pack(vault, out_dir: str, *, public_key: bytes | None = None,
                         secret_key: bytes | None = None,
                         attested_at: str | None = None,
                         allow_ephemeral: bool = False) -> str:
    """Write a Command Center ingestable evidence pack attesting this vault's
    custody posture. Returns the pack directory.

    SECURITY (2026-08-19): a dedicated STABLE evidence-signing identity must be supplied
    (``public_key`` + ``secret_key``) — the pack is verified against its own embedded
    ``public_key.b64``, so a fresh per-export key makes it self-vouching with no trust anchor
    (an attacker who can write the ingest dir mints a key and fabricates any posture). Minting an
    ephemeral key now requires an explicit ``allow_ephemeral=True`` (tests/dev only). The pack also
    carries a SIGNED MANIFEST pinning the entry count + head hash, so a dropped trailing entry (e.g. a
    disappeared legal-hold custody record) is detectable; verify with :func:`verify_evidence_pack`
    and pin the expected kid.
    """
    if public_key is None or secret_key is None:
        if not allow_ephemeral:
            raise ValueError(
                "export_evidence_pack requires a stable public_key + secret_key (the published "
                "evidence-signing identity). Pass allow_ephemeral=True only for tests/dev — an ephemeral "
                "key makes the pack self-vouching with no trust anchor.")
        public_key, secret_key = signing.generate_keypair()
        if len(public_key) != signing.PUBLIC_KEY_BYTES:
            public_key, secret_key = secret_key, public_key
    kid = signing.kid_for(public_key)
    attested_at = attested_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    status = vault.status()
    os.makedirs(out_dir, exist_ok=True)

    chain: list[str] = []
    prev: str | None = None
    count = 0
    for i, entry in enumerate(_custody_entries(status)):
        payload = {"type": ENTRY_TYPE, "seq": i, "prev_entry_hash": prev,
                   "algovoi_access": status.get("algovoi_access"),
                   "attested_at": attested_at, **entry}
        chain.append(_envelope(payload, secret_key, kid))
        prev = _payload_hash(payload)
        count += 1
    # Signed manifest trailer: pins the entry count and head hash so truncation is detectable.
    manifest = {"type": MANIFEST_TYPE, "entry_count": count, "head_entry_hash": prev,
                "attested_at": attested_at}
    chain.append(_envelope(manifest, secret_key, kid))

    with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
        json.dump(chain, fh)
    with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(public_key).decode())
    return out_dir


def verify_evidence_pack(pack_dir: str, *, expected_kid: str | None = None) -> dict:
    """Verify a recovery-vault evidence pack offline. Returns {valid, reason, entry_count, kid}.

    Checks every entry's Falcon signature, seq contiguity + prev-hash links, and the SIGNED MANIFEST
    trailer whose ``entry_count``/``head_entry_hash`` pin the chain against truncation. Pass
    ``expected_kid`` (the auditor's published evidence kid) to ANCHOR trust — without it the pack only
    proves internal self-consistency, not who signed it.
    """
    try:
        pk = base64.b64decode(open(os.path.join(pack_dir, "public_key.b64"), encoding="utf-8").read())
        chain = json.load(open(os.path.join(pack_dir, CHAIN_FILE), encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"valid": False, "reason": f"unreadable_pack: {exc}", "entry_count": 0, "kid": None}
    kid = signing.kid_for(pk)
    if expected_kid is not None and kid != expected_kid:
        return {"valid": False, "reason": "kid_not_anchored", "entry_count": 0, "kid": kid}
    if not chain:
        return {"valid": False, "reason": "empty_pack", "entry_count": 0, "kid": kid}
    prev: str | None = None
    for i, env in enumerate(chain[:-1]):   # all but the manifest trailer
        try:
            payload, sig = _open_envelope(env)
        except Exception:  # noqa: BLE001
            return {"valid": False, "reason": f"malformed_entry@{i}", "entry_count": i, "kid": kid}
        if payload.get("type") != ENTRY_TYPE:
            return {"valid": False, "reason": f"wrong_type@{i}", "entry_count": i, "kid": kid}
        if not signing.verify_bytes(pk, substrate2.canonicalize_bytes(payload), sig):
            return {"valid": False, "reason": f"bad_signature@{i}", "entry_count": i, "kid": kid}
        if payload.get("seq") != i or payload.get("prev_entry_hash") != prev:
            return {"valid": False, "reason": f"chain_break@{i}", "entry_count": i, "kid": kid}
        prev = _payload_hash(payload)
    # Manifest trailer: pins count + head.
    try:
        m_payload, m_sig = _open_envelope(chain[-1])
    except Exception:  # noqa: BLE001
        return {"valid": False, "reason": "malformed_manifest", "entry_count": len(chain) - 1, "kid": kid}
    if m_payload.get("type") != MANIFEST_TYPE:
        return {"valid": False, "reason": "missing_manifest", "entry_count": len(chain) - 1, "kid": kid}
    if not signing.verify_bytes(pk, substrate2.canonicalize_bytes(m_payload), m_sig):
        return {"valid": False, "reason": "bad_manifest_signature", "entry_count": len(chain) - 1, "kid": kid}
    n = len(chain) - 1
    if int(m_payload.get("entry_count", -1)) != n or m_payload.get("head_entry_hash") != prev:
        return {"valid": False, "reason": "manifest_mismatch_truncated", "entry_count": n, "kid": kid}
    return {"valid": True, "reason": None, "entry_count": n, "kid": kid}
