"""Ingest + verify engine for the Compliance Command Center.

Ingests exported AlgoVoi evidence packs and re-verifies every signed chain **offline** via the
substrate2 crypto core (Falcon-1024 over RFC 8785 JCS bytes, i.e. ``pqcrypto`` + ``rfc8785``
underneath), using only the public key from the pack and no AlgoVoi service. The command center
never trusts the producer; it recomputes every signature and hash-link. (The standalone
verifiers handed to external auditors keep their own minimal ``pqcrypto`` + ``rfc8785`` trust base.)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field

import substrate2
from substrate2.pqc import verify_falcon_1024 as _falcon_verify


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _jcs(payload) -> bytes:
    return substrate2.canonicalize_bytes(payload)


def _payload_hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(_jcs(payload)).hexdigest()


def _kid(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:16]


def _open_envelope(env_b64: str):
    env = json.loads(_b64u(env_b64.strip()))
    return env["payload"], _b64u(env["sig"]), env.get("kid", "")


def _falcon_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(_falcon_verify(pk, msg, sig))
    except Exception:  # noqa: BLE001
        return False


@dataclass
class ChainResult:
    """Verification result for one signed chain in a pack."""
    name: str
    entry_type: str | None
    entries: int
    verified: bool
    head: str | None
    reason: str
    payloads: list[dict] = field(default_factory=list)


@dataclass
class PackResult:
    """Verification result for one evidence pack (a directory)."""
    pack: str
    kid: str
    public_key_bytes: int
    chains: list[ChainResult]
    timestamp_binding: bool | None  # None = not applicable (no archive+tsa pair)

    @property
    def verified(self) -> bool:
        ok = all(c.verified for c in self.chains)
        return ok and (self.timestamp_binding is not False)


def verify_chain(envelopes: list[str], public_key: bytes) -> ChainResult:
    """Verify a signed, hash-linked chain (offline). Type + prev-hash field auto-detected."""
    prev = None
    etype = None
    payloads: list[dict] = []
    for i, e in enumerate(envelopes):
        try:
            payload, sig, _ = _open_envelope(e)
        except Exception:  # noqa: BLE001
            return ChainResult("", etype, i, False, prev, f"malformed_entry@{i}", payloads)
        t = payload.get("type")
        if etype is None:
            etype = t
        elif t != etype:
            return ChainResult("", etype, i, False, prev, f"type_changed@{i}", payloads)
        if not _falcon_ok(public_key, _jcs(payload), sig):
            return ChainResult("", etype, i, False, prev, f"bad_signature@{i}", payloads)
        if payload.get("seq") != i:
            return ChainResult("", etype, i, False, prev, f"seq_mismatch@{i}", payloads)
        prev_field = "prev_receipt_hash" if "prev_receipt_hash" in payload else "prev_entry_hash"
        if payload.get(prev_field) != prev:
            return ChainResult("", etype, i, False, prev, f"chain_break@{i}", payloads)
        prev = _payload_hash(payload)
        payloads.append(payload)
    return ChainResult("", etype, len(envelopes), True, prev, "ok", payloads)


def verify_chain_cached(envelopes: list[str], public_key: bytes, cache) -> ChainResult:
    """verify_chain with a content-hash cache: an unchanged chain that previously
    verified is trusted without re-running the Falcon checks. The chain is
    append-only and hash-linked, so identical content cannot have changed; a grown
    chain has new content and re-verifies. Cache is any object with
    ``verified_seen(sha)`` / ``verified_add(sha)`` (the store)."""
    # SECURITY (2026-08-19): the cache key MUST include the verifying public key. Keying on the envelope
    # bytes alone let a chain that verified under key A return "verified (cached)" when re-presented with a
    # different key B, skipping the Falcon re-check (issuer misattribution / signature re-check bypass).
    # Binding the public key means a different key is a different cache entry and re-verifies from scratch.
    _kh = hashlib.sha256()
    _kh.update(b"cc-cache-v2\x00")
    _kh.update(public_key)
    _kh.update(b"\x00")
    _kh.update("".join(envelopes).encode())
    key = _kh.hexdigest()
    if cache is not None and cache.verified_seen(key):
        payloads = []
        for e in envelopes:
            try:
                payloads.append(_open_envelope(e)[0])
            except Exception:  # noqa: BLE001
                return verify_chain(envelopes, public_key)
        etype = payloads[0].get("type") if payloads else None
        head = _payload_hash(payloads[-1]) if payloads else None
        return ChainResult("", etype, len(envelopes), True, head, "ok (cached)", payloads)
    res = verify_chain(envelopes, public_key)
    if cache is not None and res.verified:
        cache.verified_add(key)
    return res


def verify_pack(pack_dir: str, cache=None) -> PackResult:
    """Verify every ``*_chain.json`` in an evidence pack against its embedded ``public_key.b64``."""
    with open(os.path.join(pack_dir, "public_key.b64"), encoding="utf-8") as fh:
        pk = base64.b64decode(fh.read().strip())

    def load(name: str):
        with open(os.path.join(pack_dir, name), encoding="utf-8") as fh:
            return json.load(fh)

    chain_files = sorted(f for f in os.listdir(pack_dir) if f.endswith("_chain.json"))
    chains: list[ChainResult] = []
    by_name: dict[str, ChainResult] = {}
    for fn in chain_files:
        res = verify_chain_cached(load(fn), pk, cache) if cache is not None else verify_chain(load(fn), pk)
        res.name = fn[:-len("_chain.json")]
        chains.append(res)
        by_name[fn] = res

    # timestamp binding: every tsa.message_imprint == hash(its archive receipt)
    binding: bool | None = None
    if "archive_chain.json" in by_name and "tsa_chain.json" in by_name:
        binding = True
        arch = by_name["archive_chain.json"].payloads
        for tp in by_name["tsa_chain.json"].payloads:
            aseq = tp.get("archive_seq")
            want = _payload_hash(arch[aseq]) if isinstance(aseq, int) and aseq < len(arch) else None
            if tp.get("message_imprint") != want:
                binding = False

    return PackResult(os.path.basename(pack_dir.rstrip("/\\")) or pack_dir, _kid(pk), len(pk), chains, binding)


def ingest(ingest_dir: str, cache=None) -> list[PackResult]:
    """Verify every evidence pack found under ``ingest_dir`` (a dir with ``public_key.b64`` + chains)."""
    results: list[PackResult] = []
    if _is_pack(ingest_dir):
        return [verify_pack(ingest_dir, cache)]
    for name in sorted(os.listdir(ingest_dir)):
        sub = os.path.join(ingest_dir, name)
        if os.path.isdir(sub) and _is_pack(sub):
            results.append(verify_pack(sub, cache))
    return results


def _is_pack(d: str) -> bool:
    return os.path.isdir(d) and os.path.exists(os.path.join(d, "public_key.b64")) and \
        any(f.endswith("_chain.json") for f in os.listdir(d))
