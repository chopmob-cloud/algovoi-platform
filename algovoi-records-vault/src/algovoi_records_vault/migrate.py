"""algovoi-records-vault — migration: bring existing records into the PQC Verifiable Archive.

Built entirely on ``algovoi_doc_archive.Archive`` — no crypto is reimplemented. Two modes:

  * ``"bridge"`` (hash-only): notarize a content hash of each existing record **without moving
    bytes**. The legacy store stays where it is; from that moment any change to a record is
    detectable (its hash no longer matches the notarized entry). This is the zero-disruption on-ramp.
  * ``"store"``: pull bytes, ML-KEM-encrypt, and store them in the archive (the legacy store can be
    decommissioned afterwards).

Migration is **idempotent / content-addressed**: re-running skips records whose hash is already in the
chain. ``reconcile`` + ``sign_manifest`` produce a Falcon-1024-signed, offline-verifiable manifest
proving the migrated set is complete and matches the source; ``detect_drift`` flags any bridged record
whose source bytes changed after notarisation.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Protocol

import substrate2

from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class SourceRecord:
    ref: str                                      # source-relative id (path / object key / row id)
    sha256: str                                   # "sha256:<hex>"
    data: bytes | None = None                     # required for "store" mode
    content_type: str = "application/octet-stream"
    metadata: dict = field(default_factory=dict)


class Source(Protocol):
    name: str
    def records(self) -> Iterable[SourceRecord]: ...


class FsSource:
    """Filesystem source: walk a directory tree, yield one record per file (deterministic order)."""

    def __init__(self, root: str, *, content_type: str = "application/octet-stream") -> None:
        self.root = root
        self.name = "fs:" + os.path.abspath(root).replace(os.sep, "/")
        self._ct = content_type

    def records(self) -> Iterable[SourceRecord]:
        for dirpath, _dirs, files in sorted(os.walk(self.root)):
            for fn in sorted(files):
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, self.root).replace(os.sep, "/")
                with open(p, "rb") as fh:
                    data = fh.read()
                yield SourceRecord(
                    ref=rel, sha256=_sha(data), data=data, content_type=self._ct,
                    metadata={"migrated_from": self.name, "ref": rel},
                )


@dataclass
class MigrationResult:
    source: str
    mode: str
    total: int = 0
    notarized: int = 0          # newly notarized this run
    skipped: int = 0            # already in the chain (idempotent re-run)
    entries: dict = field(default_factory=dict)   # sha256 -> seq
    started_at: str = ""
    finished_at: str = ""


async def _chain_index(archive: Archive) -> tuple[dict, dict]:
    """Return (sha256 -> seq, ref -> sha256) for every entry already in the chain."""
    by_hash: dict[str, int] = {}
    by_ref: dict[str, str] = {}
    for env in await archive.list_entries():
        payload, _sig, _kid = signing.open_envelope(env)
        by_hash[payload["doc_hash"]] = payload["seq"]
        ref = (payload.get("metadata") or {}).get("ref")
        if ref is not None:
            by_ref[ref] = payload["doc_hash"]
    return by_hash, by_ref


async def migrate(archive: Archive, source: Source, *, mode: str = "bridge",
                  skip_existing: bool = True) -> MigrationResult:
    """Migrate every record from ``source`` into ``archive``."""
    if mode not in ("bridge", "store"):
        raise ValueError("mode must be 'bridge' (hash-only) or 'store' (encrypt + store)")
    by_hash, _by_ref = await _chain_index(archive) if skip_existing else ({}, {})
    res = MigrationResult(source=source.name, mode=mode, started_at=_now(), entries=dict(by_hash))
    for rec in source.records():
        res.total += 1
        if skip_existing and rec.sha256 in by_hash:
            res.skipped += 1
            continue
        if mode == "store":
            if rec.data is None:
                raise ValueError(f"store mode needs bytes for {rec.ref!r}")
            entry = await archive.notarize(data=rec.data, title=rec.ref,
                                           content_type=rec.content_type, metadata=rec.metadata)
        else:
            entry = await archive.notarize(doc_hash=rec.sha256, title=rec.ref,
                                           content_type=rec.content_type, metadata=rec.metadata)
        by_hash[rec.sha256] = entry["seq"]
        res.entries[rec.sha256] = entry["seq"]
        res.notarized += 1
    res.finished_at = _now()
    return res


async def reconcile(archive: Archive, source: Source) -> dict:
    """Reconcile the source inventory against the chain. Returns an (unsigned) manifest dict."""
    by_hash, _by_ref = await _chain_index(archive)
    inventory: list[dict] = []
    missing: list[str] = []
    for rec in source.records():
        present = rec.sha256 in by_hash
        inventory.append({"ref": rec.ref, "sha256": rec.sha256,
                          "seq": by_hash.get(rec.sha256), "in_chain": present})
        if not present:
            missing.append(rec.ref)
    return {
        "type": "records_migration_manifest", "version": "1",
        "source": source.name,
        "total_source_records": len(inventory),
        "in_chain": len(inventory) - len(missing),
        "missing": missing,
        "complete": not missing,
        "inventory_sha256": "sha256:" + hashlib.sha256(substrate2.canonicalize_bytes(inventory)).hexdigest(),
        "generated_at": _now(),
    }


def sign_manifest(manifest: dict, secret_key: bytes, public_key: bytes) -> str:
    """Falcon-1024-signed, offline-verifiable migration manifest envelope."""
    from algovoi_doc_archive.signer import LocalSigner
    return sign_manifest_with(manifest, LocalSigner(public_key, secret_key))


def sign_manifest_with(manifest: dict, signer) -> str:
    """As :func:`sign_manifest`, signing through a pluggable Signer (HSM / KMS / Vault custody)."""
    return signing.make_envelope_with(manifest, signer)


def verify_manifest(manifest_envelope: str, public_key: bytes) -> bool:
    """Offline verification of a signed migration manifest (public key only)."""
    payload, sig, _kid = signing.open_envelope(manifest_envelope)
    return signing.verify_payload(payload, sig, public_key)


async def detect_drift(archive: Archive, source: Source) -> list[dict]:
    """Flag bridged records whose source bytes changed after notarisation, or that were never
    notarized. Uses the ``metadata.ref`` recorded at migration time."""
    by_hash, by_ref = await _chain_index(archive)
    drift: list[dict] = []
    for rec in source.records():
        if rec.ref in by_ref:
            if by_ref[rec.ref] != rec.sha256:
                drift.append({"ref": rec.ref, "issue": "source_changed_since_notarised",
                              "notarised": by_ref[rec.ref], "now": rec.sha256})
        elif rec.sha256 not in by_hash:
            drift.append({"ref": rec.ref, "issue": "never_notarised", "now": rec.sha256})
    return drift
