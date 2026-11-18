"""Switchable volume importer for the AlgoVoi Records Vault.

One entry point, two signing strategies, chosen per import:

  * ``strategy="falcon"`` - one Falcon-1024 signature **per document**. Maximum granularity and
    independence: every record is its own signed archive entry, revocable and provable on its own. This
    is the base per-document ``migrate`` path. Throughput is bounded by signing (~one sign per doc).
  * ``strategy="merkle"`` - one Falcon-1024 signature **per batch**. A batch of documents is folded into
    a SHA-256 Merkle root and only that root is signed, so throughput is bounded by hashing and IO, not
    signing (measured ~300x faster at batch=1000). Each document keeps an offline inclusion proof against
    the signed batch root.

Both modes support ``bridge`` (hash-only, no bytes moved) and ``store`` (encrypt + store). The importer
is idempotent/resumable, streams the source at constant memory, and can hash the filesystem in parallel.

Commercial add-on to Records Vault: runtime-licensed, fail-closed.
"""
from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

from algovoi_doc_archive import signing
from algovoi_records_vault.migrate import SourceRecord, _sha
from algovoi_records_vault.migrate import migrate as _falcon_migrate

from algovoi_records_vault_importer import licensing, merkle

STRATEGIES = ("merkle", "falcon")
BATCH_CONTENT_TYPE = "application/vnd.algovoi.records-batch"
BATCH_ALG = "sha256-merkle/v1"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ImportResult:
    strategy: str
    source: str
    mode: str
    total: int = 0
    committed: int = 0
    skipped: int = 0
    batches: int = 0
    signatures: int = 0
    started_at: str = ""
    finished_at: str = ""
    docs_per_sec: float = 0.0
    batch_seqs: list[int] = field(default_factory=list)


# ---- merkle (batch) strategy -----------------------------------------------------------------------

async def _committed_refs(archive) -> set[str]:
    seen: set[str] = set()
    for env in await archive.list_entries():
        payload, _sig, _kid = signing.open_envelope(env)
        meta = payload.get("metadata") or {}
        if meta.get("kind") == "records_batch":
            for r in meta.get("refs", []):
                seen.add(r["ref"])
    return seen


async def _commit_batch(archive, batch: list[SourceRecord], mode: str) -> dict:
    if mode == "store":
        for rec in batch:
            if rec.data is None:
                raise ValueError(f"store mode needs bytes for {rec.ref!r}")
            blob = archive.enc.encrypt(rec.data) if getattr(archive, "enc", None) is not None else rec.data
            await archive.storage.put(f"blob/{rec.sha256.split(':', 1)[1]}", blob)
    shas = [rec.sha256 for rec in batch]
    root = merkle.merkle_root(shas)
    refs = [{"ref": rec.ref, "sha256": rec.sha256} for rec in batch]
    return await archive.notarize(
        doc_hash=root, title=f"records-batch[{len(batch)}]", content_type=BATCH_CONTENT_TYPE,
        metadata={"kind": "records_batch", "algorithm": BATCH_ALG, "count": len(batch),
                  "merkle_root": root, "stored": mode == "store", "refs": refs})


async def _merkle_import(archive, source, *, batch_size, mode, skip_existing, checkpoint_path, progress):
    done = await _committed_refs(archive) if skip_existing else set()
    res = ImportResult(strategy="merkle", source=source.name, mode=mode, started_at=_now())
    t0 = time.perf_counter()
    batch: list[SourceRecord] = []

    async def flush():
        if not batch:
            return
        entry = await _commit_batch(archive, batch, mode)
        res.committed += len(batch); res.batches += 1; res.signatures += 1
        res.batch_seqs.append(entry["seq"])
        for rec in batch:
            done.add(rec.ref)
        batch.clear()
        res.docs_per_sec = res.committed / max(time.perf_counter() - t0, 1e-9)
        if checkpoint_path:
            json.dump({"committed": res.committed, "batches": res.batches, "at": _now()},
                      open(checkpoint_path, "w"))
        if progress:
            progress(res)

    for rec in source.records():
        res.total += 1
        if skip_existing and rec.ref in done:
            res.skipped += 1
            continue
        batch.append(rec)
        if len(batch) >= batch_size:
            await flush()
    await flush()
    res.finished_at = _now()
    res.docs_per_sec = res.committed / max(time.perf_counter() - t0, 1e-9)
    return res


# ---- public API ------------------------------------------------------------------------------------

async def import_records(archive, source, *, strategy: str = "merkle", mode: str = "bridge",
                         batch_size: int = 1000, skip_existing: bool = True,
                         checkpoint_path: str | None = None,
                         progress: Callable[[ImportResult], None] | None = None) -> ImportResult:
    """Import every record from ``source`` into ``archive`` using the chosen signing ``strategy``."""
    licensing.require_license()
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {STRATEGIES}, got {strategy!r}")
    if strategy == "falcon":
        r = await _falcon_migrate(archive, source, mode=mode, skip_existing=skip_existing)
        return ImportResult(strategy="falcon", source=r.source, mode=mode, total=r.total,
                            committed=r.notarized, skipped=r.skipped, batches=r.notarized,
                            signatures=r.notarized, started_at=r.started_at, finished_at=r.finished_at)
    return await _merkle_import(archive, source, batch_size=batch_size, mode=mode,
                                skip_existing=skip_existing, checkpoint_path=checkpoint_path,
                                progress=progress)


def _hash_one(path_ref: tuple[str, str], want_bytes: bool) -> SourceRecord:
    path, ref = path_ref
    with open(path, "rb") as fh:
        data = fh.read()
    return SourceRecord(ref=ref, sha256=_sha(data), data=data if want_bytes else None, metadata={"ref": ref})


async def import_records_fs(archive, root_dir: str, *, strategy: str = "merkle", mode: str = "bridge",
                            batch_size: int = 1000, workers: int = 8, skip_existing: bool = True,
                            checkpoint_path: str | None = None,
                            progress: Callable[[ImportResult], None] | None = None) -> ImportResult:
    """Filesystem import with parallel hashing (SHA-256 releases the GIL), for either strategy."""
    def _paths() -> Iterable[tuple[str, str]]:
        for dirpath, _dirs, files in sorted(os.walk(root_dir)):
            for fn in sorted(files):
                p = os.path.join(dirpath, fn)
                yield p, os.path.relpath(p, root_dir).replace(os.sep, "/")

    want_bytes = mode == "store"

    class _PoolSource:
        name = "fs:" + os.path.abspath(root_dir).replace(os.sep, "/")

        def records(self):
            with ThreadPoolExecutor(max_workers=workers) as ex:
                yield from ex.map(lambda pr: _hash_one(pr, want_bytes), _paths(), chunksize=32)

    return await import_records(archive, _PoolSource(), strategy=strategy, mode=mode, batch_size=batch_size,
                                skip_existing=skip_existing, checkpoint_path=checkpoint_path, progress=progress)


def verify_document_in_batch(doc_sha: str, batch_envelope: str, public_key: bytes) -> bool:
    """Offline proof that ``doc_sha`` is in a signed merkle batch: valid Falcon-1024 signature AND the
    document is a leaf under the signed root. Never raises: malformed input returns False. (Falcon-strategy
    entries are ordinary per-document archive receipts, verified with the base archive/verify_stream.)"""
    try:
        payload, sig, _kid = signing.open_envelope(batch_envelope)
        if not signing.verify_payload(payload, sig, public_key):
            return False
        meta = payload.get("metadata") or {}
        if meta.get("kind") != "records_batch":
            return False
        shas = [r["sha256"] for r in meta.get("refs", [])]
        index = shas.index(doc_sha)
        root = payload.get("doc_hash")
        if merkle.merkle_root(shas) != root:
            return False
        return merkle.verify_inclusion(doc_sha, index, merkle.inclusion_proof(shas, index), root)
    except Exception:  # noqa: BLE001 - a verifier must reject malformed input, not crash
        return False


def compact_proof(batch_envelope: str, doc_sha: str) -> dict:
    """A small standalone inclusion proof for one document, to hand to a third party without the batch."""
    payload, _sig, _kid = signing.open_envelope(batch_envelope)
    shas = [r["sha256"] for r in (payload.get("metadata") or {}).get("refs", [])]
    index = shas.index(doc_sha)
    return {"doc_sha": doc_sha, "index": index, "root": payload.get("doc_hash"),
            "proof": merkle.inclusion_proof(shas, index), "batch_envelope": batch_envelope}
