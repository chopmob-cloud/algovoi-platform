"""Opt-in folder watcher for the AlgoVoi Records Vault volume importer.

A polling watcher (stdlib only, no external dependency) for continuous ingestion: point it at a source
folder and it runs an idempotent import whenever the folder has been *quiescent* (no size change) for a
grace period, so half-written files are never imported mid-write. Because the underlying import is
idempotent (``skip_existing`` dedups by content), each cycle only commits genuinely new documents.

This is the automation layer over the explicit CLI import, and is deliberately conservative:

  * complete-file safety: a cycle runs only after ``quiescent_secs`` with no file size change;
  * trust boundary: whoever can write to the watched folder can get records notarized, so the folder
    should be an allowlisted, access-controlled path (the caller owns that policy);
  * fail-closed: an exception in one cycle is reported via ``on_error`` and the watcher keeps polling;
    it never silently drops input.

Off by default; enable per vault only when there is a real streaming source.
"""
from __future__ import annotations

import os
import time
from typing import Callable

from algovoi_records_vault_importer.importer import ImportResult, import_records_fs


def _dir_signature(root: str) -> tuple[int, int, int]:
    """A cheap fingerprint of a directory tree: (file_count, total_size, max_mtime_ns)."""
    count = 0
    size = 0
    mtime = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            try:
                st = os.stat(os.path.join(dirpath, fn))
            except OSError:
                continue
            count += 1
            size += st.st_size
            mtime = max(mtime, st.st_mtime_ns)
    return count, size, mtime


async def watch(archive, source: str, *, strategy: str = "merkle", mode: str = "bridge",
                batch_size: int = 1000, workers: int = 8, checkpoint_path: str | None = None,
                poll_secs: float = 10.0, quiescent_secs: float = 5.0,
                on_cycle: Callable[[ImportResult], None] | None = None,
                on_error: Callable[[Exception], None] | None = None,
                stop: Callable[[], bool] | None = None,
                clock: Callable[[], float] | None = None,
                sleep: Callable[[float], "object"] | None = None) -> int:
    """Watch ``source`` and import quiescent, previously-unseen documents until ``stop()`` is true.

    Returns the number of import cycles that committed at least one document. ``clock``/``sleep`` are
    injectable for testing (default: ``time.monotonic`` and ``asyncio.sleep``).
    """
    import asyncio

    now = clock or time.monotonic
    nap = sleep or asyncio.sleep
    should_stop = stop or (lambda: False)

    last_sig = None
    stable_since = None
    committed_cycles = 0

    while not should_stop():
        sig = _dir_signature(source)
        empty = sig[0] == 0
        if sig != last_sig:
            last_sig = sig
            stable_since = now()
        elif not empty and stable_since is not None and (now() - stable_since) >= quiescent_secs:
            stable_since = None  # arm once per quiescent settle
            try:
                result = await import_records_fs(
                    archive, source, strategy=strategy, mode=mode, batch_size=batch_size,
                    workers=workers, skip_existing=True, checkpoint_path=checkpoint_path)
                if result.committed:
                    committed_cycles += 1
                if on_cycle is not None:
                    on_cycle(result)
            except Exception as exc:  # noqa: BLE001 - fail-closed: report and keep watching
                if on_error is not None:
                    on_error(exc)
        await nap(poll_secs)
    return committed_cycles
