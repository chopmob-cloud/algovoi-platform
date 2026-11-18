"""
Pluggable storage backend. The engine encrypts before calling these, so backends store ciphertext.

Implement :class:`StorageBackend` to target any object store; :class:`LocalFsBackend` (pure-Python,
no external deps) is bundled here. The S3 / S3-compatible backend ships in ``algovoi-doc-archive-s3``.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class StorageBackend(Protocol):
    async def put(self, key: str, data: bytes) -> None: ...
    async def get(self, key: str) -> bytes | None: ...
    async def exists(self, key: str) -> bool: ...
    async def list_prefix(self, prefix: str) -> list[str]: ...


class LocalFsBackend:
    """Stores each object as a file under ``root``. Air-gap friendly; atomic writes via temp+rename."""

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        p = (self.root / key).resolve()
        if self.root not in p.parents and p != self.root:
            raise ValueError("path traversal blocked")
        return p

    def _put(self, key: str, data: bytes) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)

    def _get(self, key: str) -> bytes | None:
        p = self._path(key)
        return p.read_bytes() if p.exists() else None

    def _exists(self, key: str) -> bool:
        return self._path(key).exists()

    def _list(self, prefix: str) -> list[str]:
        out: list[str] = []
        for f in self.root.rglob("*"):
            if f.is_file():
                rel = f.relative_to(self.root).as_posix()
                if rel.startswith(prefix):
                    out.append(rel)
        return sorted(out)

    async def put(self, key: str, data: bytes) -> None:
        await asyncio.to_thread(self._put, key, data)

    async def get(self, key: str) -> bytes | None:
        return await asyncio.to_thread(self._get, key)

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self._exists, key)

    async def list_prefix(self, prefix: str) -> list[str]:
        return await asyncio.to_thread(self._list, prefix)
