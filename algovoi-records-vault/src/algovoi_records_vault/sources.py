"""Migration sources beyond the filesystem: SQLite blob tables and S3-compatible object stores.

Both implement the :class:`algovoi_records_vault.migrate.Source` protocol (``name`` +
``records()``) and yield deterministic, ref-ordered :class:`SourceRecord` streams so migration
runs are reproducible and manifests are stable. No cryptography here — hashing comes from the
same helper the migrator uses.
"""
from __future__ import annotations

import sqlite3
from typing import Iterable

from algovoi_records_vault.migrate import SourceRecord, _sha


class SqliteBlobSource:
    """Read records out of a SQLite table: one row per record, blob column = the bytes.

    ``ref_column`` must be unique per row (it becomes the migration ``ref``). Rows are read in
    ``ORDER BY ref_column`` so re-runs and manifests are deterministic. ``where`` (optional,
    operator-supplied) lets a caller scope the migration, e.g. ``"archived = 0"``; it must be a
    single boolean expression — statement terminators and SQL comments are rejected.
    """

    def __init__(self, db_path: str, *, table: str, ref_column: str, blob_column: str,
                 where: str | None = None,
                 content_type: str = "application/octet-stream") -> None:
        for ident in (table, ref_column, blob_column):
            if not ident.replace("_", "").isalnum():
                raise ValueError(f"unsafe SQL identifier: {ident!r}")
        if where is not None:
            if not isinstance(where, str):
                raise ValueError("where must be a string SQL boolean expression")
            # `where` is interpolated into the query, so it must be operator-supplied and TRUSTED — it
            # is NOT sanitised here. This guard only enforces the "single boolean expression" contract
            # (reject statement terminators / SQL comments) to catch mistakes; never pass attacker input.
            if any(tok in where for tok in (";", "--", "/*", "*/")):
                raise ValueError("where must be a single boolean expression (no ';' or SQL comments)")
        self.db_path = db_path
        self.table = table
        self.ref_column = ref_column
        self.blob_column = blob_column
        self.where = where
        self._ct = content_type
        self.name = f"sqlite:{db_path}#{table}.{blob_column}"

    def records(self) -> Iterable[SourceRecord]:
        q = (f"SELECT {self.ref_column}, {self.blob_column} FROM {self.table}"  # nosec B608 - parameterized query; only the portable placeholder (self._ph) is interpolated, values are bound
             + (f" WHERE {self.where}" if self.where else "")
             + f" ORDER BY {self.ref_column}")
        conn = sqlite3.connect(self.db_path)
        try:
            for ref, blob in conn.execute(q):
                if blob is None:
                    continue
                data = bytes(blob) if not isinstance(blob, bytes) else blob
                if isinstance(blob, str):
                    data = blob.encode("utf-8")
                yield SourceRecord(
                    ref=str(ref), sha256=_sha(data), data=data, content_type=self._ct,
                    metadata={"migrated_from": self.name, "ref": str(ref)},
                )
        finally:
            conn.close()


class S3Source:
    """Read records out of an S3-compatible bucket (AWS S3, MinIO, R2).

    ``client`` is a boto3 S3 client (or any object with ``get_paginator('list_objects_v2')`` and
    ``get_object``) — injectable so unit tests can pass a fake and live runs can point at MinIO
    via ``boto3.client('s3', endpoint_url=...)``. Keys are yielded in the lexicographic order S3
    lists them (deterministic). ``prefix`` scopes the migration; the migration ``ref`` is the key
    with the prefix stripped.
    """

    def __init__(self, client, *, bucket: str, prefix: str = "",
                 content_type: str = "application/octet-stream") -> None:
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self._ct = content_type
        self.name = f"s3:{bucket}/{prefix}".rstrip("/")

    def records(self) -> Iterable[SourceRecord]:
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []) or []:
                key = obj["Key"]
                if key.endswith("/"):           # folder placeholder objects
                    continue
                body = self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()
                ref = key[len(self.prefix):].lstrip("/") if self.prefix else key
                yield SourceRecord(
                    ref=ref, sha256=_sha(body), data=body, content_type=self._ct,
                    metadata={"migrated_from": self.name, "ref": ref, "s3_key": key},
                )
