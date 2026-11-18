"""
S3 / S3-compatible :class:`StorageBackend` for the AlgoVoi Verifiable Archive.

The archive engine encrypts every document **before** it reaches storage, so this backend only ever
stores ciphertext — the same evidence model and the same encryption as the local-filesystem backend.
Works with Amazon S3 and any S3-compatible store (MinIO, Cloudflare R2, Wasabi, Ceph) via
``endpoint_url``.
"""
from __future__ import annotations

from algovoi_doc_archive_s3 import licensing

import asyncio
from typing import Any


def _is_not_found(exc: Exception) -> bool:
    """True if a boto3/botocore error represents a missing key/bucket (404)."""
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = str(resp.get("Error", {}).get("Code", ""))
        if code in ("NoSuchKey", "NoSuchBucket", "404", "NotFound"):
            return True
    return False


class S3Backend:
    """Stores archive objects in an S3 / S3-compatible bucket.

    Provide a ready boto3 S3 ``client``, or let the backend build one from connection params
    (``endpoint_url`` selects an S3-compatible provider). An optional ``prefix`` namespaces all keys
    within the bucket.
    """

    def __init__(
        self,
        bucket: str,
        *,
        client: Any | None = None,
        prefix: str = "",
        endpoint_url: str | None = None,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        **client_kwargs: Any,
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        if client is not None:
            self._client = client
        else:
            import boto3  # imported lazily so tests can inject a fake client without boto3

            self._client = boto3.client(
                "s3", endpoint_url=endpoint_url, region_name=region_name,
                aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
                **client_kwargs)

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def _put(self, key: str, data: bytes) -> None:
        self._client.put_object(Bucket=self.bucket, Key=self._key(key), Body=data)

    def _get(self, key: str) -> bytes | None:
        try:
            resp = self._client.get_object(Bucket=self.bucket, Key=self._key(key))
        except Exception as e:  # noqa: BLE001
            if _is_not_found(e):
                return None
            raise
        return resp["Body"].read()

    def _exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=self._key(key))
        except Exception as e:  # noqa: BLE001
            if _is_not_found(e):
                return False
            raise
        return True

    def _list(self, prefix: str) -> list[str]:
        full = self._key(prefix)
        strip = len(self.prefix) + 1 if self.prefix else 0
        out: list[str] = []
        token: str | None = None
        while True:
            kw: dict[str, Any] = {"Bucket": self.bucket, "Prefix": full}
            if token:
                kw["ContinuationToken"] = token
            resp = self._client.list_objects_v2(**kw)
            for obj in resp.get("Contents", []) or []:
                out.append(obj["Key"][strip:])
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        return sorted(out)

    async def put(self, key: str, data: bytes) -> None:
        await asyncio.to_thread(self._put, key, data)

    async def get(self, key: str) -> bytes | None:
        return await asyncio.to_thread(self._get, key)

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self._exists, key)

    async def list_prefix(self, prefix: str) -> list[str]:
        return await asyncio.to_thread(self._list, prefix)
