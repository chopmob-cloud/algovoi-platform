"""
substrate2.httpsig — RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest.

Implemented from draft-hopley-x402-rfc9421-binding-00, RFC 9421 (§2.3-2.5 signature base)
and RFC 9530 (Content-Digest), validated against the RFC 8032 §7.1 pinned fixture. The
signature base is built line-per-covered-component with @signature-params last; @method
preserves case, @authority is lowercased. Ed25519 via `cryptography` (deterministic), so
the signature is byte-reproducible.

Public signature preserved from v1 (name/args/return); body independently authored.
Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_COVERED = ["@method", "@authority", "@path", "content-digest", "created"]
_SUPPORTED_DERIVED = {"@method", "@authority", "@path"}
_SPECIAL = {"content-digest", "created"}


class SignError(ValueError):
    pass


@dataclass
class SignResult:
    signature_input: str
    signature: str
    content_digest: str
    signing_base: str
    label: str
    covered_components: list
    created: int


def _coerce_seed(private_key: Any) -> bytes:
    if isinstance(private_key, str):
        try:
            private_key = bytes.fromhex(private_key)
        except ValueError as exc:
            raise SignError(f"private_key hex invalid: {exc}") from exc
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
        raise SignError("private_key must be a 32 bytes Ed25519 seed")
    return bytes(private_key)


def compute_content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest using sha-256."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _component_value(comp, *, method, authority, path, content_digest, created, headers_lower, expires=None):
    if comp == "@method":
        return method  # preserve case
    if comp == "@authority":
        return authority.lower()
    if comp == "@path":
        return path
    if comp == "content-digest":
        return content_digest
    if comp == "created":
        return str(created)
    if comp == "expires":
        if expires is None:
            raise SignError(
                "'expires' covered but no expires= argument was supplied; "
                "pass expires=<unix-seconds> to sign_request."
            )
        return str(expires)
    if comp.startswith("@"):
        raise SignError(f"unsupported derived component: {comp}")
    value = headers_lower.get(comp.lower())
    if value is None:
        raise SignError(f"covered header not present in request: {comp}")
    return value


def build_signing_base(covered, *, method, authority, path, content_digest, created, keyid, headers_lower, label="sig", algorithm="ed25519", expires=None, nonce=None, tag=None):
    # Params order mirrors the reference signer: created, then optional expires, then
    # keyid + alg, then optional nonce + tag. Each optional param is emitted only when
    # set, so signatures produced without them are byte-unchanged.
    params = "(" + " ".join(f'"{c}"' for c in covered) + ")" + f";created={created}"
    if expires is not None:
        params += f";expires={expires}"
    params += f";keyid=\"{keyid}\";alg=\"{algorithm}\""
    if nonce is not None:
        params += f";nonce=\"{nonce}\""
    if tag is not None:
        params += f";tag=\"{tag}\""
    lines = [
        f'"{c}": {_component_value(c, method=method, authority=authority, path=path, content_digest=content_digest, created=created, headers_lower=headers_lower, expires=expires)}'
        for c in covered
    ]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines), params


def sign_request(
    *,
    method: str,
    authority: str,
    path: str,
    body: bytes = b"",
    private_key: Any,
    keyid: str,
    headers: dict | None = None,
    covered_components: list | None = None,
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
    tag: str | None = None,
    label: str = "sig",
    algorithm: str = "ed25519",
) -> SignResult:
    if algorithm != "ed25519":
        raise SignError(f"unsupported algorithm {algorithm!r}; only ed25519 is supported")
    seed = _coerce_seed(private_key)
    if created is None:
        created = int(time.time())
    covered = list(covered_components) if covered_components is not None else list(DEFAULT_COVERED)
    headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

    content_digest = compute_content_digest(body)
    signing_base, params = build_signing_base(
        covered,
        method=method,
        authority=authority,
        path=path,
        content_digest=content_digest,
        created=created,
        keyid=keyid,
        headers_lower=headers_lower,
        label=label,
        algorithm=algorithm,
        expires=expires,
        nonce=nonce,
        tag=tag,
    )

    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(signing_base.encode("utf-8"))
    signature = f"{label}=:" + base64.b64encode(sig).decode() + ":"
    signature_input = f"{label}={params}"

    return SignResult(
        signature_input=signature_input,
        signature=signature,
        content_digest=content_digest,
        signing_base=signing_base,
        label=label,
        covered_components=covered,
        created=created,
    )


def verify_request(**kwargs: Any):
    """Verify an RFC 9421 signed request. Delegates to :mod:`substrate2.rfc9421_verifier`.

    The verifier half lives in its own module because it is a substantially larger surface
    (signature-input parsing, signing-base reconstruction, content-digest checking) than the
    signer. This entry point exists so `substrate2.verify_request` is the natural counterpart
    to `substrate2.sign_request` rather than a dead name.

    Until 2.0.0 this raised NotImplementedError("Phase 3") while the implementation it should
    have been calling was already complete next door -- a stub advertising unfinished work
    that was finished. Caught by the GA criteria sweep (GA-CRITERIA.md, criterion 5).
    """
    from .rfc9421_verifier import verify_request as _verify

    return _verify(**kwargs)


__all__ = [
    "DEFAULT_COVERED",
    "SignError",
    "SignResult",
    "build_signing_base",
    "compute_content_digest",
    "sign_request",
    "verify_request",
]
