"""``.acv`` sealed, portable, post-quantum encrypted records container.

File layout (all one file, movable anywhere)::

    MAGIC(5) | u32(header_len) | header_envelope | nonce(12) | AES-256-GCM(tar.gz)

The *header* is a Falcon-1024-signed envelope (cleartext, so it can be verified before anything is
decrypted): container id, issuer, recipient fingerprint, per-document sha256, the revocation policy, and
the **content key wrapped with ML-KEM-1024 to the recipient's public key**. Only the named recipient's
ML-KEM secret can unwrap the CEK; the tar of documents + their archive receipts is then AES-256-GCM
decrypted (AAD-bound to the signed header, so ciphertext cannot be paired with a different header).

Create with :func:`seal_container` / :func:`seal_from_archive` (inside the suite); open with the
self-contained ``acv_unseal.py`` extractor (recipient side, no AlgoVoi packages required) or, in-process,
with :func:`open_container`.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from algovoi_doc_archive import recovery as _recovery
from algovoi_doc_archive import signing
from algovoi_doc_archive.encryption import HybridPqcEncryptor

from algovoi_records_vault_container import crl as _crl
from algovoi_records_vault_container import licensing

MAGIC = b"ACV1\0"
NONCE = 12
HEADER_TYPE = "acv_container"


def _sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _recipient_kid(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def safe_name(name: str) -> str:
    """Return ``name`` iff it is safe to extract, else raise ``ValueError``.

    Document names are written to disk by the recipient's extractor, so a name that is absolute,
    drive-qualified, or contains a ``..`` segment could escape the output directory (path traversal /
    zip-slip). Names must be relative, NUL-free, forward-only POSIX-style paths. Enforced at BOTH seal
    time (fail-closed on creation) and open time (defends against an already-crafted malicious container)."""
    if not isinstance(name, str) or not name:
        raise ValueError("document name must be a non-empty string")
    if "\x00" in name:
        raise ValueError(f"document name contains a NUL byte: {name!r}")
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) >= 2 and n[1] == ":"):
        raise ValueError(f"document name must be relative, not absolute: {name!r}")
    if any(seg == ".." for seg in n.split("/")):
        raise ValueError(f"document name may not contain a '..' segment: {name!r}")
    return name


def _expired(iso: str | None, now: datetime | None = None) -> bool:
    if not iso:
        return False
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return True
    return (now or datetime.now(timezone.utc)) >= exp


def _make_tar(entries: list[dict], names_map: dict | None = None) -> bytes:
    """``entries`` = ``[{"tarname", "data", "receipt"?}]`` (the tar member id, which is the real name
    unless opaque-names is on). When ``names_map`` is given (opaque mode: ``{tarname: real_name}``) it is
    written as an encrypted ``NAMES.json`` member so the recipient can restore real names after decrypt."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for e in entries:
            data = e["data"]
            ti = tarfile.TarInfo("docs/" + e["tarname"]); ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
            if e.get("receipt"):
                r = e["receipt"].encode()
                ti = tarfile.TarInfo("receipts/" + e["tarname"] + ".receipt"); ti.size = len(r)
                tf.addfile(ti, io.BytesIO(r))
        if names_map is not None:
            nb = json.dumps(names_map, sort_keys=True).encode()
            ti = tarfile.TarInfo("NAMES.json"); ti.size = len(nb)
            tf.addfile(ti, io.BytesIO(nb))
    return buf.getvalue()


def seal_container(*, documents: list[dict], recipient_public_key: bytes,
                   container_id: str, out_path: str,
                   issuer_signer=None, issuer_public_key: bytes | None = None,
                   issuer_secret_key: bytes | None = None, expires_at: str | None = None,
                   revocation_registry: str = "default", require_revocation_check: bool = True,
                   title: str | None = None, recovery: dict | None = None,
                   escrow_public_key: bytes | None = None, min_crl_at: str | None = None,
                   opaque_names: bool = False) -> dict:
    """Seal ``documents`` (each ``{"name", "data", "receipt"?}``) into a ``.acv`` at ``out_path``,
    encrypted so only the holder of ``recipient_public_key``'s ML-KEM secret can open it. Sign the
    header either with an ``issuer_signer`` (a Signer, e.g. the Command Center console signer, for
    pluggable HSM/KMS custody) or with a raw ``issuer_public_key`` + ``issuer_secret_key`` pair.

    ``min_crl_at`` (default: the container's ``created_at``) is the earliest revocation-list timestamp
    the opener will accept, so an attacker cannot replay a validly-signed CRL issued *before* this
    container to pretend it was never revoked. ``opaque_names=True`` hides document names and the title
    from the cleartext header: the header lists opaque ids and the real names travel encrypted inside the
    body, restored only after decryption. Returns a manifest summary. Runtime licence enforced."""
    licensing.require_license()
    if issuer_signer is not None:
        issuer_public_key = issuer_signer.public_key()
    if issuer_public_key is None or (issuer_signer is None and issuer_secret_key is None):
        raise ValueError("provide issuer_signer, or issuer_public_key + issuer_secret_key")
    if not documents:
        raise ValueError("no documents to seal")
    names = [d["name"] for d in documents]
    if len(set(names)) != len(names):
        raise ValueError("duplicate document names")
    for n in names:
        safe_name(n)   # fail-closed: never seal a traversal-capable name

    # opaque-names: the tar member id + header name become opaque; real names ride in encrypted NAMES.json
    entries, names_map = [], {}
    for i, d in enumerate(documents):
        tarname = f"d{i}" if opaque_names else d["name"]
        if opaque_names:
            names_map[tarname] = d["name"]
        entries.append({"tarname": tarname, "data": d["data"], "receipt": d.get("receipt")})

    cek = os.urandom(32)
    tar_bytes = _make_tar(entries, names_map if opaque_names else None)
    wrapped_cek = HybridPqcEncryptor(recipient_public_key).encrypt(cek)

    # Optional Shamir k-of-n recovery: split the content key so that any k custodians can reconstruct
    # it and open the container even if the recipient's ML-KEM secret is lost. The (non-secret) recovery
    # envelope rides inside the Falcon-signed header; the n shares are returned to the issuer to
    # distribute and are never stored. Reuses the audited SLIP-39 recovery primitive.
    recovery_meta = {"enabled": False}
    recovery_shares: list[str] = []
    if recovery:
        k = int(recovery["threshold_k"]); n = int(recovery["total_n"])
        env, recovery_shares = _recovery.split_recovery(
            master_secret=cek, threshold_k=k, total_n=n,
            include_algovoi_support=bool(recovery.get("include_algovoi_support", False)))
        recovery_meta = {"enabled": True, "threshold_k": k, "total_n": n,
                         "support_assisted": env.get("support_assisted", False), "envelope": env}

    # Optional console escrow: additionally wrap the CEK to a Command-Center-held recovery key so the
    # operator can recover THIS container 100% from the console alone (no custodian shares). Opt-in per
    # container: whoever holds the escrow secret can decrypt it, so it is a deliberate confidentiality
    # trade-off recorded in the signed header.
    escrow_meta = {"enabled": False}
    if escrow_public_key is not None:
        escrow_meta = {"enabled": True, "kem": "ML-KEM-1024",
                       "recovery_kid": hashlib.sha256(escrow_public_key).hexdigest()[:16],
                       "wrapped_cek_b64": signing.b64u_encode(HybridPqcEncryptor(escrow_public_key).encrypt(cek))}

    created_at = _iso()
    header_payload = {
        "type": HEADER_TYPE, "version": "1", "container_id": container_id,
        "title": None if opaque_names else title,
        "issuer_kid": signing.kid_for(issuer_public_key),
        "issuer_pub_b64": signing.public_key_b64(issuer_public_key),
        "created_at": created_at, "expires_at": expires_at,
        "recipient_kid": _recipient_kid(recipient_public_key),
        "docs": [{"name": e["tarname"], "sha256": _sha(e["data"]), "has_receipt": bool(e.get("receipt"))}
                 for e in entries],
        "names_opaque": bool(opaque_names),
        "wrapped_cek_b64": signing.b64u_encode(wrapped_cek),
        "revocation": {"registry": revocation_registry, "required": bool(require_revocation_check),
                       "min_crl_at": min_crl_at or created_at},
        "recovery": recovery_meta,
        "escrow": escrow_meta,
        "kem": "ML-KEM-1024", "cipher": "AES-256-GCM",
    }
    header_env = (signing.make_envelope_with(header_payload, issuer_signer) if issuer_signer is not None
                  else signing.make_envelope(header_payload, issuer_secret_key, issuer_public_key))
    header_bytes = header_env.encode()
    aad = hashlib.sha256(header_bytes).digest()
    nonce = os.urandom(NONCE)
    ct = AESGCM(cek).encrypt(nonce, tar_bytes, aad)
    blob = MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + nonce + ct
    with open(out_path, "wb") as fh:
        fh.write(blob)
    return {"container_id": container_id, "path": out_path, "documents": len(documents),
            "bytes": len(blob), "sha256": _sha(blob), "issuer_kid": header_payload["issuer_kid"],
            "recipient_kid": header_payload["recipient_kid"], "created_at": header_payload["created_at"],
            "expires_at": expires_at,
            "recovery": {"enabled": recovery_meta["enabled"],
                         "threshold_k": recovery_meta.get("threshold_k"),
                         "total_n": recovery_meta.get("total_n"),
                         "shares": recovery_shares},
            "escrow": {"enabled": escrow_meta["enabled"], "recovery_kid": escrow_meta.get("recovery_kid")}}


async def seal_from_archive(archive, doc_hashes: list[str], *, recipient_public_key: bytes,
                            container_id: str, out_path: str, issuer_signer=None,
                            issuer_public_key: bytes | None = None, issuer_secret_key: bytes | None = None,
                            names: list[str] | None = None, **kwargs) -> dict:
    """Pull ``doc_hashes`` (their bytes + archive receipts) from a Records Vault ``archive`` and seal
    them into a ``.acv``. The archive's own signing key is the natural issuer key."""
    entries = await archive.list_entries()
    by_hash: dict[str, str] = {}
    for e in entries:
        try:
            p, _, _ = signing.open_envelope(e)
        except Exception:  # noqa: BLE001
            continue
        if p.get("doc_hash"):
            by_hash[p["doc_hash"]] = e
    documents = []
    for i, h in enumerate(doc_hashes):
        data = await archive.retrieve(doc_hash=h)
        name = (names[i] if names and i < len(names) else None) or (h.split(":", 1)[-1][:16] + ".bin")
        documents.append({"name": name, "data": data, "receipt": by_hash.get(h)})
    return seal_container(documents=documents, recipient_public_key=recipient_public_key,
                          issuer_signer=issuer_signer, issuer_public_key=issuer_public_key,
                          issuer_secret_key=issuer_secret_key,
                          container_id=container_id, out_path=out_path, **kwargs)


def read_header(path: str) -> dict:
    """Return the container's validated-by-shape header payload (does NOT verify the signature).
    Use :func:`open_container` for the full verify-then-decrypt."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("not an .acv container (bad magic)")
    hlen = int.from_bytes(blob[len(MAGIC):len(MAGIC) + 4], "big")
    header_bytes = blob[len(MAGIC) + 4:len(MAGIC) + 4 + hlen]
    payload, _, _ = signing.open_envelope(header_bytes.decode())
    return payload


def _parse_and_verify(path: str, *, crl_env: str | None, now: datetime | None,
                      enforce_revocation: bool = True, max_crl_age_seconds: int | None = None):
    """Parse a ``.acv``, verify the signed header, and enforce expiry + revocation policy.
    Returns ``(payload, header_bytes, nonce, ct, issuer_pub)``. Raises ``ValueError`` on any failure.
    ``enforce_revocation=False`` skips the revocation gate (used by console escrow recovery, where the
    issuer is recovering its own container). ``max_crl_age_seconds`` is a recipient-side freshness
    requirement: reject a CRL older than that many seconds so a stale-but-post-creation list cannot keep
    a revoked container openable."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("not an .acv container (bad magic)")
    off = len(MAGIC)
    hlen = int.from_bytes(blob[off:off + 4], "big"); off += 4
    header_bytes = blob[off:off + hlen]; off += hlen
    nonce = blob[off:off + NONCE]; off += NONCE
    ct = blob[off:]

    payload, sig, _ = signing.open_envelope(header_bytes.decode())
    if payload.get("type") != HEADER_TYPE:
        raise ValueError("not an acv_container header")
    issuer_pub = signing.load_key_b64(payload["issuer_pub_b64"])
    if not signing.verify_payload(payload, sig, issuer_pub):
        raise ValueError("header signature verification failed")
    if _expired(payload.get("expires_at"), now):
        raise ValueError(f"container expired at {payload.get('expires_at')}")

    rev = payload.get("revocation") or {}
    if enforce_revocation:
        if crl_env is not None:
            crl_payload = _crl.verify_crl(crl_env, issuer_pub)
            if crl_payload is None:
                raise ValueError("revocation list did not verify against the issuer key")
            # freshness floor: refuse a validly-signed CRL issued before this container (anti-replay)
            min_crl_at = rev.get("min_crl_at")
            crl_at = crl_payload.get("updated_at") or ""
            if min_crl_at and crl_at < min_crl_at:
                raise ValueError(
                    f"revocation list is stale (updated {crl_at}, container requires {min_crl_at} or later)")
            # recipient freshness policy: refuse a CRL older than max_crl_age_seconds from now
            if max_crl_age_seconds is not None:
                try:
                    crl_dt = datetime.strptime(crl_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                except Exception as exc:  # noqa: BLE001
                    raise ValueError("revocation list has no valid updated_at for the freshness check") from exc
                if (now or datetime.now(timezone.utc)) - crl_dt > timedelta(seconds=max_crl_age_seconds):
                    raise ValueError(
                        f"revocation list is too old (updated {crl_at}); a list within "
                        f"{max_crl_age_seconds}s is required")
            if any(r.get("container_id") == payload["container_id"] for r in crl_payload.get("revoked", [])):
                raise ValueError(f"container {payload['container_id']} is revoked")
        elif rev.get("required"):
            raise ValueError("this container requires a revocation-list check but none was supplied")
    return payload, header_bytes, nonce, ct, issuer_pub


def _decrypt_extract(header_bytes: bytes, payload: dict, nonce: bytes, ct: bytes, cek: bytes,
                     verify_receipts: bool, issuer_pub: bytes) -> dict:
    aad = hashlib.sha256(header_bytes).digest()
    try:
        tar_bytes = AESGCM(cek).decrypt(nonce, ct, aad)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("payload decryption failed (wrong key or tampered container)") from exc

    by_tar: dict[str, bytes] = {}     # keyed by tar member id (opaque id, or the real name)
    receipts: dict[str, str] = {}
    names_map: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.name == "NAMES.json":
                names_map = json.loads(tf.extractfile(m).read().decode())
            elif m.name.startswith("docs/"):
                dn = m.name[len("docs/"):]
                safe_name(dn)   # reject a traversal id even from an already-crafted container
                by_tar[dn] = tf.extractfile(m).read()
            elif m.name.startswith("receipts/"):
                receipts[m.name[len("receipts/"):-len(".receipt")]] = tf.extractfile(m).read().decode()

    by_name = {d["name"]: d for d in payload["docs"]}   # header lists tar ids
    for tid, data in by_tar.items():
        if tid not in by_name:
            raise ValueError(f"decrypted doc {tid!r} not listed in the signed header")
        if _sha(data) != by_name[tid]["sha256"]:
            raise ValueError(f"doc {tid!r} failed integrity check")
    if verify_receipts:
        for tid, r in receipts.items():
            rp, rsig, rkid = signing.open_envelope(r)
            # Only receipts signed by the issuer key are checkable here (the seal_from_archive case,
            # where the archive key is the issuer). Foreign-archive receipts are carried as provenance
            # but need that archive's public key to verify, so they are not rejected here.
            if rkid == payload["issuer_kid"]:
                if rp.get("type") != "archive_entry" or not signing.verify_payload(rp, rsig, issuer_pub):
                    raise ValueError(f"receipt for {tid!r} failed archive-signature check")

    # restore real names (opaque mode) after integrity; the restored name is re-checked for traversal
    out: dict[str, bytes] = {}
    for tid, data in by_tar.items():
        real = names_map.get(tid, tid)
        safe_name(real)   # a malicious NAMES.json must not smuggle a path-escaping real name
        out[real] = data
    return out


def open_container(path: str, *, recipient_secret_key: bytes, crl_env: str | None = None,
                   now: datetime | None = None, verify_receipts: bool = True,
                   expect_issuer: str | None = None,
                   max_crl_age_seconds: int | None = None) -> tuple[dict, dict]:
    """Verify + decrypt a ``.acv`` in-process with the recipient's ML-KEM secret. Returns
    ``(header_payload, {name: data})``. Raises ``ValueError`` on any failure (bad
    magic/signature/expiry/revocation/tamper). The issuer key is taken from the signed header, so the
    signature only proves internal consistency, not *who* signed: pass ``expect_issuer`` with the
    issuer_kid you were given out of band to bind the container to a known issuer."""
    payload, header_bytes, nonce, ct, issuer_pub = _parse_and_verify(
        path, crl_env=crl_env, now=now, max_crl_age_seconds=max_crl_age_seconds)
    if expect_issuer is not None and payload.get("issuer_kid") != expect_issuer:
        raise ValueError(f"issuer_kid {payload.get('issuer_kid')} does not match expected {expect_issuer}")
    cek = HybridPqcEncryptor(b"", recipient_secret_key).decrypt(signing.b64u_decode(payload["wrapped_cek_b64"]))
    return payload, _decrypt_extract(header_bytes, payload, nonce, ct, cek, verify_receipts, issuer_pub)


def recover_container(path: str, *, shares: list[str], crl_env: str | None = None,
                      now: datetime | None = None, verify_receipts: bool = True) -> tuple[dict, dict]:
    """Recover + decrypt a ``.acv`` WITHOUT the recipient's key, using ``k`` Shamir recovery shares
    (for when the recipient's ML-KEM secret is lost). Requires the container was sealed with a recovery
    policy. Still enforces expiry and revocation. Returns ``(header_payload, {name: data})``."""
    payload, header_bytes, nonce, ct, issuer_pub = _parse_and_verify(path, crl_env=crl_env, now=now)
    rec = payload.get("recovery") or {}
    if not rec.get("enabled"):
        raise ValueError("no recovery policy configured for this container")
    try:
        cek = _recovery.recover_from_shares(envelope=rec["envelope"], shares=shares)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"recovery failed: {exc}") from exc
    return payload, _decrypt_extract(header_bytes, payload, nonce, ct, cek, verify_receipts, issuer_pub)


def recover_via_escrow(path: str, *, escrow_secret_key: bytes, crl_env: str | None = None,
                       now: datetime | None = None, verify_receipts: bool = True) -> tuple[dict, dict]:
    """Recover a container 100% from the console-held escrow key (for containers sealed
    ``console_recoverable``). No recipient key and no custodian shares needed. Verifies the signed
    header and expiry; the revocation gate is skipped because the issuer is recovering its own data.
    Returns ``(header_payload, {name: data})``. Raises if the container carries no escrow key."""
    payload, header_bytes, nonce, ct, issuer_pub = _parse_and_verify(
        path, crl_env=crl_env, now=now, enforce_revocation=False)
    esc = payload.get("escrow") or {}
    if not esc.get("enabled"):
        raise ValueError("this container is not console-recoverable (sealed without an escrow key)")
    try:
        cek = HybridPqcEncryptor(b"", escrow_secret_key).decrypt(signing.b64u_decode(esc["wrapped_cek_b64"]))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"escrow recovery failed (wrong console recovery key): {exc}") from exc
    return payload, _decrypt_extract(header_bytes, payload, nonce, ct, cek, verify_receipts, issuer_pub)
