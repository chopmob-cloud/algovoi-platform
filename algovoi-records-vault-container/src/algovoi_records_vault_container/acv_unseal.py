#!/usr/bin/env python3
"""acv-unseal — self-contained offline extractor for an AlgoVoi ``.acv`` sealed records container.

The recipient runs this with their **ML-KEM-1024 secret key**; it verifies the container's Falcon-1024
signed header, checks the revocation list (if the container requires one), unwraps the AES content key
with the recipient's secret, decrypts, and writes each document out after a SHA-256 integrity check. It
is fully OFFLINE and imports NO AlgoVoi packages — only ``pqcrypto``, ``rfc8785`` and ``cryptography``.

The issuer's public key is carried in the (signed) header; compare the printed ``issuer_kid`` against the
fingerprint you were given out of band before you trust the contents.

Usage:
    python acv_unseal.py --key @recipient_sk.b64 --out ./unsealed container.acv
    python acv_unseal.py --key @recipient_sk.b64 --revocation-list @crl.txt --out ./unsealed container.acv
    # recovery: recipient key lost -> reconstruct from k Shamir shares (one --recover-share per share)
    python acv_unseal.py --recover-share "word list one ..." --recover-share "word list two ..." --out ./unsealed container.acv

Deps: pqcrypto, rfc8785, cryptography (+ shamir-mnemonic for --recover-share)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import sys
import tarfile
from datetime import datetime, timezone

MAGIC = b"ACV1\0"
NONCE = 12


def _die(msg: str, code: int = 2):
    print(f"acv-unseal: ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _safe_name(name: str) -> bool:
    """False if ``name`` is absolute, drive-qualified, NUL-bearing, or contains a '..' segment
    (path traversal / zip-slip). Document names get written under --out, so an unsafe name could
    escape it."""
    if not isinstance(name, str) or not name or "\x00" in name:
        return False
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) >= 2 and n[1] == ":"):
        return False
    return not any(seg == ".." for seg in n.split("/"))


def _load_arg(arg: str) -> str:
    if arg.startswith("@"):
        with open(arg[1:], encoding="utf-8") as fh:
            return fh.read().strip()
    return arg.strip()


def _falcon_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    from pqcrypto.sign.falcon_1024 import verify as _v
    try:
        return bool(_v(pk, msg, sig))
    except Exception:  # noqa: BLE001
        return False


def _mlkem_unwrap(secret_key: bytes, blob: bytes) -> bytes:
    """Reverse HybridPqcEncryptor: u16(len kem_ct) | kem_ct | nonce(12) | ct+tag."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pqcrypto.kem.ml_kem_1024 import decrypt as _decap
    n = int.from_bytes(blob[:2], "big")
    kem_ct, rest = blob[2:2 + n], blob[2 + n:]
    nonce, ct = rest[:NONCE], rest[NONCE:]
    shared = _decap(secret_key, kem_ct)
    key = hashlib.sha256(shared).digest()
    return AESGCM(key).decrypt(nonce, ct, None)


def _recover_cek(payload: dict, shares: list[str]) -> bytes:
    """Reconstruct the content key from k Shamir recovery shares (SLIP-39), reversing split_recovery:
    combine shares -> DEK, then AES-256-GCM-unwrap the CEK the DEK sealed."""
    rec = payload.get("recovery") or {}
    if not rec.get("enabled"):
        _die("this container has no recovery policy (cannot use --recover-share)")
    env = rec["envelope"]
    try:
        from shamir_mnemonic import combine_mnemonics
    except Exception:  # noqa: BLE001
        _die("recovery needs the shamir-mnemonic package: pip install shamir-mnemonic")
    try:
        dek = combine_mnemonics([s.strip() for s in shares])
    except Exception as exc:  # noqa: BLE001
        _die(f"could not combine recovery shares (invalid, mismatched, or too few): {exc}")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    wrapped = _b64u_decode(env["wrapped_secret_b64"])
    try:
        return AESGCM(dek).decrypt(wrapped[:NONCE], wrapped[NONCE:], None)
    except Exception:  # noqa: BLE001
        _die("recovered key did not unwrap the content key (wrong shares)")


def _expired(iso, now):
    if not iso:
        return False
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return True
    return now >= exp


def _jcs(payload) -> bytes:
    import rfc8785
    return rfc8785.dumps(payload)


def _crl_revoked(crl_env: str, issuer_pub: bytes, container_id: str):
    """(verified: bool, revoked: bool, updated_at: str|None) for a signed acv_revocation_list envelope."""
    try:
        env = json.loads(_b64u_decode(crl_env))
        payload = env["payload"]
        sig = _b64u_decode(env["sig"])
    except Exception:  # noqa: BLE001
        return False, False, None
    if payload.get("type") != "acv_revocation_list" or env.get("alg") != "Falcon-1024":
        return False, False, None
    if not _falcon_verify(issuer_pub, _jcs(payload), sig):
        return False, False, None
    return (True, any(r.get("container_id") == container_id for r in payload.get("revoked", [])),
            payload.get("updated_at"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="acv-unseal", description=__doc__)
    ap.add_argument("container", nargs="?", help="path to the .acv container (omit with --genkey)")
    ap.add_argument("--genkey", metavar="PREFIX", default=None,
                    help="generate a recipient ML-KEM-1024 keypair -> <PREFIX>_pk.b64 (send to the "
                         "issuer) + <PREFIX>_sk.b64 (keep private), then exit")
    ap.add_argument("--key", default=None, help="recipient ML-KEM-1024 secret key (base64), or @file")
    ap.add_argument("--recover-share", dest="recover_shares", action="append", default=[],
                    help="a Shamir recovery share (repeat once per share) to open without the recipient key; "
                         "value may be @file")
    ap.add_argument("--revocation-list", dest="crl", default=None,
                    help="signed revocation list (envelope string), or @file")
    ap.add_argument("--out", default="./unsealed", help="output directory")
    ap.add_argument("--expect-issuer", default=None, help="optional: require this issuer_kid (out-of-band pin)")
    ap.add_argument("--max-crl-age-days", type=float, default=None,
                    help="optional: refuse a revocation list older than this many days (recipient freshness)")
    args = ap.parse_args(argv)

    if args.genkey:
        from pqcrypto.kem.ml_kem_1024 import generate_keypair
        pk, sk = generate_keypair()
        with open(args.genkey + "_pk.b64", "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(pk).decode())
        with open(args.genkey + "_sk.b64", "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(sk).decode())
        try:
            os.chmod(args.genkey + "_sk.b64", 0o600)
        except Exception:  # noqa: BLE001
            pass
        print(f"acv-unseal: wrote {args.genkey}_pk.b64 (send this to the issuer so they can seal to you) "
              f"and {args.genkey}_sk.b64 (keep this private; it opens your containers)")
        return 0

    if not args.container:
        _die("no container given (use --genkey to make a keypair, or pass a .acv path)")
    if not args.key and not args.recover_shares:
        _die("provide --key (recipient secret) or one or more --recover-share")

    blob = open(args.container, "rb").read()
    if blob[:len(MAGIC)] != MAGIC:
        _die("not an .acv container (bad magic header)")
    off = len(MAGIC)
    hlen = int.from_bytes(blob[off:off + 4], "big"); off += 4
    header_bytes = blob[off:off + hlen]; off += hlen
    nonce = blob[off:off + NONCE]; off += NONCE
    ct = blob[off:]

    try:
        env = json.loads(_b64u_decode(header_bytes.decode()))
        payload = env["payload"]
        sig = _b64u_decode(env["sig"])
    except Exception as exc:  # noqa: BLE001
        _die(f"malformed header: {exc}")
    if payload.get("type") != "acv_container" or env.get("alg") != "Falcon-1024":
        _die("not an acv_container header")

    issuer_pub = base64.b64decode(payload["issuer_pub_b64"])
    if not _falcon_verify(issuer_pub, _jcs(payload), sig):
        _die("header signature verification FAILED")
    issuer_kid = payload.get("issuer_kid")
    print(f"acv-unseal: header OK  container_id={payload['container_id']}  issuer_kid={issuer_kid}  "
          f"recipient_kid={payload.get('recipient_kid')}  docs={len(payload.get('docs', []))}")
    if args.expect_issuer and args.expect_issuer != issuer_kid:
        _die(f"issuer_kid {issuer_kid} does not match expected {args.expect_issuer}")
    if not args.expect_issuer:
        print(f"acv-unseal: WARNING: issuer identity is NOT pinned. The signature proves this container "
              f"is internally consistent, not WHO issued it. If you were given an issuer fingerprint out "
              f"of band, re-run with --expect-issuer {issuer_kid} to bind the container to it.",
              file=sys.stderr)

    now = datetime.now(timezone.utc)
    if _expired(payload.get("expires_at"), now):
        _die(f"container expired at {payload.get('expires_at')}")

    rev = payload.get("revocation") or {}
    if args.crl is not None:
        verified, revoked, updated_at = _crl_revoked(_load_arg(args.crl), issuer_pub, payload["container_id"])
        if not verified:
            _die("revocation list did not verify against the issuer key")
        min_crl_at = rev.get("min_crl_at")
        if min_crl_at and (updated_at or "") < min_crl_at:
            _die(f"revocation list is stale (updated {updated_at}, container requires {min_crl_at} or "
                 "later); an out-of-date list cannot prove this container was never revoked")
        if args.max_crl_age_days is not None:
            try:
                crl_dt = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except Exception:  # noqa: BLE001
                _die("revocation list has no valid updated_at for the freshness check")
            if (now - crl_dt).total_seconds() > args.max_crl_age_days * 86400:
                _die(f"revocation list is too old (updated {updated_at}); a list within "
                     f"{args.max_crl_age_days} day(s) is required")
        if revoked:
            _die(f"container {payload['container_id']} is REVOKED")
        print("acv-unseal: revocation checked — not revoked")
    elif rev.get("required"):
        _die("this container requires a revocation-list check (--revocation-list) but none was supplied")

    if args.recover_shares:
        shares = [_load_arg(s) for s in args.recover_shares]
        cek = _recover_cek(payload, shares)
        print(f"acv-unseal: recovered content key from {len(shares)} share(s)")
    else:
        sk = base64.b64decode(_load_arg(args.key))
        try:
            cek = _mlkem_unwrap(sk, _b64u_decode(payload["wrapped_cek_b64"]))
        except Exception as exc:  # noqa: BLE001
            _die(f"could not unwrap the content key with this recipient secret: {exc}")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aad = hashlib.sha256(header_bytes).digest()
    try:
        tar_bytes = AESGCM(cek).decrypt(nonce, ct, aad)
    except Exception:  # noqa: BLE001
        _die("payload decryption failed (wrong key or tampered container)")

    os.makedirs(args.out, exist_ok=True)
    out_root = os.path.realpath(args.out)
    by_name = {d["name"]: d for d in payload["docs"]}   # header lists tar ids (opaque or real)
    names_map: dict = {}
    members: dict = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.name == "NAMES.json":
                names_map = json.loads(tf.extractfile(m).read().decode())
            elif m.name.startswith("docs/"):
                members[m.name[len("docs/"):]] = tf.extractfile(m).read()
    written = 0
    for tid, data in members.items():
        if tid not in by_name:
            _die(f"decrypted doc {tid!r} not listed in the signed header")
        if not _safe_name(tid):
            _die(f"unsafe document id (path traversal) refused: {tid!r}")
        if "sha256:" + hashlib.sha256(data).hexdigest() != by_name[tid]["sha256"]:
            _die(f"doc {tid!r} failed integrity check")
        name = names_map.get(tid, tid)                  # restore the real name (opaque mode)
        if not _safe_name(name):
            _die(f"unsafe restored document name refused: {name!r}")
        dest = os.path.join(args.out, name)
        # defense in depth: confirm the resolved path stays under --out even if the name slipped through
        full = os.path.realpath(dest)
        if full != out_root and not full.startswith(out_root + os.sep):
            _die(f"document path escapes the output directory: {name!r}")
        os.makedirs(os.path.dirname(dest), exist_ok=True) if os.path.dirname(dest) != args.out else None
        with open(dest, "wb") as fh:
            fh.write(data)
        written += 1
    print(f"acv-unseal: VERIFIED + unsealed {written} document(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
