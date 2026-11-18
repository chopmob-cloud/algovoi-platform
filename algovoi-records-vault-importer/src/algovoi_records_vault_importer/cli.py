"""Command-line interface for the AlgoVoi Records Vault volume importer.

Wraps :func:`import_records_fs` so an operator imports a document estate from a designated folder with
one command: resumable (checkpoint), idempotent (skip_existing dedups by content), batch-signed (Merkle
root per batch, or one Falcon-1024 signature per document). Also verifies a single document against a
signed batch envelope. Commercial add-on to Records Vault; runtime-licensed, fail-closed.

    algovoi-rv-import import <source_dir> --archive <archive_dir> --keys-dir <keys_dir> \
        --strategy merkle --mode bridge --batch-size 1000 --checkpoint <path> --progress
    algovoi-rv-import verify --doc-sha <sha256> --batch-envelope <b64u> --public-key <pk_file>
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from algovoi_records_vault_importer import STRATEGIES, __version__, import_records_fs, verify_document_in_batch, watch

_MODES = ("bridge", "store")


def _load_or_create_keys(keys_dir: str):
    """Load a persistent Falcon + ML-KEM keypair from ``keys_dir`` (create + persist if absent).

    Keys are persisted so re-runs dedup and remain offline-verifiable; ephemeral keys would make a
    later batch unverifiable. Secret keys are written 0600 where the OS supports it.
    """
    from algovoi_doc_archive import signing
    from algovoi_doc_archive.encryption import generate_mlkem_keypair

    os.makedirs(keys_dir, exist_ok=True)
    paths = {k: os.path.join(keys_dir, f"{k}.key") for k in ("falcon_pk", "falcon_sk", "mlkem_pk", "mlkem_sk")}
    if all(os.path.exists(p) for p in paths.values()):
        keys = {k: open(p, "rb").read() for k, p in paths.items()}
        return keys["falcon_pk"], keys["falcon_sk"], keys["mlkem_pk"], keys["mlkem_sk"]
    pk, sk = signing.generate_keypair()
    kp, ks = generate_mlkem_keypair()
    for name, blob in (("falcon_pk", pk), ("falcon_sk", sk), ("mlkem_pk", kp), ("mlkem_sk", ks)):
        with open(paths[name], "wb") as fh:
            fh.write(blob)
    for secret in ("falcon_sk", "mlkem_sk"):
        try:
            os.chmod(paths[secret], 0o600)
        except OSError:
            pass
    return pk, sk, kp, ks


def _open_archive(archive_dir: str, keys_dir: str):
    from algovoi_doc_archive.archive import Archive
    from algovoi_doc_archive.backend import LocalFsBackend
    from algovoi_doc_archive.encryption import HybridPqcEncryptor

    pk, sk, kp, ks = _load_or_create_keys(keys_dir)
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(archive_dir),
                      encryptor=HybridPqcEncryptor(kp, ks))
    return archive, pk


def _progress(r) -> None:
    sys.stderr.write(f"\r  {r.committed}/{r.total} committed | {r.skipped} skipped | "
                     f"{r.batches} batches | {r.docs_per_sec:.0f} docs/s")
    sys.stderr.flush()


def cmd_import(args: argparse.Namespace) -> int:
    if not os.path.isdir(args.source):
        print(f"error: source is not a directory: {args.source}", file=sys.stderr)
        return 2
    archive, pk = _open_archive(args.archive, args.keys_dir)
    result = asyncio.run(import_records_fs(
        archive, args.source, strategy=args.strategy, mode=args.mode, batch_size=args.batch_size,
        workers=args.workers, skip_existing=not args.no_skip, checkpoint_path=args.checkpoint,
        progress=_progress if args.progress else None))
    if args.progress:
        sys.stderr.write("\n")
    out = {
        "strategy": result.strategy, "source": result.source, "mode": result.mode,
        "total": result.total, "committed": result.committed, "skipped": result.skipped,
        "batches": result.batches, "signatures": result.signatures,
        "docs_per_sec": round(result.docs_per_sec, 1),
        "started_at": result.started_at, "finished_at": result.finished_at,
        "public_key_bytes": len(pk),
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    if not os.path.isdir(args.source):
        print(f"error: source is not a directory: {args.source}", file=sys.stderr)
        return 2
    archive, _pk = _open_archive(args.archive, args.keys_dir)

    def _on_cycle(r) -> None:
        if r.committed:
            sys.stderr.write(f"  cycle: committed {r.committed} in {r.batches} batch(es) | "
                             f"{r.skipped} skipped | {r.docs_per_sec:.0f} docs/s\n")
            sys.stderr.flush()

    def _on_error(exc: Exception) -> None:
        sys.stderr.write(f"  cycle error (continuing): {exc}\n")
        sys.stderr.flush()

    stopped = {"v": False}
    try:
        import signal
        signal.signal(signal.SIGINT, lambda *_a: stopped.__setitem__("v", True))
        signal.signal(signal.SIGTERM, lambda *_a: stopped.__setitem__("v", True))
    except (ValueError, OSError):
        pass  # not the main thread; caller drives stop another way

    n = asyncio.run(watch(
        archive, args.source, strategy=args.strategy, mode=args.mode, batch_size=args.batch_size,
        workers=args.workers, checkpoint_path=args.checkpoint, poll_secs=args.poll_secs,
        quiescent_secs=args.quiescent_secs, on_cycle=_on_cycle, on_error=_on_error,
        stop=lambda: stopped["v"]))
    print(json.dumps({"committing_cycles": n, "source": args.source}, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    pk = open(args.public_key, "rb").read()
    ok = verify_document_in_batch(args.doc_sha, args.batch_envelope, pk)
    print(json.dumps({"doc_sha": args.doc_sha, "verified": bool(ok)}, indent=2))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="algovoi-rv-import",
                                description="AlgoVoi Records Vault volume importer (folder -> signed archive).")
    p.add_argument("--version", action="version", version=f"algovoi-rv-import {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import", help="import a document estate from a source folder")
    imp.add_argument("source", help="source directory to import (walked recursively)")
    imp.add_argument("--archive", required=True, help="archive output directory")
    imp.add_argument("--keys-dir", required=True, help="directory holding/creating the Falcon + ML-KEM keys")
    imp.add_argument("--strategy", choices=STRATEGIES, default="merkle", help="merkle (batch) or falcon (per-doc)")
    imp.add_argument("--mode", choices=_MODES, default="bridge", help="bridge (hash-only) or store (encrypt+store)")
    imp.add_argument("--batch-size", type=int, default=1000, help="documents per Merkle batch (merkle strategy)")
    imp.add_argument("--workers", type=int, default=8, help="parallel hashing workers")
    imp.add_argument("--checkpoint", default=None, help="checkpoint file for resumable imports")
    imp.add_argument("--no-skip", action="store_true", help="do not skip records already in the archive")
    imp.add_argument("--progress", action="store_true", help="stream progress to stderr")
    imp.set_defaults(func=cmd_import)

    wat = sub.add_parser("watch", help="continuously import a quiescent drop folder until stopped")
    wat.add_argument("--source", required=True, help="drop folder to watch (an access-controlled ingest path)")
    wat.add_argument("--archive", required=True, help="archive output directory")
    wat.add_argument("--keys-dir", required=True, help="directory holding/creating the Falcon + ML-KEM keys")
    wat.add_argument("--strategy", choices=STRATEGIES, default="merkle", help="merkle (batch) or falcon (per-doc)")
    wat.add_argument("--mode", choices=_MODES, default="bridge", help="bridge (hash-only) or store (encrypt+store)")
    wat.add_argument("--batch-size", type=int, default=1000, help="documents per Merkle batch (merkle strategy)")
    wat.add_argument("--workers", type=int, default=8, help="parallel hashing workers")
    wat.add_argument("--checkpoint", default=None, help="checkpoint file for resumable imports")
    wat.add_argument("--poll-secs", type=float, default=10.0, help="seconds between folder polls")
    wat.add_argument("--quiescent-secs", type=float, default=5.0,
                     help="seconds of no size change before a cycle runs (complete-file safety)")
    wat.set_defaults(func=cmd_watch)

    ver = sub.add_parser("verify", help="verify a document sha against a signed batch envelope")
    ver.add_argument("--doc-sha", required=True, help="the document sha256 (hex)")
    ver.add_argument("--batch-envelope", required=True, help="the signed batch envelope (b64u)")
    ver.add_argument("--public-key", required=True, help="file holding the Falcon public key bytes")
    ver.set_defaults(func=cmd_verify)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
