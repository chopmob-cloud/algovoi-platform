"""
Recovery CLI — Shamir k-of-n threshold custody for an archive's master secret.

    # split the archive secret into a non-secret envelope + n SLIP-39 shares (k to recover)
    python -m algovoi_doc_archive.recovery_cli split \
        --archive-sk ./keys/archive.sk --archive-pk ./keys/archive.pub \
        -k 2 -n 3 [--support] \
        [--sign-sk ./keys/falcon.sk --sign-pub ./keys/falcon.pub] \
        --out ./recovery-envelope.json --shares-out ./recovery-shares.txt

    python -m algovoi_doc_archive.recovery_cli inspect ./recovery-envelope.json
    python -m algovoi_doc_archive.recovery_cli verify  ./recovery-envelope.json --signer-pub ./keys/falcon.pub

    # recover: supply >= k shares (one SLIP-39 mnemonic per line)
    python -m algovoi_doc_archive.recovery_cli recover ./recovery-envelope.json \
        --shares-file ./my-shares.txt [--signer-pub ./keys/falcon.pub] --out ./recovered-archive.sk

    # AlgoVoi-side only (offline support secret): emit AlgoVoi's single share to contribute
    python -m algovoi_doc_archive.recovery_cli algovoi-share ./recovery-envelope.json --support-sk ./hsm/support.sk

Key files are base64url text. SHARES ARE SECRET — distribute them to separate custodians; any k of
them reconstruct the archive. The envelope is NOT secret (useless without k shares).
"""
from __future__ import annotations

import argparse
import json
import sys

from algovoi_doc_archive import recovery, signing


def _read_key(path: str) -> bytes:
    with open(path, encoding="utf-8") as fh:
        return signing.b64u_decode(fh.read().strip())


def _write_key(path: str, raw: bytes) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(signing.b64u_encode(raw))


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _cmd_split(args) -> int:
    sign_sk = _read_key(args.sign_sk) if args.sign_sk else None
    sign_pk = _read_key(args.sign_pub) if args.sign_pub else None
    env, shares = recovery.split_recovery(
        master_secret=_read_key(args.archive_sk),
        archive_public_key=_read_key(args.archive_pk),
        threshold_k=args.k,
        total_n=args.n,
        include_algovoi_support=args.support,
        sign_secret_key=sign_sk,
        sign_public_key=sign_pk,
        note=args.note or "",
    )
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=2, sort_keys=True)
    with open(args.shares_out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(shares) + "\n")
    print(f"envelope written: {args.out}")
    print(f"client shares written: {args.shares_out}  ({len(shares)} share(s), threshold k={args.k} of n={args.n})")
    if args.support:
        fp = env.get("algovoi_support_share", {}).get("fingerprint", "?")
        print(
            f"support-assisted: AlgoVoi holds ONE share (embedded in the envelope, fingerprint {fp}). "
            "One share recovers nothing; support can contribute it on a verified request but cannot "
            "recover alone."
        )
    else:
        print("self-custody only - AlgoVoi holds nothing. Distribute the shares to separate custodians.")
    return 0


def _cmd_inspect(args) -> int:
    e = _load(args.envelope)
    print(json.dumps({
        "version": e.get("version"),
        "scheme": e.get("scheme"),
        "threshold_k": e.get("threshold_k"),
        "total_n": e.get("total_n"),
        "support_assisted": e.get("support_assisted"),
        "algovoi_share_fingerprint": e.get("algovoi_support_share", {}).get("fingerprint"),
        "signed": "signature_b64" in e,
        "signer_kid": e.get("signer_kid"),
        "note": e.get("note"),
    }, indent=2))
    return 0


def _cmd_verify(args) -> int:
    ok = recovery.verify_envelope(_load(args.envelope), _read_key(args.signer_pub))
    print("signature: VALID" if ok else "signature: INVALID")
    return 0 if ok else 1


def _read_shares(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip()]


def _cmd_recover(args) -> int:
    shares = list(args.share or [])
    if args.shares_file:
        shares += _read_shares(args.shares_file)
    if not shares:
        print("provide shares via --shares-file and/or repeated --share", file=sys.stderr)
        return 2
    verify_pub = _read_key(args.signer_pub) if args.signer_pub else None
    try:
        master = recovery.recover_from_shares(
            envelope=_load(args.envelope), shares=shares, verify_public_key=verify_pub
        )
    except recovery.RecoveryError as exc:
        print(f"recovery failed: {exc}", file=sys.stderr)
        return 1
    _write_key(args.out, master)
    print(f"recovered archive master secret -> {args.out}")
    print("rebuild: HybridPqcEncryptor(archive_pub, <this secret>) to decrypt stored documents.")
    return 0


def _cmd_algovoi_share(args) -> int:
    try:
        m = recovery.algovoi_share_mnemonic(_load(args.envelope), _read_key(args.support_sk))
    except recovery.RecoveryError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 1
    print(m)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="algovoi-recovery", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("split", help="split an archive master secret into envelope + k-of-n shares")
    s.add_argument("--archive-sk", required=True)
    s.add_argument("--archive-pk", required=True)
    s.add_argument("-k", type=int, required=True, help="recovery threshold (>=2)")
    s.add_argument("-n", type=int, required=True, help="total shares (>=k)")
    s.add_argument("--support", action="store_true", help="AlgoVoi holds ONE share (opt-in)")
    s.add_argument("--sign-sk")
    s.add_argument("--sign-pub")
    s.add_argument("--note", default="")
    s.add_argument("--out", required=True)
    s.add_argument("--shares-out", required=True)
    s.set_defaults(func=_cmd_split)

    i = sub.add_parser("inspect", help="print an envelope's parameters")
    i.add_argument("envelope")
    i.set_defaults(func=_cmd_inspect)

    v = sub.add_parser("verify", help="verify an envelope's Falcon signature")
    v.add_argument("envelope")
    v.add_argument("--signer-pub", required=True)
    v.set_defaults(func=_cmd_verify)

    r = sub.add_parser("recover", help="recover the master secret from >= k shares")
    r.add_argument("envelope")
    r.add_argument("--share", action="append", help="a SLIP-39 mnemonic (repeatable)")
    r.add_argument("--shares-file", help="file with one SLIP-39 mnemonic per line")
    r.add_argument("--signer-pub")
    r.add_argument("--out", required=True)
    r.set_defaults(func=_cmd_recover)

    a = sub.add_parser("algovoi-share", help="(AlgoVoi-side) emit AlgoVoi's single share to contribute")
    a.add_argument("envelope")
    a.add_argument("--support-sk", required=True)
    a.set_defaults(func=_cmd_algovoi_share)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
