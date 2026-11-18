# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
# Copyright (c) 2026 AlgoVoi. All rights reserved.
"""av-reseal — quantum-seal the signed documents you already have.

Commands:
    av-reseal inspect FILE...                    what classical evidence is there, and how exposed is it
    av-reseal keygen  [--keys DIR]               generate your Falcon-1024 + ML-DSA-65 identity
    av-reseal seal    FILE... [--keys DIR] [--tsa URL | --no-tsa] [--out DIR]
    av-reseal verify  ARTIFACT [--file ORIGINAL]

``inspect`` is free-standing triage: it names every classical signature in the
file, whether it verifies TODAY, and when its provability dies. ``seal`` is the
rescue: it binds today's verification into a post-quantum, RFC 3161 timestamped
attestation that verifies offline, forever. Batch seals are hash-linked and the
chain head carries the one TSA stamp, transparency-log style.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import (build_attestation_payload, seal_payload, attach_rfc3161,
               verify_artifact, generate_keys, load_keys, _prefixed, LicenseError)
from algovoi_reseal_verify.tsa import DEFAULT_TSA

_DEFAULT_KEYS = os.path.join(os.path.expanduser("~"), ".algovoi-reseal")


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


_SIG_EXTS = (".p7s", ".p7m")


def _load_trust(args) -> tuple[list[bytes] | None, bytes | None]:
    """Load optional trust roots (a dir or file of PEM/DER certs) and a CRL."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    roots: list[bytes] | None = None
    if getattr(args, "trust_roots", None):
        roots = []
        src = args.trust_roots
        paths = ([os.path.join(src, f) for f in sorted(os.listdir(src))]
                 if os.path.isdir(src) else [src])
        for p in paths:
            try:
                raw = _read(p)
            except OSError:
                continue
            try:
                for c in x509.load_pem_x509_certificates(raw):
                    roots.append(c.public_bytes(Encoding.DER))
            except Exception:  # noqa: BLE001 - try DER
                try:
                    roots.append(x509.load_der_x509_certificate(raw)
                                 .public_bytes(Encoding.DER))
                except Exception:  # noqa: BLE001
                    print(f"warning: could not parse cert(s) in {p}", file=sys.stderr)
        if not roots:
            print(f"warning: no usable certs in {src}; trust path stays unchecked",
                  file=sys.stderr)
            roots = None
    crl = _read(args.crl) if getattr(args, "crl", None) else None
    return roots, crl


def _resolve_pairs(paths: list[str]) -> list[tuple[str, str | None]]:
    """Pair each subject file with a sibling detached signature.

    ``X.p7s`` next to ``X`` collapses into one (X, X.p7s) entry whichever of
    the two was named; a .p7s with no sibling stays its own subject so the
    detached-CMS honesty note surfaces instead of a silent skip.
    """
    out: list[tuple[str, str | None]] = []
    claimed_sigs: set[str] = set()
    for p in paths:
        if p.lower().endswith(_SIG_EXTS):
            base = p[:p.rfind(".")]
            if os.path.exists(base):
                claimed_sigs.add(p)
                if base not in paths:
                    out.append((base, p))
                continue
            out.append((p, None))
        else:
            sib = next((p + e for e in _SIG_EXTS if os.path.exists(p + e)), None)
            if sib:
                claimed_sigs.add(sib)
            out.append((p, sib))
    return [(s, g) for s, g in out if s not in claimed_sigs]


def _cmd_inspect(args) -> int:
    worst = 0
    roots, crl = _load_trust(args)
    for path, sig_path in _resolve_pairs(args.files):
        payload = build_attestation_payload(
            _read(path), path,
            detached_sig_bytes=_read(sig_path) if sig_path else None,
            trust_roots_der=roots, crl_bytes=crl)
        if sig_path:
            print(f"\n[paired with {sig_path}]", end="")
        c = payload["classical"]
        print(f"\n{path}")
        print(f"  sha256: {payload['subject']['sha256']}")
        if not c["present"]:
            print(f"  no classical signature ({c.get('note', c['carrier'])})")
            continue
        for i, s in enumerate(c["signatures"]):
            v = "VERIFIES today" if s.get("verified") else f"DOES NOT verify ({s.get('error', 'see checks')})"
            print(f"  signature[{i}] {s.get('signature_algorithm', '?')}: {v}")
            if s.get("weak_digest"):
                print("    WEAK DIGEST: SHA-1 collisions are practical; treat this as weak evidence.")
            if s.get("covers_entire_file") is False:
                print(f"    PARTIAL COVERAGE: {s.get('coverage_note')}")
            if "trust_path" in s:
                tp = "chains to a trusted root" if s["trust_path"]["ok"] else "NO path to a trusted root"
                print(f"    trust path: {tp}")
            if "revocation" in s:
                rv = s["revocation"]
                msg = ("REVOKED " + rv.get("revoked_at", "") if rv.get("revoked")
                       else ("not revoked" if rv.get("ok") else "revocation inconclusive"))
                print(f"    revocation: {msg}")
            if s.get("signer_subject"):
                print(f"    signer: {s['signer_subject']}")
            if s.get("claimed_signing_time"):
                print(f"    claimed signing time: {s['claimed_signing_time']}")
            if s.get("quantum_vulnerable"):
                print("    QUANTUM-VULNERABLE: this signature is forgeable by a quantum adversary.")
                print("    Once that happens the original cannot be told apart from a tamper.")
                print("    It can only be rescued while it still verifies: av-reseal seal")
            if not s.get("verified"):
                worst = 1
    print()
    return worst


_PROFILES = {
    "65": ("Compact (NIST L3)", "Falcon-1024 + ML-DSA-65", "smaller seals, estate-standard"),
    "87": ("Matched (NIST L5)", "Falcon-1024 + ML-DSA-87", "both signatures at L5, ~1.3 KB larger"),
}


def _cmd_keygen(args) -> int:
    mldsa_alg = f"ML-DSA-{args.mldsa_level}"
    try:
        info = generate_keys(args.keys, mldsa_alg=mldsa_alg)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    name, pair, note = _PROFILES[args.mldsa_level]
    other = "87" if args.mldsa_level == "65" else "65"
    print(f"keys written: {info['path']} (mode 0600)")
    print(f"profile:     {name} - {pair} ({note})")
    print(f"falcon kid:  {info['falcon_kid']}")
    print(f"{info['mldsa_alg'].lower()} kid: {info['mldsa_kid']}")
    print(f"(the other profile is available with --mldsa-level {other}: "
          f"{_PROFILES[other][0]}, {_PROFILES[other][1]})")
    return 0


def _cmd_seal(args) -> int:
    if not os.path.exists(os.path.join(args.keys, "reseal-keys.json")):
        print(f"no keys in {args.keys}; run: av-reseal keygen --keys {args.keys}", file=sys.stderr)
        return 2
    keys = load_keys(args.keys)
    out_dir = args.out or "."
    os.makedirs(out_dir, exist_ok=True)

    roots, crl = _load_trust(args)
    prev = None
    artifacts = []
    for path, sig_path in _resolve_pairs(args.files):
        payload = build_attestation_payload(
            _read(path), path, prev_entry_hash=prev,
            detached_sig_bytes=_read(sig_path) if sig_path else None,
            trust_roots_der=roots, crl_bytes=crl)
        prev = _prefixed(payload)
        try:
            artifacts.append((path, seal_payload(payload, keys)))
        except LicenseError as exc:
            print(f"sealing requires an AlgoVoi licence: {exc}", file=sys.stderr)
            return 2

    # One TSA stamp on the chain head proves existence for every link beneath it.
    if not args.no_tsa:
        try:
            attach_rfc3161(artifacts[-1][1], args.tsa)
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: RFC 3161 stamp failed ({exc}); seals written UNSTAMPED. "
                  f"Re-run with a reachable TSA or accept self-asserted time.", file=sys.stderr)

    for path, artifact in artifacts:
        dest = os.path.join(out_dir, os.path.basename(path) + ".reseal.json")
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2, sort_keys=True)
        stamped = "stamped" if artifact.get("rfc3161") else "chained"
        print(f"sealed [{stamped}]: {dest}")
    return 0


def _cmd_verify(args) -> int:
    """Exit codes mirror the estate free-verifier: 0 verified AND anchored to
    --expect-kid; 1 failed; 2 malformed/usage; 3 intact but self-asserted."""
    try:
        artifact = json.loads(_read(args.artifact))
    except (OSError, ValueError) as exc:
        print(f"cannot read artifact: {exc}", file=sys.stderr)
        return 2
    if not isinstance(artifact, dict):
        print("cannot read artifact: not a JSON object", file=sys.stderr)
        return 2
    file_bytes = _read(args.file) if args.file else None
    tsa_roots, _ = _load_trust(argparse.Namespace(trust_roots=args.tsa_roots, crl=None))
    report = verify_artifact(artifact, file_bytes=file_bytes,
                             expected_kid=args.expect_kid, tsa_roots_der=tsa_roots)
    if report.get("error"):
        print(f"VERIFICATION FAILED: {report['error']}")
        return 1
    for c in report["checks"]:
        mark = {True: "ok", False: "FAIL", None: "skip"}[c.get("ok")]
        extra = c.get("gen_time") or c.get("note") or c.get("error") or ""
        # An RFC 3161 token is only a trustworthy TIME if its TSA is anchored.
        # Never present an unanchored genTime as authoritative - it is
        # attacker-settable (a self-signed TSA cert forges any genTime).
        if c["check"] == "rfc3161_token" and report.get("tsa_anchored") is not True:
            extra = (f"{c.get('gen_time', '')}  [UNANCHORED TIME - not independently "
                     f"verified; pin --tsa-roots to trust genTime]")
        print(f"  {c['check']}: {mark}  {extra}")
    if report.get("payload"):
        subj = report["payload"]["subject"]
        print(f"  subject: {subj.get('filename')} sha256:{str(subj.get('sha256'))[:16]}…")
    if not report["ok"]:
        print("VERIFICATION FAILED")
        return 1
    if args.expect_kid:
        print("VERIFIED and anchored")
        return 0
    print("VERIFIED (cryptographically intact - but the signing key is self-asserted;")
    print("pin the sealer's published kid and pass --expect-kid to anchor authenticity)")
    return 3


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="av-reseal", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("inspect", help="triage classical signatures and quantum exposure")
    s.add_argument("files", nargs="+")
    s.add_argument("--trust-roots", default=None,
                   help="dir or file of trusted root certs (PEM/DER); enables offline chain validation")
    s.add_argument("--crl", default=None, help="offline CRL (PEM/DER) for revocation check")
    s.set_defaults(fn=_cmd_inspect)

    s = sub.add_parser("keygen", help="generate a post-quantum signing identity")
    s.add_argument("--keys", default=_DEFAULT_KEYS)
    s.add_argument("--mldsa-level", choices=["65", "87"], default="65",
                   help="second signature level: 65 = ML-DSA-65 (NIST L3, default), "
                        "87 = ML-DSA-87 (NIST L5, matches Falcon-1024)")
    s.set_defaults(fn=_cmd_keygen)

    s = sub.add_parser("seal", help="seal files into PQ attestations (batch = hash-linked chain)")
    s.add_argument("files", nargs="+")
    s.add_argument("--keys", default=_DEFAULT_KEYS)
    s.add_argument("--tsa", default=DEFAULT_TSA)
    s.add_argument("--no-tsa", action="store_true", help="air-gapped: skip the network timestamp")
    s.add_argument("--trust-roots", default=None,
                   help="dir or file of trusted root certs (PEM/DER); records chain validation in the seal")
    s.add_argument("--crl", default=None, help="offline CRL (PEM/DER) for revocation check")
    s.add_argument("--out", default=None)
    s.set_defaults(fn=_cmd_seal)

    s = sub.add_parser("verify", help="verify a .reseal.json artifact offline")
    s.add_argument("artifact")
    s.add_argument("--file", default=None, help="original file, to re-derive the subject hash")
    s.add_argument("--expect-kid", default=None,
                   help="the sealer's published Falcon kid; anchors authenticity (exit 0 vs 3)")
    s.add_argument("--tsa-roots", default=None,
                   help="dir or file of trusted TSA root certs; anchors the RFC-3161 time (fail-closed)")
    s.set_defaults(fn=_cmd_verify)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
