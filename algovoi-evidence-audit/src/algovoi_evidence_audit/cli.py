# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
# Copyright (c) 2026 AlgoVoi. All rights reserved.
"""av-audit — batch-verify an archive of signed documents into a signed audit report.

    av-audit keygen [--keys DIR]                          the auditor identity
    av-audit run PATH... [--keys DIR] [--out DIR] [--trust-roots X] [--crl F]
                         [--baseline prev-report.json] [--format html,json,csv]
    av-audit verify REPORT.reseal.json --file audit-report.json   (or use av-reseal-verify)

`run` produces: audit-report.json (findings), audit-report.json.reseal.json
(signed attestation the free verifier checks), audit-report.html, audit-report.csv.
Sealing the report is the licensed action; verification is free.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from algovoi_reseal_verify import verify_artifact, _kid, _b64u_dec
from . import run_audit, sign_report, canonical_report_bytes, LicenseError
from . import report as _report
from .signer import generate_keys, load_keys

_DEFAULT_KEYS = os.path.join(os.path.expanduser("~"), ".algovoi-audit")


def _load_trust(trust_roots, crl):
    roots = None
    if trust_roots:
        roots = []
        src = trust_roots
        paths = ([os.path.join(src, f) for f in sorted(os.listdir(src))]
                 if os.path.isdir(src) else [src])
        for p in paths:
            try:
                raw = open(p, "rb").read()
            except OSError:
                continue
            try:
                for c in x509.load_pem_x509_certificates(raw):
                    roots.append(c.public_bytes(Encoding.DER))
            except Exception:  # noqa: BLE001
                try:
                    roots.append(x509.load_der_x509_certificate(raw).public_bytes(Encoding.DER))
                except Exception:  # noqa: BLE001
                    pass
        roots = roots or None
    crl_bytes = open(crl, "rb").read() if crl else None
    return roots, crl_bytes


def _cmd_keygen(args) -> int:
    try:
        info = generate_keys(args.keys, mldsa_alg=f"ML-DSA-{args.mldsa_level}")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"auditor keys: {info['path']} (mode 0600)")
    print(f"falcon kid:  {info['falcon_kid']}")
    return 0


def _cmd_run(args) -> int:
    if not os.path.exists(os.path.join(args.keys, "audit-keys.json")):
        print(f"no auditor keys in {args.keys}; run: av-audit keygen --keys {args.keys}", file=sys.stderr)
        return 2
    keys = load_keys(args.keys)
    roots, crl = _load_trust(args.trust_roots, args.crl)
    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(open(args.baseline, encoding="utf-8").read())
        except (OSError, ValueError) as exc:
            print(f"cannot read baseline: {exc}", file=sys.stderr)
            return 2

    try:
        report = run_audit(args.paths, trust_roots_der=roots, crl_bytes=crl, baseline=baseline,
                           expected_kid=getattr(args, "expect_kid", None))
        report_bytes, artifact = sign_report(report, keys)   # both licence-gated
    except LicenseError as exc:
        print(f"auditing an archive requires an AlgoVoi licence: {exc}\n"
              f"(single-document verification is free: pip install algovoi-reseal-verify)",
              file=sys.stderr)
        return 2

    out = args.out or "."
    os.makedirs(out, exist_ok=True)
    fmts = set((args.format or "html,json,csv").split(","))
    with open(os.path.join(out, "audit-report.json"), "wb") as fh:
        fh.write(report_bytes)
    with open(os.path.join(out, "audit-report.json.reseal.json"), "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2, sort_keys=True)
    kid = _kid(_b64u_dec(keys["falcon_pk"]))
    if "html" in fmts:
        open(os.path.join(out, "audit-report.html"), "w", encoding="utf-8").write(
            _report.to_html(report, attestation_kid=kid))
    if "csv" in fmts:
        open(os.path.join(out, "audit-report.csv"), "w", encoding="utf-8", newline="").write(
            _report.to_csv(report))

    s = report["summary"]
    print(f"audited {s['total']} documents: {s['verified']} verified, {s['invalid']} invalid, "
          f"{s['unsigned']} unsigned, {s['quantum_exposed']} quantum-exposed")
    print(f"report: {os.path.join(out, 'audit-report.json')} (signed, kid {kid})")
    return 0


def _cmd_verify(args) -> int:
    try:
        artifact = json.loads(open(args.artifact, encoding="utf-8").read())
    except (OSError, ValueError) as exc:
        print(f"cannot read report attestation: {exc}", file=sys.stderr)
        return 2
    fb = open(args.file, "rb").read() if args.file else None
    rep = verify_artifact(artifact, file_bytes=fb, expected_kid=args.expect_kid)
    ok = rep.get("ok")
    if ok and args.expect_kid:
        print("report VERIFIED and anchored")
        return 0
    if ok:
        print("report VERIFIED (pin --expect-kid to anchor the auditor)")
        return 3
    print("report VERIFICATION FAILED")
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="av-audit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="generate the auditor identity")
    s.add_argument("--keys", default=_DEFAULT_KEYS)
    s.add_argument("--mldsa-level", choices=["65", "87"], default="65")
    s.set_defaults(fn=_cmd_keygen)

    s = sub.add_parser("run", help="audit an archive of signed documents")
    s.add_argument("paths", nargs="+")
    s.add_argument("--keys", default=_DEFAULT_KEYS)
    s.add_argument("--out", default=None)
    s.add_argument("--trust-roots", default=None)
    s.add_argument("--crl", default=None)
    s.add_argument("--baseline", default=None, help="a prior audit-report.json to diff against")
    s.add_argument("--format", default="html,json,csv")
    s.add_argument("--expect-kid", default=None,
                   help="pin a reseal signer kid; only .reseal.json attestations anchored to it "
                        "(and bound to their subject) count as verified")
    s.set_defaults(fn=_cmd_run)

    s = sub.add_parser("verify", help="verify a signed audit report")
    s.add_argument("artifact")
    s.add_argument("--file", default=None, help="the audit-report.json the attestation covers")
    s.add_argument("--expect-kid", default=None)
    s.set_defaults(fn=_cmd_verify)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
