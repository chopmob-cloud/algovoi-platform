#!/usr/bin/env python3
"""Validate an RFC 9421 verifier against rfc9421_hardening_v1.json.

Usage:
    python validate_vectors.py <vectors.json> <import.path.to.verify_request>

Example:
    python validate_vectors.py rfc9421_hardening_v1.json substrate2.rfc9421_verifier:verify_request

For each vector it calls verify_request and compares result.valid to the expected
verdict (and, when given, that an expected substring appears in the errors). It
introspects the target's signature: a vector whose policy needs a kwarg the target
does not accept is reported UNSUPPORTED (not a failure) — this is how the parity
matrix distinguishes "wrong verdict" from "control not implemented".

Exit code 0 iff every supported vector matched its expected verdict.
"""
from __future__ import annotations

import importlib
import inspect
import json
import sys


def load_verifier(spec: str):
    mod_name, _, attr = spec.partition(":")
    attr = attr or "verify_request"
    mod = importlib.import_module(mod_name)
    fn = getattr(mod, attr)
    params = set(inspect.signature(fn).parameters)
    return fn, params


def run(vectors_path: str, spec: str) -> int:
    doc = json.loads(open(vectors_path, encoding="utf-8").read())
    verify_request, supported = load_verifier(spec)
    pubkey = doc["public_key_hex"]

    rows = []
    fails = 0
    supported_count = 0
    for v in doc["vectors"]:
        http = v["http"]
        args = dict(v.get("verify_args", {}))
        requires = args.pop("__requires_kwarg__", None)
        nonce_flag = args.pop("__nonce_seen__", None)

        # Skip vectors whose control depends on a kwarg this impl lacks.
        if requires and requires not in supported:
            rows.append((v["id"], "UNSUPPORTED", f"needs kwarg {requires!r}"))
            continue

        kwargs = dict(
            method=http["method"], authority=http["authority"], path=http["path"],
            headers=dict(http["headers"]), body=bytes.fromhex(http["body_hex"]),
            public_key=pubkey,
        )
        if "scheme" in supported:
            kwargs["scheme"] = http.get("scheme", "https")
        # allowed_algorithms wants a set/frozenset
        if "allowed_algorithms" in args:
            args["allowed_algorithms"] = frozenset(args["allowed_algorithms"])
        if nonce_flag == "replayed":
            if "nonce_seen" not in supported:
                rows.append((v["id"], "UNSUPPORTED", "needs kwarg 'nonce_seen'"))
                continue
            kwargs["nonce_seen"] = lambda n, k: True
        # Drop any remaining policy kwargs the target does not accept.
        dropped = [k for k in args if k not in supported]
        for k in list(args):
            if k in supported:
                kwargs[k] = args[k]
            else:
                args.pop(k)

        try:
            res = verify_request(**kwargs)
            got_valid = bool(getattr(res, "valid"))
            errors = [str(e).lower() for e in getattr(res, "errors", [])]
        except Exception as exc:  # a hardened verifier may raise on some malformed input
            got_valid = False
            errors = [f"exception: {exc}".lower()]

        exp = v["expect"]
        ok = got_valid == exp["valid"]
        reason = exp.get("reason_contains")
        supported_count += 1
        if not ok:
            # Verdict mismatch is the only hard failure: the corpus asserts the
            # accept/reject verdict, which every conformant verifier must agree on.
            fails += 1
            rows.append((v["id"], "FAIL", f"expected valid={exp['valid']}, got {got_valid}"))
            continue
        note = ""
        # reason_contains is advisory: two verifiers may reject the same vector at
        # different layers (early parse-reject vs late signature-fail). Report drift
        # without failing, so the matrix shows real verdict divergence only.
        if not exp["valid"] and reason and not any(reason.lower() in e for e in errors):
            note = f"reason drift (no {reason!r}): {errors}"
        if dropped:
            note = (note + f" (dropped {dropped})").strip()
        rows.append((v["id"], "PASS", note))

    width = max(len(r[0]) for r in rows)
    print(f"\n=== {doc['name']} vs {spec} ===")
    for vid, status, note in rows:
        print(f"  {vid.ljust(width)}  {status:<12} {note}")
    n = len(doc["vectors"])
    unsupported = sum(1 for _, s, _ in rows if s == "UNSUPPORTED")
    print(f"\n  {supported_count - fails}/{supported_count} supported vectors matched; "
          f"{unsupported} unsupported; {fails} failed; {n} total")
    return 1 if fails else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(run(sys.argv[1], sys.argv[2]))
