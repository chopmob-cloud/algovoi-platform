"""
Section 9 — CAIP-2/10/19 identifier grammar (caip_edge_v1).

Every vector is an ACCEPT or REJECT verdict on one identifier, fed to substrate2.caip.
Inputs arrive base64-encoded because several of them carry bytes that do not survive a
round-trip through a JSON string reader unchanged (trailing newlines, NUL, U+2028), and
those are precisely the vectors with teeth.

Why this is not section 1: a CAIP identifier is not canonicalised here, it is *validated*.
Section 1's generic reader looks for an input object plus published canonical bytes and
would skip all 102 of these, reporting nothing. The set is registered in the manifest with
a fixture_type so section 1 passes over it cleanly and this section owns it.

What it protects: the identifier ends up inside a canonicalised, content-addressed record,
so a validator that accepts "eip155:1\\n" lets a record be built whose bytes differ from
the clean identifier on the verifying side. The digest then stops recomputing and the
receipt is unverifiable. The vectors pin the ``\\A``/``\\Z`` anchor discipline that prevents
it, which a ``^``/``$`` implementation fails.
"""
from __future__ import annotations

import base64
import json

from .._paths import vector_set_path

_SET = "caip_edge_v1"


def run() -> tuple[bool, str]:
    from substrate2 import caip

    path = vector_set_path(_SET, f"{_SET}.json")
    if not path.exists():
        return False, f"{_SET} not bundled (looked in {path.parent})"

    validators = {
        "caip2": caip.is_caip2,
        "caip10": caip.is_caip10,
        "caip19": caip.is_caip19,
    }

    data = json.loads(path.read_text(encoding="utf-8"))
    vectors = data.get("vectors", [])

    fails: list[str] = []
    passed = 0
    by_family: dict[str, int] = {}

    for vec in vectors:
        vid = vec.get("vector_id", "?")
        kind = vec.get("kind")
        fn = validators.get(kind)
        if fn is None:
            fails.append(f"{vid}: unknown kind {kind!r}")
            continue

        raw = base64.b64decode(vec["input_b64"])
        try:
            ident = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Not decodable as UTF-8 is itself a reject case; hand the validator the
            # surrogate-escaped form rather than skipping the vector.
            ident = raw.decode("utf-8", "surrogateescape")

        want_accept = vec.get("expectation") == "accept"
        got_accept = fn(ident)

        if got_accept != want_accept:
            verb = "accepted" if got_accept else "rejected"
            fails.append(f"{vid}({kind}): {verb} {vec.get('input_display', ident)!s}")
            continue

        passed += 1
        fam = vec.get("family", "?")
        by_family[fam] = by_family.get(fam, 0) + 1

    total = len(vectors)
    ok = not fails and passed == total and total > 0

    fam_summary = ", ".join(f"{k} {v}" for k, v in sorted(by_family.items()))
    detail = f"{passed}/{total} identifier verdicts exact ({fam_summary})"
    if fails:
        detail += f" | {len(fails)} FAIL: " + "; ".join(fails[:6])
        if len(fails) > 6:
            detail += f" (+{len(fails) - 6} more)"
    return ok, detail
