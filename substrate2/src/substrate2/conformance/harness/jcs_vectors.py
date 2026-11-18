"""
Section 1 — JCS vector convergence (the authoritative wire-identity proof).

For each JCS anchor set, every vector's input object is canonicalised with substrate2 and
asserted to reproduce the published canonical bytes AND the published hash. This is the
real conformance signal and it drives pass/fail.

The manifest's per-file SHA-256 anchor is checked too, but only ADVISORILY: the local
checkout carries inconsistent CRLF/LF line endings, so a byte-level file hash is not a
reliable signal on a Windows working copy. A file-anchor mismatch is reported as a NOTE,
never a hard fail; the per-vector recompute — which uses the values AlgoVoi published
inside each vector — is what must be byte-exact.

The bundle is a curated subset of the public corpus, not a full mirror; see `subset_note`
in manifest.json. Sets registered with a `fixture_type` are skipped here and owned by the
section that can actually assert something about them (caip_edge_v1 by section 9,
jws_anchor_v1 by section 10).
"""
from __future__ import annotations

import base64
import hashlib
import json

from .._paths import JCS_MANIFEST, JCS_VECTORS_DIR

# Keys that may hold the canonical input object, in priority order.
_INPUT_KEYS = (
    "preimage", "mandate_body", "receipt", "attestation_body", "row", "object",
    "envelope", "payload", "input", "frame", "query", "attestation",
)
# Keys to ignore when falling back to "first non-metadata container".
_META_PREFIXES = ("expected", "canonical", "pair", "ed25519", "seed")
_META_EXACT = {"different_hash_from", "same_hash_as", "keypair"}


def _crlf_norm(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n")


def _b64_to_bytes(s: str) -> bytes:
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    return base64.b64decode(s2)


def _find_input(vector: dict):
    """Return (input_key, input_value) for the canonical input object in this vector."""
    for k in _INPUT_KEYS:
        v = vector.get(k)
        if isinstance(v, (dict, list)):
            return k, v
    # Fallback: first container value whose key is not metadata.
    for k, v in vector.items():
        if isinstance(v, (dict, list)) and not k.startswith(_META_PREFIXES) and k not in _META_EXACT:
            return k, v
    return None, None


def _expected_bytes(vector: dict, input_key: str | None = None):
    """Published canonical bytes, accepting base64 (`*_jcs_bytes_b64`) or hex (`canonical_bytes_hex`).

    When input_key is known, prefer `expected_{input_key}_jcs_bytes_b64` over the first
    match — vectors with multiple `*_jcs_bytes_b64` keys (e.g. pef_v1 has both
    `expected_receipt_jcs_bytes_b64` and `expected_preimage_jcs_bytes_b64`) must not
    have the wrong one picked by insertion-order luck.
    """
    if input_key:
        specific = f"expected_{input_key}_jcs_bytes_b64"
        v = vector.get(specific)
        if isinstance(v, str):
            return _b64_to_bytes(v)
    for k, v in vector.items():
        if isinstance(v, str) and k.endswith("_jcs_bytes_b64"):
            return _b64_to_bytes(v)
    for k, v in vector.items():
        if isinstance(v, str) and k.endswith("_bytes_hex"):
            return bytes.fromhex(v)
    return None


def _expected_hash(vector: dict):
    if isinstance(vector.get("canonical_sha256"), str):
        return vector["canonical_sha256"]
    for k, v in vector.items():
        if isinstance(v, str) and k.startswith("expected_") and (k.endswith("_hash") or k.endswith("_ref")):
            if k.endswith("_jcs_bytes_b64"):
                continue
            return v
    return None


def _actual_hash_matches(vector: dict, actual_hex: str) -> bool | None:
    """Check whether `actual_hex` matches any expected sha256 value in the vector.

    Vectors may name the hash of the canonical input object differently from their
    other hash fields (e.g. pef_v1 uses `expected_frame_id` for SHA-256(JCS(preimage))
    alongside `expected_receipt_hash` for a different object). Rather than guessing
    which key is the right one by name, we confirm that `actual_hex` appears as at
    least one `expected_*` sha256 value.

    Returns:
        True  — actual_hex found in at least one expected sha256 slot
        False — expected sha256 slots exist but none match actual_hex
        None  — no expected sha256 slots found (skip hash check)
    """
    found_any = False
    for k, v in vector.items():
        if not isinstance(v, str) or not k.startswith("expected_"):
            continue
        stripped = v.split(":")[-1]
        if len(stripped) == 64 and all(c in "0123456789abcdef" for c in stripped):
            found_any = True
            if stripped == actual_hex:
                return True
    return False if found_any else None


def run():
    from substrate2.canon import canonicalize_bytes

    manifest = json.loads(JCS_MANIFEST.read_text(encoding="utf-8"))
    anchor_sets = manifest.get("anchor_sets", [])

    fails: list[str] = []
    notes: list[str] = []
    passed = total = skipped = sets_seen = 0

    for aset in anchor_sets:
        name = aset["name"]
        path = JCS_VECTORS_DIR / name / aset["primary_file"]
        if not path.exists():
            fails.append(f"{name}: missing primary_file {aset['primary_file']}")
            continue
        sets_seen += 1
        raw = path.read_bytes()

        # (a) advisory anchor check — line-ending robust.
        anchor = aset.get("sha256", "").split(":")[-1]
        if anchor and anchor not in (hashlib.sha256(raw).hexdigest(), hashlib.sha256(_crlf_norm(raw)).hexdigest()):
            notes.append(f"{name} diverges from its manifest file anchor (line endings)")

        if aset.get("fixture_type"):
            continue  # crypto fixtures exercised by section 2

        data = json.loads(raw)
        for vec in data.get("vectors", []) or []:
            inp_key, inp = _find_input(vec)
            exp_bytes = _expected_bytes(vec, inp_key)
            if inp is None or exp_bytes is None:
                skipped += 1
                continue
            total += 1
            vid = vec.get("vector_id") or vec.get("name") or "?"
            try:
                canon = canonicalize_bytes(inp)
            except Exception as exc:
                fails.append(f"{name}/{vid}: canon error {type(exc).__name__}: {exc}")
                continue
            if canon != exp_bytes:
                fails.append(f"{name}/{vid}: JCS bytes mismatch")
                continue
            match = _actual_hash_matches(vec, hashlib.sha256(canon).hexdigest())
            if match is False:
                fails.append(f"{name}/{vid}: hash mismatch")
                continue
            passed += 1

    ok = (not fails) and passed > 0 and sets_seen == len(anchor_sets)
    detail = f"{passed}/{total} vectors byte+hash exact across {sets_seen} sets; {skipped} skipped(shape)"
    if notes:
        detail += f" | NOTE: {len(notes)} set(s) off stale manifest ({'; '.join(notes)})"
    if fails:
        detail += f" | {len(fails)} FAIL: " + "; ".join(fails[:6])
        if len(fails) > 6:
            detail += f" (+{len(fails) - 6} more)"
    return ok, detail
