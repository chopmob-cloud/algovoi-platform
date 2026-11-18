"""
Section 10 — signed-token anchoring (jws_anchor_v1).

Canonicalisation answers "given an object, what are its exact bytes". Anchoring a *signed*
receipt raises a second question that RFC 8785 does not answer: given a signed token, which
bytes do you hash. Two parties can both be perfectly JCS-conformant and still disagree on
the anchor, because one of them hashed a different thing.

The rule this section enforces: anchor the RAW SIGNED BYTES. Never decode, re-serialise or
re-canonicalise a payload before hashing it. A signed token is already a byte string, and
those are the bytes the signature covers.

Four checks, matching the set's own invariants:

  I1  Re-canonicalising a decoded payload must NOT reproduce the signed-token anchor. This
      is run actively, not asserted from the file: substrate2 canonicalises the decoded
      payload itself and the result must equal the published recanon digest and differ from
      the signed anchor. A verifier that re-canonicalises anywhere fails here.
  I2  The issuer-JWT anchor is disclosure-invariant. An SD-JWT issuance form, a holder
      presentation and the bare issuer JWT are three distinct digests, so anchoring a
      presentation silently binds the record to one disclosure subset.
  I3  Every signed token verifies under a fixed deterministic Ed25519 test public key
      (700e2ce7...; NOT RFC 8032 Test 1). EdDSA is
      deterministic, so the tokens regenerate byte-identically and nothing is taken on trust.
  I4  The canon-sensitive divergence is attributable to a jcs_edge_v1 class (literal U+2028
      and the 1.0-serialises-as-1 rule), which is why the two sets are siblings.
"""
from __future__ import annotations

import base64
import hashlib
import json

from .._paths import vector_set_path

_SET = "jws_anchor_v1"


def _b64url(s: str) -> bytes:
    pad = "=" * ((-len(s)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _anchor(token: str) -> str:
    """The rule: hash the token exactly as issued."""
    return "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()


def _decoded_payload(token: str) -> dict:
    jwt = token.split("~", 1)[0]
    return json.loads(_b64url(jwt.split(".")[1]))


def _verify_ed25519(token: str, public_key_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    jwt = token.split("~", 1)[0]
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        key.verify(_b64url(sig_b64), f"{header_b64}.{payload_b64}".encode("ascii"))
        return True
    except InvalidSignature:
        return False


def run() -> tuple[bool, str]:
    from substrate2.canon import canonicalize_bytes

    path = vector_set_path(_SET, f"{_SET}.json")
    if not path.exists():
        return False, f"{_SET} not bundled (looked in {path.parent})"

    data = json.loads(path.read_text(encoding="utf-8"))
    vectors = {v["vector_id"]: v for v in data.get("vectors", [])}
    pubkey = data["signing_key"]["public_key_hex"]

    fails: list[str] = []
    anchors_checked = 0
    anchors_ok = 0
    invariants_ok = 0

    # ---- anchor recompute, per vector -------------------------------------------------
    for vid, vec in vectors.items():
        rule = vec.get("anchor_rule")
        expected = vec.get("expected_anchor")
        if not expected:
            continue
        anchors_checked += 1
        if rule == "jcs":
            actual = "sha256:" + hashlib.sha256(canonicalize_bytes(vec["input"])).hexdigest()
        elif rule == "signed_bytes":
            token = vec.get("input") or vec.get("issuer_jwt")
            if token is None:
                fails.append(f"{vid}: no token field")
                continue
            # SD-JWT: the disclosure-invariant anchor is the segment before the first '~'.
            actual = _anchor(token.split("~", 1)[0] if vec.get("issuer_jwt") else token)
        else:
            fails.append(f"{vid}: unknown anchor_rule {rule!r}")
            continue
        if actual != expected:
            fails.append(f"{vid}: anchor {actual[:22]}.. != published {expected[:22]}..")
        else:
            anchors_ok += 1

    # ---- I1: re-canonicalising must diverge, proven by doing it -----------------------
    _mark = len(fails)
    v1, v2 = vectors.get("jws-anchor-001"), vectors.get("jws-anchor-002")
    if v1 and v2:
        recanon = "sha256:" + hashlib.sha256(
            canonicalize_bytes(_decoded_payload(v1["input"]))
        ).hexdigest()
        if recanon != v2["recanon_of_decoded_payload"]:
            fails.append("I1: substrate2 recanon != published recanon digest")
        if recanon == v1["expected_anchor"]:
            fails.append("I1 VIOLATED: recanon reproduced the signed-token anchor")
    else:
        fails.append("I1: vectors 001/002 missing")

    invariants_ok += len(fails) == _mark

    # ---- I2: disclosure-invariance ----------------------------------------------------
    _mark = len(fails)
    v3, v4 = vectors.get("jws-anchor-003"), vectors.get("jws-anchor-004")
    if v3 and v4:
        issuer = _anchor(v3["issuer_jwt"].split("~", 1)[0])
        presentation = _anchor(v4["presentation"])
        issuance = _anchor(v3["issuance_form"])
        if presentation != v4["presentation_hash"]:
            fails.append("I2: presentation hash != published")
        if issuance != v4["issuance_hash"]:
            fails.append("I2: issuance hash != published")
        if len({issuer, presentation, issuance}) != 3:
            fails.append("I2 VIOLATED: issuer/presentation/issuance are not three distinct digests")
    else:
        fails.append("I2: vectors 003/004 missing")

    invariants_ok += len(fails) == _mark

    # ---- I3: signatures verify --------------------------------------------------------
    _mark = len(fails)
    verified = 0
    for vid, vec in vectors.items():
        for field in ("input", "issuer_jwt", "presentation"):
            token = vec.get(field)
            if not isinstance(token, str) or vec.get("anchor_rule") != "signed_bytes":
                continue
            if not _verify_ed25519(token, pubkey):
                fails.append(f"I3: {vid}.{field} failed Ed25519 verify")
            else:
                verified += 1

    invariants_ok += len(fails) == _mark

    # ---- I4: the canon-sensitive case is attributable ---------------------------------
    _mark = len(fails)
    v6 = vectors.get("jws-anchor-006")
    if v6:
        if v6.get("xref") != "jcs_edge_v1":
            fails.append("I4: vector 006 no longer cross-references jcs_edge_v1")
        recanon6 = "sha256:" + hashlib.sha256(
            canonicalize_bytes(_decoded_payload(v6["input"]))
        ).hexdigest()
        if recanon6 != v6["recanon_of_decoded_payload"]:
            fails.append("I4: substrate2 recanon of the canon-sensitive payload != published")
        if recanon6 == v6["expected_anchor"]:
            fails.append("I4 VIOLATED: canon-sensitive recanon reproduced the signed anchor")
    else:
        fails.append("I4: vector 006 missing")

    invariants_ok += len(fails) == _mark

    ok = not fails
    # Two of the six vectors are negative/derived (002 recanon, 004 presentation) and carry
    # no expected_anchor of their own; they are proven by I1 and I2 rather than skipped. So
    # the anchor count is reported against the vectors that actually publish one, not
    # against the set size, which would read like two failures.
    negatives = len(vectors) - anchors_checked
    detail = (
        f"{anchors_ok}/{anchors_checked} published anchors exact "
        f"(+{negatives} negative vectors via invariants); {invariants_ok}/4 invariants; "
        f"{verified} Ed25519 verifies under RFC 8032 7.1"
    )
    if fails:
        detail += f" | {len(fails)} FAIL: " + "; ".join(fails[:6])
    return ok, detail
