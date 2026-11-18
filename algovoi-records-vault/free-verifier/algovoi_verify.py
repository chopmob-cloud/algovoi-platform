#!/usr/bin/env python3
"""AlgoVoi free verifier — check any AlgoVoi signed receipt, chain, evidence pack, or key lineage.

**Don't trust AlgoVoi — verify it yourself.** This tool contains *no AlgoVoi code*. Its entire trust
base is two public, audited-primitive libraries:

    pip install pqcrypto rfc8785

It re-derives every Falcon-1024 (FN-DSA-1024) signature and SHA-256 hash-link itself, from the
published public key alone — no secret key, no running service, no network. If it prints OK, the
evidence is genuine and unaltered; if a single byte was changed, it fails at exactly that entry.

Usage:
    python algovoi_verify.py <path> [<pubkey.b64>]                 # AUTO-DETECT — drop any AlgoVoi file
    python algovoi_verify.py validate <path> [<pubkey.b64>]        #   (same; explicit form)

    python algovoi_verify.py pack <pack_dir> [<expected_kid>]      # a full evidence pack
    python algovoi_verify.py epi <epi_dir> [<expected_kid>]        # a .epi portable-evidence artifact
    python algovoi_verify.py receipt <receipt.txt> <pubkey.b64>    # one signed receipt
    python algovoi_verify.py chain <chain.json> <pubkey.b64>       # a signed-chain stream (JSON array)
    python algovoi_verify.py keys <proofs.json> [<genesis_kid>]    # an F7 key-rotation lineage
    python algovoi_verify.py product-keys <registry.json> [<kid>]  # AlgoVoi product key registry (+ optional kid lookup)

Auto-detect figures out the artifact type from its structure. A bare receipt or chain needs the
signer's published public key (pass it as the second argument).

**Anchoring.** Evidence packs, .epi artifacts and key lineages carry the signing public key *inside
the artifact*, so re-deriving their signatures proves the artifact is internally consistent and
unaltered — it does NOT prove who signed it. Anyone can generate a keypair and produce a wholly
fabricated pack that is internally perfect. To get authenticity you must anchor the key to AlgoVoi
out-of-band, exactly as you would for any signer (X.509 included): pin the `kid` fingerprint
published at https://api.algovoi.co.uk and pass it as `<expected_kid>`.

Exit codes:
    0  verified AND anchored to the expected kid
    1  verification failed (bad signature, broken chain, or kid mismatch)
    2  usage error / artifact not recognised
    3  cryptographically intact, but the key is self-asserted — no expected kid was supplied
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

try:
    import rfc8785
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
except Exception as exc:  # noqa: BLE001
    print(f"This verifier needs two public libraries: pip install pqcrypto rfc8785  ({exc})")
    raise SystemExit(2)


# ── primitives ────────────────────────────────────────────────────────────────────────────────
def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def jcs(payload) -> bytes:
    return rfc8785.dumps(payload)


def payload_hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(jcs(payload)).hexdigest()


def open_envelope(env_b64: str):
    env = json.loads(_b64u(env_b64.strip()))
    return env["payload"], _b64u(env["sig"]), env.get("kid", "")


def falcon_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(_falcon_verify(pk, msg, sig))
    except Exception:  # noqa: BLE001
        return False


# ── verifiers ─────────────────────────────────────────────────────────────────────────────────
def verify_receipt(env_b64: str, public_key: bytes) -> tuple[bool, dict]:
    """Verify a single signed receipt/entry envelope. Returns (ok, payload)."""
    try:
        payload, sig, _ = open_envelope(env_b64)
    except Exception:  # noqa: BLE001
        return False, {}
    return falcon_ok(public_key, jcs(payload), sig), (payload if isinstance(payload, dict) else {})


def verify_chain(envelopes: list[str], public_key: bytes) -> tuple[bool, str]:
    """Verify a signed, hash-linked chain. Type + prev-hash field are auto-detected from the entries."""
    prev = None
    etype = None
    for i, e in enumerate(envelopes):
        try:
            payload, sig, _ = open_envelope(e)
        except Exception:  # noqa: BLE001
            return False, f"malformed_entry@{i}"
        t = payload.get("type")
        if etype is None:
            etype = t
        elif t != etype:
            return False, f"type_changed@{i} ({etype}->{t})"
        if not falcon_ok(public_key, jcs(payload), sig):
            return False, f"bad_signature@{i}"
        if payload.get("seq") != i:
            return False, f"seq_mismatch@{i}"
        prev_field = "prev_receipt_hash" if "prev_receipt_hash" in payload else "prev_entry_hash"
        if payload.get(prev_field) != prev:
            return False, f"chain_break@{i}"
        prev = payload_hash(payload)
    return True, f"{len(envelopes)} entries (type={etype}), head={prev}"


_ROT_KEYS = ("old_kid", "new_kid", "old_pubkey_b64", "new_pubkey_b64", "rotated_at")


def _kid(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:16]


def _anchor(kid: str, expected: str | None, ok_all: bool, subject: str) -> tuple[str, int]:
    """Resolve the trust half of a self-contained artifact into a (result line, exit code).

    The signature checks prove the artifact is intact. They say nothing about *who* signed it,
    because the key travelled inside the artifact. Only a `kid` the caller pinned out-of-band
    turns that into authenticity, so an unanchored run must never be reported as fully verified.
    """
    if not ok_all:
        return f"{subject} VERIFICATION FAILED", 1
    if expected is None:
        return (f"{subject} INTACT, KEY NOT ANCHORED — signed by kid {kid}, which this artifact "
                f"supplied itself. Re-run with the kid you pinned out-of-band to prove authenticity.", 3)
    if kid != expected:
        return f"{subject} VERIFICATION FAILED — kid {kid} does not match expected {expected}", 1
    return f"{subject} VERIFIED AND ANCHORED to kid {kid}", 0


def verify_rotation_proof(proof: dict) -> bool:
    """An F7 rotation proof: both cross-signatures valid + each kid matches its embedded public key."""
    try:
        b = {k: proof[k] for k in _ROT_KEYS}
        msg = jcs(b)
        old_pk = base64.b64decode(proof["old_pubkey_b64"])
        new_pk = base64.b64decode(proof["new_pubkey_b64"])
        if _kid(old_pk) != proof["old_kid"] or _kid(new_pk) != proof["new_kid"]:
            return False
        return (falcon_ok(old_pk, msg, _b64u(proof["old_sig"]))
                and falcon_ok(new_pk, msg, _b64u(proof["new_sig"])))
    except Exception:  # noqa: BLE001
        return False


def verify_key_chain(proofs: list[dict], genesis_kid: str | None = None) -> tuple[bool, str]:
    """Verify an ordered old->new rotation lineage.

    Every proof carries both public keys, so an unanchored lineage only proves internal
    consistency: a whole fake lineage cross-signs perfectly. `genesis_kid` pins the first
    `old_kid` to a fingerprint obtained out-of-band, which is what makes the lineage evidence.
    """
    if genesis_kid is not None and proofs and proofs[0].get("old_kid") != genesis_kid:
        return False, f"genesis_mismatch (expected {genesis_kid}, got {proofs[0].get('old_kid')})"
    prev_new = None
    for i, p in enumerate(proofs):
        if not verify_rotation_proof(p):
            return False, f"bad_rotation_proof@{i}"
        if prev_new is not None and p["old_kid"] != prev_new:
            return False, f"lineage_gap@{i}"
        prev_new = p["new_kid"]
    anchored = "anchored to genesis" if genesis_kid else "NOT ANCHORED (genesis kid self-asserted)"
    return True, f"{len(proofs)} rotations, current_kid={prev_new}, {anchored}"


def verify_pack(pack_dir: str, expected_kid: str | None = None) -> int:
    with open(os.path.join(pack_dir, "public_key.b64"), encoding="utf-8") as fh:
        pk = base64.b64decode(fh.read().strip())

    def load(name):
        with open(os.path.join(pack_dir, name), encoding="utf-8") as fh:
            return json.load(fh)

    print("=" * 70)
    print("AlgoVoi free verifier — offline, public key only, no AlgoVoi code")
    print(f"  pack: {pack_dir}")
    print(f"  public key kid: {_kid(pk)}  (Falcon-1024, {len(pk)} bytes)"
          f"{'  [supplied by the pack, not anchored]' if expected_kid is None else f'  [expected {expected_kid}]'}")
    print("=" * 70)

    ok_all = True
    chain_files = sorted(f for f in os.listdir(pack_dir) if f.endswith("_chain.json"))
    for fn in chain_files:
        ok, detail = verify_chain(load(fn), pk)
        print(f"  [{'PASS' if ok else 'FAIL'}] {fn:<20} {detail}")
        ok_all &= ok

    # optional TSA binding (if both an archive and a tsa chain are present)
    if "archive_chain.json" in chain_files and "tsa_chain.json" in chain_files:
        arch = [open_envelope(e)[0] for e in load("archive_chain.json")]
        bind_ok = True
        for e in load("tsa_chain.json"):
            tp = open_envelope(e)[0]
            aseq = tp.get("archive_seq")
            want = payload_hash(arch[aseq]) if isinstance(aseq, int) and aseq < len(arch) else None
            if tp.get("message_imprint") != want:
                bind_ok = False
        print(f"  [{'PASS' if bind_ok else 'FAIL'}] timestamp binding     "
              f"each tsa.messageImprint == hash(archive receipt)")
        ok_all &= bind_ok

    line, code = _anchor(_kid(pk), expected_kid, ok_all, "ALL EVIDENCE")
    print("=" * 70)
    print("RESULT:", line)
    print("=" * 70)
    return code


def verify_epi(epi_dir: str, expected_kid: str | None = None) -> int:
    """Verify a `.epi` artifact (AlgoVoi PQC profile) with the spec's five checks. Falcon-1024 suite.

    `expected_kid` is the signer fingerprint pinned out-of-band. Without it the five checks still
    run, but the key came from inside the artifact, so the result is intact-not-authentic (exit 3).
    """
    def path(n):
        return os.path.join(epi_dir, n)

    print("=" * 70)
    print("AlgoVoi free verifier — .epi portable evidence (offline, public key only)")
    print(f"  artifact: {epi_dir}")
    print("=" * 70)
    results: list[tuple[str, bool, str]] = []

    # 1. Structure valid
    needed = ["manifest.json", "steps.jsonl", "public_key.b64"]
    structure_ok = all(os.path.exists(path(n)) for n in needed)
    manifest = {}
    if structure_ok:
        try:
            manifest = json.load(open(path("manifest.json"), encoding="utf-8"))
        except Exception:  # noqa: BLE001
            structure_ok = False
    results.append(("Structure valid", structure_ok, "manifest.json + steps.jsonl + public_key.b64"))

    pk = base64.b64decode(open(path("public_key.b64"), encoding="utf-8").read().strip()) if structure_ok else b""

    # 2. Hashes match (every file in manifest.files matches its recorded sha256)
    hashes_ok = structure_ok
    bad = []
    for f in (manifest.get("files") or []):
        try:
            h = hashlib.sha256(open(path(f["name"]), "rb").read()).hexdigest()
        except Exception:  # noqa: BLE001
            h = None
        if h != f.get("sha256"):
            hashes_ok = False
            bad.append(f.get("name"))
    results.append(("Hashes match", hashes_ok, ("mismatch: " + ", ".join(bad)) if bad else f"{len(manifest.get('files') or [])} files"))

    # 3. Signature valid (Falcon-1024 over JCS(manifest sans signature))
    sig_ok = False
    detail = "no signature"
    sig = manifest.get("signature", "")
    if structure_ok and sig.count(":") >= 2:
        suite, kid, b64 = sig.split(":", 2)
        body = {k: v for k, v in manifest.items() if k != "signature"}
        if suite == "falcon1024":
            sig_ok = (kid == manifest.get("kid") == _kid(pk)) and falcon_ok(pk, jcs(body), _b64u(b64))
            detail = f"falcon1024 / kid {kid}"
        else:
            detail = f"unsupported suite {suite!r} (this verifier supports falcon1024; ed25519 needs PyNaCl)"
    results.append(("Signature valid", sig_ok, detail))

    # 4. Chain intact (steps.jsonl hash-links + steps_head)
    chain_ok = structure_ok
    cdetail = ""
    if structure_ok:
        prev = None
        n = 0
        head = None
        for line in open(path("steps.jsonl"), encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            step = json.loads(line)
            if step.get("prev") != prev:
                chain_ok = False
                cdetail = f"chain_break@{n}"
                break
            prev = "sha256:" + hashlib.sha256(jcs(step)).hexdigest()
            head = prev
            n += 1
        if chain_ok:
            if manifest.get("steps_count") != n:
                chain_ok, cdetail = False, f"steps_count {manifest.get('steps_count')} != {n}"
            elif manifest.get("steps_head") != head:
                chain_ok, cdetail = False, "steps_head mismatch"
            else:
                cdetail = f"{n} steps linked"
    results.append(("Chain intact", chain_ok, cdetail))

    # 5. SCITT anchored (optional)
    scitt = manifest.get("scitt_receipt") is not None
    results.append(("SCITT anchored", True, "present" if scitt else "not anchored (optional)"))

    for name, ok, det in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<16} {det}")
    ok_all = all(ok for _, ok, _ in results)
    line, code = _anchor(_kid(pk) if pk else "?", expected_kid, ok_all, ".epi")
    print("=" * 70)
    print("RESULT:", line)
    print("=" * 70)
    return code


def verify_product_registry(path: str, kid: str | None = None) -> int:
    """Verify the AlgoVoi product key registry (Falcon self-signed) and, optionally,
    authenticate a given kid against the AlgoVoi-operated keys it lists."""
    doc = json.load(open(path, encoding="utf-8"))
    payload = doc["payload"]
    pk = base64.b64decode(doc["public_key_pqclean_b64"])
    sig = _b64u(doc["sig"])
    kid_ok = doc["kid"] == hashlib.sha256(pk).hexdigest()[:16]
    sig_ok = falcon_ok(pk, jcs(payload), sig)
    print(("PASS" if kid_ok else "FAIL"), "registry kid binds to its public key", doc["kid"])
    print(("PASS" if sig_ok else "FAIL"), "Falcon-1024 signature over registry payload")
    print("INFO valid_until", payload.get("valid_until"),
          "| operated keys", len(payload.get("algovoi_operated_keys", [])),
          "| products", len(payload.get("products", [])))
    ok = kid_ok and sig_ok
    # key-lineage (F7): genesis anchors + any cross-signed rotation chains
    lineage = payload.get("key_lineage", {})
    if lineage:
        nrot = sum(len(v.get("rotations", [])) for v in lineage.values())
        print("INFO key_lineage:", len(lineage), "anchor(s),", nrot, "rotation(s)")
        for lk, v in lineage.items():
            rots = v.get("rotations", [])
            if not rots:
                continue  # genesis-only anchor: nothing to cross-verify yet
            prev = None
            chain_ok = True
            for i, p in enumerate(rots):
                binding = {k: p[k] for k in ("old_kid", "new_kid", "old_pubkey_b64", "new_pubkey_b64", "rotated_at")}
                msg = jcs(binding)
                if v.get("alg") == "Falcon-1024":
                    opk, npk = base64.b64decode(p["old_pubkey_b64"]), base64.b64decode(p["new_pubkey_b64"])
                    good = falcon_ok(opk, msg, _b64u(p["old_sig"])) and falcon_ok(npk, msg, _b64u(p["new_sig"]))
                else:
                    print(f"INFO  {lk} rotation chain uses {v.get('alg')} (needs ed25519 lib; skipped here)")
                    good = None
                if good is False or (good and prev is not None and p["old_kid"] != prev):
                    chain_ok = False
                prev = p["new_kid"]
            if v.get("alg") == "Falcon-1024":
                print(("PASS" if chain_ok else "FAIL"), f"lineage {lk}: {len(rots)} rotation(s) -> {prev}")
                ok = ok and chain_ok
    if kid:
        opk = [k for k in payload.get("algovoi_operated_keys", []) if k["kid"] == kid]
        if opk:
            k = opk[0]
            print("PASS", f"kid {kid} is an AlgoVoi-operated key:",
                  k["alg"], f"({k.get('status')})", "-", k.get("used_for", ""))
        else:
            print("WARN", f"kid {kid} is not an AlgoVoi-operated key. If it signed a product "
                  "receipt, that product is buyer-custody (on-prem): the receipt is "
                  "self-verifying via its embedded key, generated at install.")
    print("RESULT:", "PRODUCT REGISTRY VERIFIED" if ok else "REGISTRY VERIFICATION FAILED")
    return 0 if ok else 1


# ── auto-detect ───────────────────────────────────────────────────────────────────────────────
_SUBCOMMANDS = ("pack", "epi", "receipt", "chain", "keys", "product-keys", "validate")


def autodetect(path: str, pubkey_b64: str | None = None, expected_kid: str | None = None) -> int:
    """Detect an artifact's type from its structure, then validate it.

    A bare receipt or chain needs the signer's published public key. An evidence pack, .epi or key
    lineage carries its own key, so it validates with no further input but only proves integrity;
    pass the kid you pinned out-of-band to also prove authenticity (see the module docstring).
    """
    # A second argument that is not a readable file is taken as an expected kid, so
    # `validate <pack_dir> <kid>` works without a placeholder for the unused pubkey slot.
    if pubkey_b64 and not os.path.exists(pubkey_b64) and expected_kid is None:
        pubkey_b64, expected_kid = None, pubkey_b64
    pk = base64.b64decode(open(pubkey_b64, encoding="utf-8").read().strip()) if pubkey_b64 else None

    if os.path.isdir(path):
        if os.path.exists(os.path.join(path, "manifest.json")) and os.path.exists(os.path.join(path, "steps.jsonl")):
            print(f"detected: .epi portable-evidence artifact — {path}\n")
            return verify_epi(path, expected_kid)
        if os.path.exists(os.path.join(path, "public_key.b64")) and \
                any(f.endswith("_chain.json") for f in os.listdir(path)):
            print(f"detected: evidence pack — {path}\n")
            return verify_pack(path, expected_kid)
        print(f"could not detect an AlgoVoi artifact in directory: {path}")
        return 2

    raw = open(path, encoding="utf-8").read().strip()
    try:
        doc = json.loads(raw)
    except Exception:  # noqa: BLE001 — a bare base64 envelope (single receipt) is not JSON
        doc = raw

    if isinstance(doc, dict) and "public_key_pqclean_b64" in doc:
        print(f"detected: AlgoVoi product key registry — {path}")
        return verify_product_registry(path)
    if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "old_kid" in doc[0]:
        ok, detail = verify_key_chain(doc, expected_kid)
        print(("PASS" if ok else "FAIL"), f"detected: key-rotation lineage — {detail}")
        return (0 if expected_kid else 3) if ok else 1
    if isinstance(doc, list):
        if pk is None:
            print(f"detected: a signed chain — re-run with the signer's public key:\n"
                  f"    algovoi_verify.py validate {path} <public_key.b64>")
            return 2
        ok, detail = verify_chain(doc, pk)
        print(("PASS" if ok else "FAIL"), f"detected: signed chain — {detail}")
        return 0 if ok else 1
    if isinstance(doc, str):
        if pk is None:
            print(f"detected: a single signed receipt — re-run with the signer's public key:\n"
                  f"    algovoi_verify.py validate {path} <public_key.b64>")
            return 2
        ok, payload = verify_receipt(doc, pk)
        print(("PASS" if ok else "FAIL"), f"detected: signed receipt — type={payload.get('type')} seq={payload.get('seq')}")
        return 0 if ok else 1

    print(f"could not detect an AlgoVoi artifact in file: {path}")
    return 2


# ── CLI ───────────────────────────────────────────────────────────────────────────────────────
def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "validate" and len(argv) in (2, 3, 4):
        return autodetect(argv[1], argv[2] if len(argv) >= 3 else None, argv[3] if len(argv) == 4 else None)
    # bare-path convenience: `algovoi_verify.py <path> [pubkey|kid] [kid]` auto-detects
    if cmd not in _SUBCOMMANDS and os.path.exists(cmd):
        return autodetect(cmd, argv[1] if len(argv) >= 2 else None, argv[2] if len(argv) >= 3 else None)
    if cmd == "pack" and len(argv) in (2, 3):
        return verify_pack(argv[1], argv[2] if len(argv) == 3 else None)
    if cmd == "epi" and len(argv) in (2, 3):
        return verify_epi(argv[1], argv[2] if len(argv) == 3 else None)
    if cmd == "receipt" and len(argv) == 3:
        env = open(argv[1], encoding="utf-8").read()
        pk = base64.b64decode(open(argv[2], encoding="utf-8").read().strip())
        ok, payload = verify_receipt(env, pk)
        print(("PASS" if ok else "FAIL"), "receipt", f"type={payload.get('type')}", f"seq={payload.get('seq')}")
        return 0 if ok else 1
    if cmd == "chain" and len(argv) == 3:
        envs = json.load(open(argv[1], encoding="utf-8"))
        pk = base64.b64decode(open(argv[2], encoding="utf-8").read().strip())
        ok, detail = verify_chain(envs, pk)
        print(("PASS" if ok else "FAIL"), "chain", detail)
        return 0 if ok else 1
    if cmd == "keys" and len(argv) in (2, 3):
        genesis = argv[2] if len(argv) == 3 else None
        proofs = json.load(open(argv[1], encoding="utf-8"))
        ok, detail = verify_key_chain(proofs, genesis)
        print(("PASS" if ok else "FAIL"), "key lineage", detail)
        return (0 if genesis else 3) if ok else 1
    if cmd == "product-keys" and len(argv) in (2, 3):
        return verify_product_registry(argv[1], argv[2] if len(argv) == 3 else None)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
