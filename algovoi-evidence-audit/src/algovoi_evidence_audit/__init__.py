# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
# Copyright (c) 2026 AlgoVoi. All rights reserved.
"""algovoi_evidence_audit — batch-verify an archive of signed documents and
produce a signed, tamper-evident audit report.

The paid middle rung between the free ``algovoi-reseal-verify`` (check one) and
the AV-VCS estate (manage the whole records lifecycle). It reuses the free
verification core for every document, aggregates the findings, diffs against a
prior run, and (licence-gated) signs the report so the free verifier can confirm
it. Read-only: it never stores, governs, or mutates the documents.
"""
from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import time
import zipfile

from algovoi_reseal_verify import classical as _classical, verify_artifact, _b64u_dec

from .licensing import require_license, LicenseError  # noqa: F401
from . import signer

REPORT_TYPE = "evidence_audit_report"
REPORT_VERSION = 1
_MAX_FILE = 64 * 1024 * 1024  # skip absurdly large files defensively


# ── discovery ────────────────────────────────────────────────────────────────

def _iter_files(paths: list[str]):
    """Yield (display_path, bytes) for every file under the inputs.

    Directories recurse; .zip archives are read in-memory; globs expand; plain
    files pass through. Detached .p7s are paired with a sibling when present.
    """
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    yield from _read_one(fp, os.path.relpath(fp, p))
        elif os.path.isfile(p) and p.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(p) as z:
                    for name in z.namelist():
                        if name.endswith("/"):
                            continue
                        try:
                            data = z.read(name)
                        except Exception:  # noqa: BLE001
                            continue
                        if len(data) <= _MAX_FILE:
                            yield (f"{os.path.basename(p)}:{name}", data)
            except zipfile.BadZipFile:
                continue
        elif os.path.isfile(p):
            yield from _read_one(p, p)
        else:  # glob
            import glob as _glob
            for fp in sorted(_glob.glob(p, recursive=True)):
                if os.path.isfile(fp):
                    yield from _read_one(fp, fp)


def _read_one(fp: str, display: str):
    try:
        if os.path.getsize(fp) > _MAX_FILE:
            return
        with open(fp, "rb") as fh:
            yield (display, fh.read())
    except OSError:
        return


# ── per-file finding ─────────────────────────────────────────────────────────

def _find_sibling_p7s(display: str, index: dict) -> bytes | None:
    for ext in (".p7s", ".p7m"):
        if (display + ext) in index:
            return index[display + ext]
    return None


def _finding(display: str, data: bytes, index: dict,
             trust_roots, crl, expected_kid: str | None = None) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    low = display.lower()
    flags: list[str] = []
    signer_subject = None
    verified = None

    if low.endswith(".reseal.json"):
        # SECURITY (2026-08-19): a reseal artifact carries its OWN signing key, so a valid signature
        # only proves it is internally consistent — NOT who sealed it, and NOT that it attests any real
        # document. verify_artifact's own contract says callers must never surface plain success without
        # anchoring. Previously this counted any self-signed artifact as "verified". Now:
        #   (1) bind the attestation to the actual archived subject bytes (file_bytes), and
        #   (2) require the artifact to be ANCHORED to a pinned expected_kid before calling it verified.
        # Without a pinned kid, or if the subject is absent/mismatched, it is NOT verified (flagged).
        subject_display = display[: -len(".reseal.json")]
        subject_bytes = index.get(subject_display)
        try:
            art = json.loads(data)
            rep = verify_artifact(art, file_bytes=subject_bytes, expected_kid=expected_kid)
            ok = bool(rep.get("ok"))
            anchored = bool(rep.get("anchored"))
        except Exception:  # noqa: BLE001
            ok, anchored = False, False
        if subject_bytes is None:
            flags.append("subject_unbound")   # attests a document not present in this archive
        if ok and not anchored:
            flags.append("unanchored")        # signature intact but signer not pinned -> self-asserted
        verified = bool(ok and anchored and subject_bytes is not None)
        carrier = "reseal_attestation"
    else:
        sib = _find_sibling_p7s(display, index) if not low.endswith((".p7s", ".p7m")) else None
        if sib is not None:
            block = _classical.inspect_detached(data, sib, trust_roots, crl)
        else:
            block = _classical.inspect_bytes(data, display, trust_roots, crl)
        carrier = block.get("carrier", "raw")
        sigs = block.get("signatures", [])
        if not block.get("present"):
            verified = None  # unsigned / existence only
        else:
            verified = all(bool(s.get("verified")) for s in sigs) if sigs else False
            for s in sigs:
                if s.get("quantum_vulnerable"):
                    flags.append("quantum_exposed")
                if s.get("weak_digest"):
                    flags.append("weak_digest")
                if s.get("covers_entire_file") is False:
                    flags.append("partial_coverage")
                if s.get("trust_path") and not s["trust_path"].get("ok"):
                    flags.append("broken_chain")
                if any(c.get("check") == "cert_validity_window" and not c.get("ok")
                       for c in s.get("checks", [])):
                    flags.append("expired_cert")
                signer_subject = signer_subject or s.get("signer_subject")

    return {"path": display, "sha256": sha, "carrier": carrier,
            "verified": verified, "flags": sorted(set(flags)), "signer": signer_subject}


# ── audit run ────────────────────────────────────────────────────────────────

def run_audit(paths: list[str], root_label: str = "",
              trust_roots_der: list[bytes] | None = None,
              crl_bytes: bytes | None = None,
              baseline: dict | None = None,
              run_at_ms: int | None = None,
              expected_kid: str | None = None) -> dict:
    """Build the audit report dict over the inputs. Read-only.

    LICENCE-GATED at the engine, like every AlgoVoi commercial app: batch
    auditing an archive IS the paid product (the free ``algovoi-reseal-verify``
    covers single-document verification). Fail-closed. Verifying an existing
    report needs no licence.
    """
    require_license()
    index = {display: data for display, data in _iter_files(paths)}
    # A detached .p7s/.p7m whose subject is also present is evidence FOR that
    # subject (audited under it), not a document in its own right - fold it in.
    def _folded(display: str) -> bool:
        low = display.lower()
        return low.endswith((".p7s", ".p7m")) and display[: display.rfind(".")] in index
    findings = [_finding(d, data, index, trust_roots_der, crl_bytes, expected_kid)
                for d, data in index.items() if not _folded(d)]
    findings.sort(key=lambda f: f["path"])

    summary = {"total": len(findings), "signed": 0, "verified": 0, "invalid": 0,
               "weak_digest": 0, "expired_cert": 0, "broken_chain": 0,
               "partial_coverage": 0, "quantum_exposed": 0, "unsigned": 0}
    for f in findings:
        if f["verified"] is None:
            summary["unsigned"] += 1
        elif f["verified"] is True:
            summary["signed"] += 1
            summary["verified"] += 1
        elif f["verified"] is False:
            summary["signed"] += 1
            summary["invalid"] += 1
        for flag in f["flags"]:
            if flag in summary:
                summary[flag] += 1

    report = {
        "type": REPORT_TYPE, "v": REPORT_VERSION,
        "run_at_ms": run_at_ms if run_at_ms is not None else int(time.time() * 1000),
        "scope": {"root": root_label or (paths[0] if paths else ""), "file_count": len(findings)},
        "summary": summary,
        "findings": findings,
    }
    if baseline is not None:
        report["baseline_diff"] = _diff(baseline, findings)
    return report


def _diff(baseline: dict, findings: list[dict]) -> dict:
    def _index(items):
        return {f["path"]: f["sha256"] for f in items}
    base = _index(baseline.get("findings", []))
    cur = _index(findings)
    changed = sorted(p for p in cur if p in base and cur[p] != base[p])
    new = sorted(p for p in cur if p not in base)
    removed = sorted(p for p in base if p not in cur)
    return {"changed": changed, "new": new, "removed": removed,
            "unchanged": len(cur) - len(changed) - len(new)}


def canonical_report_bytes(report: dict) -> bytes:
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode()


def sign_report(report: dict, keys: dict) -> tuple[bytes, dict]:
    """LICENCE-GATED. Returns (report_bytes, reseal_artifact_over_report).

    The artifact is a standard reseal attestation the FREE verifier checks.
    """
    require_license()
    report_bytes = canonical_report_bytes(report)
    artifact = signer.sign_bytes(report_bytes, keys, filename="audit-report.json")
    return report_bytes, artifact
