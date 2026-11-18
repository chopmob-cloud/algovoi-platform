# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
# Copyright (c) 2026 AlgoVoi. All rights reserved.
"""Human-readable renderings of an audit report: HTML + CSV. Read-only."""
from __future__ import annotations

import csv
import datetime
import html
import io

_TILES = [("total", "Documents"), ("verified", "Verified"), ("invalid", "Invalid"),
          ("unsigned", "Unsigned"), ("weak_digest", "Weak digest (SHA-1)"),
          ("expired_cert", "Expired cert"), ("broken_chain", "Broken chain"),
          ("partial_coverage", "Partial-coverage PDF"), ("quantum_exposed", "Quantum-exposed")]


def _iso(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def to_html(report: dict, attestation_kid: str | None = None) -> str:
    s = report["summary"]
    tiles = "".join(
        f'<div class="tile"><div class="n">{s.get(k, 0)}</div><div class="l">{html.escape(lbl)}</div></div>'
        for k, lbl in _TILES)
    rows = ""
    for f in report["findings"]:
        v = f["verified"]
        badge = ('<span class="ok">verified</span>' if v is True
                 else '<span class="bad">INVALID</span>' if v is False
                 else '<span class="na">unsigned</span>')
        flags = " ".join(f'<span class="flag">{html.escape(x)}</span>' for x in f["flags"])
        rows += (f"<tr><td class=p>{html.escape(f['path'])}</td><td>{html.escape(f['carrier'])}</td>"
                 f"<td>{badge}</td><td>{html.escape(f.get('signer') or '')}</td><td>{flags}</td>"
                 f"<td class=h>{f['sha256'][:16]}…</td></tr>")
    diff = ""
    if "baseline_diff" in report:
        d = report["baseline_diff"]
        diff = (f'<p class="diff">Since baseline: <b>{d["unchanged"]}</b> unchanged, '
                f'<b>{len(d["changed"])}</b> changed, <b>{len(d["new"])}</b> new, '
                f'<b>{len(d["removed"])}</b> removed.</p>')
    anchor = (f'<p class="anchor">Report signed; verify it with '
              f'<code>av-reseal-verify verify audit-report.json.reseal.json --file audit-report.json'
              + (f' --expect-kid {html.escape(attestation_kid)}' if attestation_kid else '')
              + '</code></p>') if attestation_kid is not None else ""
    return f"""<!doctype html><meta charset=utf-8>
<title>AlgoVoi Evidence Audit</title>
<style>
 body{{font:14px system-ui,Segoe UI,sans-serif;margin:2rem;color:#14161f;max-width:1100px}}
 h1{{font-size:22px;margin:0 0 .2rem}} .sub{{color:#767b90;margin:0 0 1.2rem}}
 .tiles{{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}}
 .tile{{border:1px solid #e7e9f0;border-radius:10px;padding:.7rem 1rem;min-width:110px}}
 .tile .n{{font-size:22px;font-weight:700}} .tile .l{{color:#767b90;font-size:12px}}
 table{{border-collapse:collapse;width:100%;font-size:13px;margin-top:1rem}}
 th,td{{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #eef0f4;vertical-align:top}}
 th{{color:#464a5c;font-weight:600}} td.p{{font-family:ui-monospace,monospace;word-break:break-all}}
 td.h{{font-family:ui-monospace,monospace;color:#767b90}}
 .ok{{color:#1f9d6b;font-weight:600}} .bad{{color:#a7415a;font-weight:700}} .na{{color:#767b90}}
 .flag{{background:#f6ecd8;color:#8a5a00;border-radius:4px;padding:1px 5px;font-size:11px;margin-right:2px}}
 .anchor code,.diff{{font-size:12px}} .anchor{{color:#464a5c;background:#f4f5f9;padding:.6rem;border-radius:8px}}
</style>
<h1>AlgoVoi Evidence Audit</h1>
<p class="sub">Scope: {html.escape(str(report['scope']['root']))} &middot; {report['scope']['file_count']} documents &middot; {_iso(report['run_at_ms'])}</p>
<div class="tiles">{tiles}</div>
{diff}
{anchor}
<table><thead><tr><th>Document</th><th>Carrier</th><th>Status</th><th>Signer</th><th>Flags</th><th>SHA-256</th></tr></thead>
<tbody>{rows}</tbody></table>
"""


def to_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["path", "carrier", "verified", "flags", "signer", "sha256"])
    for f in report["findings"]:
        w.writerow([f["path"], f["carrier"],
                    {True: "verified", False: "invalid", None: "unsigned"}[f["verified"]],
                    ";".join(f["flags"]), f.get("signer") or "", f["sha256"]])
    return buf.getvalue()
