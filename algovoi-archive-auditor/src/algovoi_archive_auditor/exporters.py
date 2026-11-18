"""
Export adapters — feed audit events and metrics into existing tools, don't reinvent them.

- :func:`to_jsonl` — JSON-lines for Splunk / Elastic / Datadog ingest.
- :func:`to_syslog` — RFC 5424-style lines for any syslog/SIEM collector.
- :func:`to_cef` — ArcSight / SIEM Common Event Format.
- :func:`to_csv` — for GRC / BI import.
- :func:`to_prometheus` — exposition format for Prometheus → Grafana dashboards + alerts.
"""
from __future__ import annotations

import csv
import io
import json


def to_jsonl(events: list[dict]) -> str:
    return "\n".join(json.dumps(e, separators=(",", ":"), sort_keys=True) for e in events)


def to_csv(rows: list[dict], fields: list[str] | None = None) -> str:
    if not rows:
        return ""
    fields = fields or list(rows[0].keys())
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def to_syslog(events: list[dict], *, facility: int = 16, severity: int = 6,
              host: str = "archive-auditor", app: str = "algovoi-archive-auditor") -> str:
    pri = facility * 8 + severity
    out = []
    for e in events:
        ts = e.get("ts") or e.get("attested_at") or e.get("generated_at") or "-"
        out.append(f"<{pri}>1 {ts} {host} {app} - - - " + json.dumps(e, separators=(",", ":"), sort_keys=True))
    return "\n".join(out)


_CEF_SEVERITY = {"valid": 2, "broken": 9}


def _cef_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_cef(events: list[dict], *, vendor: str = "AlgoVoi", product: str = "ArchiveAuditor",
           version: str = "1.0") -> str:
    out = []
    for e in events:
        name = e.get("event", "archive.event")
        sev = _CEF_SEVERITY.get(str(e.get("result")), 5)
        ext = " ".join(f"{k}={_cef_escape(str(v))}" for k, v in e.items() if k != "event")
        out.append(f"CEF:0|{vendor}|{product}|{version}|{name}|{name}|{sev}|{ext}")
    return "\n".join(out)


def to_prometheus(*, archive_kid: str, chain_valid: bool, entries: int, broken_at: int | None,
                  last_verified_epoch: int, bytes_stored: int = 0) -> str:
    lbl = f'{{archive_kid="{archive_kid}"}}'
    lines = [
        "# HELP archive_chain_valid 1 if the archive chain verified intact, else 0",
        "# TYPE archive_chain_valid gauge",
        f"archive_chain_valid{lbl} {1 if chain_valid else 0}",
        "# HELP archive_entries_total number of entries in the archive chain",
        "# TYPE archive_entries_total gauge",
        f"archive_entries_total{lbl} {entries}",
        "# HELP archive_chain_broken_at index of the first broken entry, -1 if intact",
        "# TYPE archive_chain_broken_at gauge",
        f"archive_chain_broken_at{lbl} {broken_at if broken_at is not None else -1}",
        "# HELP archive_bytes_stored_total total stored document bytes (plaintext sizes)",
        "# TYPE archive_bytes_stored_total gauge",
        f"archive_bytes_stored_total{lbl} {bytes_stored}",
        "# HELP archive_last_verified_timestamp_seconds unix time of last verification",
        "# TYPE archive_last_verified_timestamp_seconds gauge",
        f"archive_last_verified_timestamp_seconds{lbl} {last_verified_epoch}",
    ]
    return "\n".join(lines) + "\n"
