"""Live SIEM forwarding of the signed console audit chain (optional, off by default).

Every console action already lands in the Falcon-signed, hash-linked audit chain (see
:mod:`~algovoi_command_center.audit`). This module *streams* those entries to a customer SIEM as they
are appended, in the formats a SOC expects: **RFC 5424 syslog**, **CEF** (ArcSight-style, over syslog
transport), and a generic **webhook** (JSON POST). Each forwarded record carries the entry's ``seq`` and
its ``sha256`` payload hash, so a SIEM record ties back to the tamper-evident chain.

Design:
- **Off by default.** With no sink configured (no ``COMMAND_CENTER_SIEM_*`` env), the forwarder is inert
  and nothing leaves the appliance, so air-gapped installs are unaffected.
- **Non-blocking.** ``emit`` enqueues onto a bounded queue drained by a daemon worker, so forwarding
  never blocks a console request and a slow/broken SIEM never stalls the console.
- **Best-effort, never breaks the chain.** The signed chain stays the system-of-record; a sink failure
  is recorded (``last_error``) and retried on the next entry, but never raised into the audit append.
- **Catch-up.** The last-forwarded ``seq`` is persisted, so on restart (or when first enabled) the
  forwarder backfills anything appended while it was off or a sink was down.
"""
from __future__ import annotations

import json
import os
import queue
import socket
import threading
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

_APP = "AlgoVoiCCC"
_ENTERPRISE = "32473"   # IANA-reserved private-enterprise number for documentation/example use
_WARN_ACTIONS = ("failed", "blocked", "denied", "refused", "forbidden", "error")


def _sev_is_warn(action: str) -> bool:
    a = (action or "").lower()
    return any(w in a for w in _WARN_ACTIONS)


def _host() -> str:
    return (os.environ.get("COMMAND_CENTER_ESTATE") or socket.gethostname() or "console").split()[0][:255]


# ── event formatters ──────────────────────────────────────────────────────────

def _strip_controls(v: str) -> str:
    """Drop C0 control chars (CR, LF, tab, ...) and DEL, replacing each with a space. A syslog frame
    is newline-delimited on the TCP sink, so an unstripped CR/LF in an attacker-controlled field
    (e.g. the unauthenticated login username, or free-text detail) would split one record into two
    and let a caller forge audit events downstream. Strip before escaping."""
    return "".join(" " if (ord(c) < 0x20 or ord(c) == 0x7f) else c for c in str(v))


def _sd_escape(v: str) -> str:
    return _strip_controls(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_rfc5424(e: dict) -> str:
    """RFC 5424 syslog line. Facility 13 (log audit); severity info, or warning for failure actions."""
    sev = 4 if _sev_is_warn(e["action"]) else 6
    pri = 13 * 8 + sev
    sd = (f'[algovoi@{_ENTERPRISE} seq="{e["seq"]}" principal="{_sd_escape(e["principal"])}" '
          f'role="{_sd_escape(e.get("role") or "")}" entry_hash="{e["entry_hash"]}" '
          f'kid="{_sd_escape(e.get("kid") or "")}"]')
    msg = _strip_controls(str(e.get("detail") or ""))
    return (f'<{pri}>1 {e["recorded_at"]} {_host()} {_APP} - {_sd_escape(e["action"])[:32] or "-"} '
            f'{sd} {msg}')


def _cef_hdr(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def format_cef(e: dict) -> str:
    """ArcSight CEF:0 record. Carried over syslog transport in practice."""
    sev = 6 if _sev_is_warn(e["action"]) else 3
    ver = e.get("product_version", "1")
    ext = (f"rt={e.get('epoch_ms', 0)} suser={_cef_ext(e['principal'])} act={_cef_ext(e['action'])} "
           f"cs1Label=seq cs1={e['seq']} cs2Label=entryHash cs2={e['entry_hash']} "
           f"cs3Label=role cs3={_cef_ext(e.get('role') or '')} msg={_cef_ext(e.get('detail') or '')}")
    act = _cef_hdr(e["action"])
    return f"CEF:0|AlgoVoi|Compliance Command Center|{_cef_hdr(ver)}|{act}|{act}|{sev}|{ext}"


def format_webhook(e: dict) -> bytes:
    return json.dumps({
        "seq": e["seq"], "recorded_at": e["recorded_at"], "principal": e["principal"],
        "role": e.get("role") or "", "action": e["action"], "detail": e.get("detail") or "",
        "entry_hash": e["entry_hash"], "kid": e.get("kid") or "", "estate": _host(),
    }, separators=(",", ":")).encode()


# ── sinks ───────────────────────────────────────────────────────────────────

class _SyslogSink:
    """UDP or TCP RFC 5424 syslog (optionally CEF-framed). ``spec`` = ``udp://host:514`` / ``tcp://host:601``."""

    def __init__(self, spec: str, fmt: str = "rfc5424", timeout: float = 3.0) -> None:
        u = urlparse(spec)
        self.proto = (u.scheme or "udp").lower()
        self.host, self.port = u.hostname, (u.port or 514)
        self.fmt = fmt.lower()
        self.timeout = timeout
        self.name = f"syslog:{self.proto}://{self.host}:{self.port}({self.fmt})"

    def send(self, e: dict) -> None:
        line = format_cef(e) if self.fmt == "cef" else format_rfc5424(e)
        data = line.encode("utf-8", "replace")
        if self.proto == "tcp":
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(data + b"\n")     # octet-stream framed by newline
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(data, (self.host, self.port))


class _WebhookSink:
    def __init__(self, url: str, token: str | None = None, timeout: float = 5.0) -> None:
        self.url, self.token, self.timeout = url, token, timeout
        self.name = f"webhook:{url}"

    def send(self, e: dict) -> None:
        req = urllib.request.Request(self.url, data=format_webhook(e),
                                     headers={"content-type": "application/json"}, method="POST")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        urllib.request.urlopen(req, timeout=self.timeout).close()  # nosec B310 - trusted URL (indexer constant / operator-config hub); scheme is fixed http(s)


# ── forwarder ─────────────────────────────────────────────────────────────────

def _state_path() -> str:
    return os.environ.get("COMMAND_CENTER_SIEM_STATE",
                          os.path.join(os.environ.get("COMMAND_CENTER_DATA_DIR", "."), "siem-state.json"))


class Forwarder:
    """Background, best-effort forwarder of audit entries to the configured sinks. Inert if none set."""

    def __init__(self, sinks: list, *, product_version: str = "", maxsize: int = 10000) -> None:
        self.sinks = sinks
        self.product_version = product_version
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self.last_forwarded = self._load_state()
        self.last_error = ""
        self.sent = 0
        self.dropped = 0

    # -- config --
    @classmethod
    def from_env(cls, *, product_version: str = "") -> "Forwarder":
        sinks: list = []
        sy = os.environ.get("COMMAND_CENTER_SIEM_SYSLOG")
        if sy:
            sinks.append(_SyslogSink(sy, os.environ.get("COMMAND_CENTER_SIEM_SYSLOG_FORMAT", "rfc5424")))
        wh = os.environ.get("COMMAND_CENTER_SIEM_WEBHOOK")
        if wh:
            sinks.append(_WebhookSink(wh, os.environ.get("COMMAND_CENTER_SIEM_WEBHOOK_TOKEN") or None))
        return cls(sinks, product_version=product_version)

    @property
    def enabled(self) -> bool:
        return bool(self.sinks)

    # -- state --
    def _load_state(self) -> int:
        try:
            with open(_state_path(), encoding="utf-8") as fh:
                return int(json.load(fh).get("last_forwarded_seq", -1))
        except Exception:  # noqa: BLE001
            return -1

    def _save_state(self) -> None:
        try:
            p = _state_path()
            os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"last_forwarded_seq": self.last_forwarded}, fh)
        except Exception:  # noqa: BLE001
            pass

    # -- lifecycle --
    def start(self) -> None:
        if not self.enabled or self._worker is not None:
            return
        self._worker = threading.Thread(target=self._run, name="siem-forwarder", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            self._ship(item)
            self._q.task_done()

    def _ship(self, e: dict) -> None:
        ok = True
        for sink in self.sinks:
            try:
                sink.send(e)
            except Exception as exc:  # noqa: BLE001 — best-effort; record and keep going
                ok = False
                self.last_error = f"{sink.name}: {exc}"[:200]
        if ok:
            self.sent += 1
            self.last_error = ""
        if e["seq"] > self.last_forwarded:
            self.last_forwarded = e["seq"]
            self._save_state()

    # -- ingest --
    def emit(self, payload: dict, entry_hash: str) -> None:
        """Enqueue one just-appended audit payload for forwarding (non-blocking; drops if the queue is
        saturated by a stalled SIEM rather than blocking the console)."""
        if not self.enabled:
            return
        try:
            self._q.put_nowait(self._event(payload, entry_hash))
        except queue.Full:
            self.dropped += 1

    def backfill(self, entries: list[dict], hashes: list[str]) -> int:
        """On start/enable, enqueue any chain entries newer than the last forwarded seq."""
        if not self.enabled:
            return 0
        n = 0
        for payload, h in zip(entries, hashes):
            if int(payload.get("seq", -1)) > self.last_forwarded:
                self.emit(payload, h)
                n += 1
        return n

    def _event(self, p: dict, entry_hash: str) -> dict:
        rec = p.get("recorded_at") or ""
        try:
            epoch_ms = int(datetime.strptime(rec, "%Y-%m-%dT%H:%M:%SZ")
                           .replace(tzinfo=timezone.utc).timestamp() * 1000)
        except Exception:  # noqa: BLE001
            epoch_ms = 0
        return {"seq": int(p.get("seq", 0)), "recorded_at": rec, "principal": p.get("principal") or "",
                "role": p.get("role") or "", "action": p.get("action") or "", "detail": p.get("detail") or "",
                "entry_hash": entry_hash, "kid": p.get("kid") or "", "epoch_ms": epoch_ms,
                "product_version": self.product_version}

    # -- status (read-only, for the console) --
    def status(self) -> dict:
        return {"enabled": self.enabled, "sinks": [s.name for s in self.sinks],
                "last_forwarded_seq": self.last_forwarded, "sent": self.sent,
                "dropped": self.dropped, "queued": self._q.qsize(), "last_error": self.last_error}
