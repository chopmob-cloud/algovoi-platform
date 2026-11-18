"""Compliance Command Center: bulk volume import, folder watcher, and the SFTP/rsync landing zone.

Drives the ``algovoi-records-vault-importer`` add-on from the console. The operator points the importer at
a server-visible folder (an SFTP/rsync drop, a mounted volume, or any path the console host can read) and
it Merkle-batch-signs the whole estate into the same Records Vault the console browses. The browser is
never the data path, so volume is bounded by disk and hashing, not by an HTTP upload.

Three surfaces on one page:
  * Secure ingest — the SFTP/rsync landing zones (per-source drop folders + live file counts). Host-side
    provisioning of the jailed, write-only drop is documented in ``docs/SECURE_INGEST.md``; the console
    reads the landed files, it does not reconfigure the host sshd.
  * Import        — run a one-shot import of a server path; live progress; recent jobs.
  * Watcher       — enable a folder watcher that imports whenever a drop folder goes quiescent.

Writers are serialized (one import OR the watcher at a time) so the signed archive chain stays linear.
Jobs and watcher state are in-memory and reset on console restart; committed records persist in the vault
and re-runs are idempotent (dedup by content), so a restart never double-commits.
"""
from __future__ import annotations

import asyncio
import html
import os
import threading
import uuid
from datetime import datetime, timezone

STRATEGIES = ("merkle", "falcon")
MODES = ("bridge", "store")

_LOCK = threading.Lock()                 # single active writer (belt-and-suspenders)
_JOBS: dict[str, dict] = {}              # job_id -> record
_JOB_ORDER: list[str] = []
_WATCH: dict = {"thread": None, "stop": None, "path": None, "strategy": None, "mode": None,
                "started_at": None, "cycles": [], "committed": 0, "error": None}


def available() -> bool:
    try:
        import algovoi_records_vault_importer  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ingest_root() -> str:
    return os.environ.get("COMMAND_CENTER_INGEST_DIR", "./evidence-ingest")


def _within_ingest_root(path: str) -> bool:
    """True iff ``path`` resolves under the configured ingest root. The importer notarizes whatever it
    reads and the vault later serves it back decrypted, so an operator must not be able to aim it at
    arbitrary host files (``/root/.ssh``, ``/etc``) outside the intended dropbox. Realpath both sides
    so a symlink can't be used to escape."""
    try:
        root = os.path.realpath(ingest_root())
        cand = os.path.realpath(path)
    except Exception:  # noqa: BLE001
        return False
    return cand == root or cand.startswith(root + os.sep)


def _count_files(p: str) -> int:
    n = 0
    for _dp, _dn, files in os.walk(p):
        n += len(files)
    return n


def landing_zones() -> list[dict]:
    """Drop folders under the ingest root: the root plus each immediate subdir (a per-source dropbox),
    each with a live file count so the operator watches material land before importing it."""
    root = ingest_root()
    out: list[dict] = []
    if os.path.isdir(root):
        out.append({"name": "(root)", "path": root, "files": _count_files(root)})
        for e in sorted(os.listdir(root)):
            fp = os.path.join(root, e)
            if os.path.isdir(fp):
                out.append({"name": e, "path": fp, "files": _count_files(fp)})
    return out


def jobs(limit: int = 12) -> list[dict]:
    return [_JOBS[j] for j in _JOB_ORDER[-limit:][::-1]]


def active_job() -> dict | None:
    for j in _JOBS.values():
        if j.get("status") == "running":
            return j
    return None


def watcher_running() -> bool:
    t = _WATCH["thread"]
    return bool(t is not None and t.is_alive())


# ── import (one-shot) ────────────────────────────────────────────────────────────

def _run_import(archive, path, strategy, mode, batch_size, workers, job) -> None:
    from algovoi_records_vault_importer import import_records_fs

    def _progress(r) -> None:
        job.update(total=r.total, committed=r.committed, skipped=r.skipped, batches=r.batches,
                   signatures=r.signatures, docs_per_sec=round(r.docs_per_sec, 1))

    try:
        with _LOCK:
            r = asyncio.run(import_records_fs(
                archive, path, strategy=strategy, mode=mode, batch_size=batch_size,
                workers=workers, skip_existing=True, progress=_progress))
        job.update(status="done", total=r.total, committed=r.committed, skipped=r.skipped,
                   batches=r.batches, signatures=r.signatures, docs_per_sec=round(r.docs_per_sec, 1),
                   finished_at=_now())
    except Exception as exc:  # noqa: BLE001 — surface on the job, never crash the console
        job.update(status="error", error=str(exc), finished_at=_now())


def start_import(archive, path, *, strategy="merkle", mode="bridge", batch_size=1000, workers=8,
                 principal="") -> tuple[str | None, str]:
    if strategy not in STRATEGIES or mode not in MODES:
        return None, "invalid strategy or mode"
    if not path or not os.path.isdir(path):
        return None, f"not a server directory: {path}"
    if not _within_ingest_root(path):
        return None, "path must be inside the ingest root"
    if active_job() is not None:
        return None, "an import is already running; wait for it to finish"
    if watcher_running():
        return None, "the folder watcher is active; stop it before a manual import"
    job_id = uuid.uuid4().hex[:12]
    job = {"job_id": job_id, "path": path, "strategy": strategy, "mode": mode, "status": "running",
           "total": 0, "committed": 0, "skipped": 0, "batches": 0, "signatures": 0, "docs_per_sec": 0.0,
           "principal": principal, "started_at": _now(), "finished_at": None, "error": None}
    _JOBS[job_id] = job
    _JOB_ORDER.append(job_id)
    threading.Thread(target=_run_import, args=(archive, path, strategy, mode, batch_size, workers, job),
                     daemon=True).start()
    return job_id, "started"


# ── watcher (continuous) ──────────────────────────────────────────────────────────

def _run_watch(archive, path, strategy, mode, batch_size, stop_flag) -> None:
    from algovoi_records_vault_importer import watch

    def _on_cycle(r) -> None:
        if r.committed:
            _WATCH["committed"] += r.committed
            _WATCH["cycles"].append({"at": _now(), "committed": r.committed, "batches": r.batches})
            _WATCH["cycles"][:] = _WATCH["cycles"][-20:]

    def _on_error(exc) -> None:
        _WATCH["error"] = str(exc)

    try:
        asyncio.run(watch(archive, path, strategy=strategy, mode=mode, batch_size=batch_size,
                          poll_secs=10.0, quiescent_secs=5.0, on_cycle=_on_cycle, on_error=_on_error,
                          stop=lambda: stop_flag["v"]))
    except Exception as exc:  # noqa: BLE001
        _WATCH["error"] = str(exc)


def start_watch(archive, path, *, strategy="merkle", mode="bridge", batch_size=1000) -> tuple[bool, str]:
    if strategy not in STRATEGIES or mode not in MODES:
        return False, "invalid strategy or mode"
    if not path or not os.path.isdir(path):
        return False, f"not a server directory: {path}"
    if not _within_ingest_root(path):
        return False, "path must be inside the ingest root"
    if watcher_running():
        return False, "watcher already running"
    if active_job() is not None:
        return False, "an import is running; wait for it to finish"
    stop_flag = {"v": False}
    _WATCH.update(stop=stop_flag, path=path, strategy=strategy, mode=mode, started_at=_now(),
                  cycles=[], committed=0, error=None)
    t = threading.Thread(target=_run_watch, args=(archive, path, strategy, mode, batch_size, stop_flag),
                         daemon=True)
    _WATCH["thread"] = t
    t.start()
    return True, "watcher started"


def stop_watch() -> tuple[bool, str]:
    if _WATCH["stop"] is not None:
        _WATCH["stop"]["v"] = True
    _WATCH["thread"] = None
    return True, "watcher stopping (finishes the current poll, then exits)"


def watch_state() -> dict:
    return {"running": watcher_running(), "path": _WATCH["path"], "strategy": _WATCH["strategy"],
            "mode": _WATCH["mode"], "started_at": _WATCH["started_at"], "committed": _WATCH["committed"],
            "cycles": list(_WATCH["cycles"]), "error": _WATCH["error"]}


# ── themed console page ───────────────────────────────────────────────────────────

def _job_status_pill(s: str) -> str:
    return {"running": '<span class="pill warn">running</span>',
            "done": '<span class="pill ok">done</span>',
            "error": '<span class="pill bad">error</span>'}.get(s, f'<span class="pill neutral">{html.escape(s)}</span>')


def render_ingest_page(archive_ok: bool, *, user: dict, can_manage: bool) -> str:
    from algovoi_command_center import theme
    e = html.escape

    if not available():
        body = ('<div class="panel"><h2>Volume import</h2><div class="desc">The '
                '<code>algovoi-records-vault-importer</code> add-on is not installed on this console.</div></div>')
        return theme.page("Import", body, user=user, active="ingest")
    if not archive_ok:
        body = ('<div class="panel"><h2>Volume import</h2><div class="desc">The Records Vault is not '
                'available on this console, so there is no archive to import into.</div></div>')
        return theme.page("Import", body, user=user, active="ingest")

    zones = landing_zones()
    zrows = "".join(
        f'<tr><td>{e(z["name"])}</td><td class="mono faint">{e(z["path"])}</td>'
        f'<td class="rt">{z["files"]}</td></tr>' for z in zones)
    if not zrows:
        zrows = (f'<tr><td colspan="3" class="muted">No ingest root yet at '
                 f'<span class="mono">{e(ingest_root())}</span>. Create it, or drop files via SFTP/rsync '
                 f'per the Secure Ingest runbook, then import below.</td></tr>')
    secure = (
        '<div class="panel"><h2>Secure ingest &mdash; SFTP / rsync landing zones</h2>'
        '<div class="desc">Files arrive over SFTP or rsync into a per-source drop folder on this host, '
        'then get imported below. The console reads the landed files; the jailed, write-only drop '
        '(chroot SFTP + <code>rrsync -wo</code>) is provisioned on the host per '
        '<code>docs/SECURE_INGEST.md</code>. Never upload bulk volumes through the browser.</div>'
        '<table><thead><tr><th>Source</th><th>Path</th><th class="rt">Files waiting</th></tr></thead>'
        f'<tbody>{zrows}</tbody></table></div>')

    ws = watch_state()
    running = ws["running"]
    active = active_job()
    busy = running or (active is not None)

    def _sel(name, opts, cur=None):
        return (f'<select name="{name}">'
                + "".join(f'<option value="{o}"{" selected" if o == cur else ""}>{o}</option>' for o in opts)
                + '</select>')

    imp = ""
    if can_manage:
        disabled = ' disabled' if busy else ''
        note = ('<div class="hint">An import or the watcher is currently active; only one writer runs at a '
                'time.</div>') if busy else ''
        imp = (
            '<div class="panel"><h2>Run an import</h2>'
            '<div class="desc">Point the importer at a server path. <b>merkle</b> signs one Falcon-1024 '
            'signature per batch (throughput bound by read/hash); <b>bridge</b> records hashes only, '
            '<b>store</b> also encrypts and stores the bytes. Re-runs skip anything already committed.</div>'
            '<form method="post" action="/ingest/import">'
            f'<label>Server path</label><input name="path" placeholder="{e(ingest_root())}/acme" required>'
            '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:6px">'
            f'<div><label>Strategy</label>{_sel("strategy", STRATEGIES, "merkle")}</div>'
            f'<div><label>Mode</label>{_sel("mode", MODES, "bridge")}</div>'
            '<div><label>Batch size</label><input name="batch_size" value="1000" inputmode="numeric" style="width:110px"></div>'
            '</div>'
            '<label>Confirm your password</label>'
            '<input name="confirm_password" type="password" autocomplete="current-password" required>'
            f'<button class="btn primary" type="submit" style="margin-top:14px"{disabled}>Start import</button>'
            f'{note}</form></div>')

    # watcher panel
    if running:
        crows = "".join(f'<tr><td class="muted mono">{e(c["at"])}</td><td class="rt">{c["committed"]}</td>'
                        f'<td class="rt">{c["batches"]}</td></tr>' for c in ws["cycles"][::-1])
        crows = crows or '<tr><td colspan="3" class="muted">No committing cycle yet (waiting for a quiescent drop).</td></tr>'
        stopbtn = ('<form method="post" action="/ingest/watch/stop" style="display:inline">'
                   '<button class="btn danger" type="submit">Stop watcher</button></form>') if can_manage else ''
        werr = f'<div class="hint" style="color:var(--bad)">last error: {e(ws["error"])}</div>' if ws["error"] else ''
        watcher = (
            '<div class="panel"><h2>Folder watcher '
            f'<span class="pill ok">running</span></h2>'
            f'<div class="desc">Watching <span class="mono">{e(ws["path"] or "")}</span> '
            f'({e(ws["strategy"] or "")}/{e(ws["mode"] or "")}), since {e(ws["started_at"] or "")}. '
            f'Imports whenever the folder is quiescent for 5s. {ws["committed"]} committed so far.</div>'
            f'{stopbtn}{werr}'
            '<table style="margin-top:12px"><thead><tr><th>Cycle</th><th class="rt">Committed</th>'
            f'<th class="rt">Batches</th></tr></thead><tbody>{crows}</tbody></table></div>')
    else:
        wform = ""
        if can_manage:
            wdis = ' disabled' if active is not None else ''
            wform = (
                '<form method="post" action="/ingest/watch/start">'
                f'<label>Drop folder to watch</label><input name="path" placeholder="{e(ingest_root())}/acme" required>'
                '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:6px">'
                f'<div><label>Strategy</label>{_sel("strategy", STRATEGIES, "merkle")}</div>'
                f'<div><label>Mode</label>{_sel("mode", MODES, "bridge")}</div></div>'
                '<label>Confirm your password</label>'
                '<input name="confirm_password" type="password" autocomplete="current-password" required>'
                f'<button class="btn primary" type="submit" style="margin-top:14px"{wdis}>Enable watcher</button>'
                '</form>')
        watcher = ('<div class="panel"><h2>Folder watcher <span class="pill neutral">off</span></h2>'
                   '<div class="desc">Continuously import a drop folder whenever it goes quiescent, for a '
                   'standing SFTP/rsync feed. One writer at a time, so a manual import must finish first.</div>'
                   + wform + '</div>')

    # recent jobs
    jrows = ""
    for j in jobs():
        jrows += (
            f'<tr><td class="mono">{e(j["job_id"])}</td>'
            f'<td class="mono faint">{e(j["path"])}</td>'
            f'<td>{e(j["strategy"])}/{e(j["mode"])}</td>'
            f'<td class="rt">{j["committed"]}/{j["total"]}</td>'
            f'<td class="rt">{j["skipped"]}</td>'
            f'<td class="rt">{j["batches"]}</td>'
            f'<td class="rt">{j["docs_per_sec"]:.0f}</td>'
            f'<td>{_job_status_pill(j["status"])}'
            + (f'<div class="hint" style="color:var(--bad)">{e(j["error"] or "")}</div>' if j["status"] == "error" else "")
            + '</td></tr>')
    jrows = jrows or '<tr><td colspan="8" class="muted">No imports yet.</td></tr>'
    jobs_panel = (
        '<div class="panel"><h2>Recent imports</h2>'
        '<table><thead><tr><th>Job</th><th>Path</th><th>Mode</th><th class="rt">Committed</th>'
        '<th class="rt">Skipped</th><th class="rt">Batches</th><th class="rt">docs/s</th><th>Status</th>'
        f'</tr></thead><tbody>{jrows}</tbody></table></div>')

    # live refresh while something is running (CSP allows inline script)
    refresh = '<script>setTimeout(function(){location.reload()},3000)</script>' if busy else ''
    subtitle = "Bulk volume import into the Records Vault, batch-signed and offline-verifiable"
    return theme.page("Import", secure + imp + watcher + jobs_panel + refresh,
                      user=user, active="ingest", subtitle=subtitle)
