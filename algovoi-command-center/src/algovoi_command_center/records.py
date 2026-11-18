"""Compliance Command Center binding for the Records Vault.

Turns the console into a command centre over a self-hosted, offline-verifiable regulated-records
archive: browse notarized records and re-verify the signed chain, retrieve a stored document,
place / release **legal holds**, run the **retention + disposition** queue, and surface the signed
evidence streams (consent receipts, chain-of-custody, key custody + rotation proofs, redactions).

The heavy lifting lives in the ``algovoi-records-vault`` product (over ``algovoi-doc-archive``); this
module is a thin, lazily-imported binding so the console still runs if the product is not installed or
not licensed (the feature simply reports as unavailable). Everything the vault signs is signed with the
**console key**, so the one published console public key offline-verifies the archive chain and every
evidence chain — exactly as the sealed-container binding reuses the console key.
"""
from __future__ import annotations

import base64
import html
import os
from datetime import datetime, timezone

_VAULT = None


class _ArchiveSigner:
    """Adapt the console signer to the ``algovoi-doc-archive`` Signer protocol.

    The console signer (local / KMS / Vault) already provides ``sign`` / ``public_key`` / ``kid`` — the
    same interface the sealed-container feature drives — but the archive engine additionally calls
    ``can_sign()``. This thin wrapper adds it (the console identity is always signing-capable) and
    delegates everything else, so the archive and every evidence stream are signed by the console key.
    """

    def __init__(self, inner) -> None:
        self._inner = inner

    def public_key(self) -> bytes:
        return self._inner.public_key()

    def kid(self) -> str:
        return self._inner.kid()

    def sign(self, message: bytes) -> bytes:
        return self._inner.sign(message)

    def can_sign(self) -> bool:
        return True


def available() -> bool:
    try:
        import algovoi_records_vault  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _records_dir() -> str:
    return os.environ.get("COMMAND_CENTER_RECORDS_DIR", "./command-center-records")


def _retention_days() -> int:
    """Routine disposal window for the disposition queue. Defaults to 7 years (a common regulated
    floor); a legal hold always overrides it, so a held record is never disposable."""
    try:
        return int(os.environ.get("COMMAND_CENTER_RETENTION_DAYS", "2555"))
    except ValueError:
        return 2555


def get_vault(console_signer):
    """A process-wide RecordsVault over a local archive signed by the console key, or None if the
    product is absent / unlicensed. Documents are encrypted at rest to the console ML-KEM escrow key
    (the same key the sealed-container feature bootstraps), so the console can retrieve them."""
    global _VAULT
    if _VAULT is not None:
        return _VAULT
    if not available():
        return None
    try:
        from algovoi_doc_archive.archive import Archive
        from algovoi_doc_archive.backend import LocalFsBackend
        from algovoi_doc_archive.encryption import HybridPqcEncryptor
        from algovoi_records_vault import RecordsVault
        from algovoi_command_center import containers as _containers

        epk, esk = _containers._escrow_keypair()
        enc = HybridPqcEncryptor(epk, esk) if epk else None
        base = _records_dir()
        archive = Archive(
            storage=LocalFsBackend(os.path.join(base, "archive")),
            signer=_ArchiveSigner(console_signer), encryptor=enc,
            issuer_did=os.environ.get("COMMAND_CENTER_ISSUER_DID", "did:web:console.local"))
        _VAULT = RecordsVault(archive=archive)
        globals()["_ARCHIVE"] = archive
    except Exception:  # noqa: BLE001 — not installed / not licensed / no PQC: degrade gracefully
        return None
    return _VAULT


_ARCHIVE = None


def get_archive(console_signer):
    """The same console-signed archive the vault writes to, for the volume importer to land records into
    the operator's own vault. None if the Records Vault is unavailable."""
    if _ARCHIVE is None:
        get_vault(console_signer)
    return _ARCHIVE


# ── read helpers ─────────────────────────────────────────────────────────────────

def _record_view(payload: dict) -> dict:
    """Flatten an archive receipt into a hold-matchable record view: the archive stores caller fields
    under ``metadata``; a hold query matches ``subject_ref`` / ``content_type`` / ``doc_hash`` /
    ``date_range`` at the top level, so lift the metadata up (top-level keys win)."""
    md = payload.get("metadata") or {}
    view = {**md}
    view.update({
        "seq": payload.get("seq"),
        "doc_hash": payload.get("doc_hash"),
        "doc_size": payload.get("doc_size"),
        "content_type": payload.get("content_type"),
        "title": payload.get("title"),
        "stored": payload.get("stored"),
        "enc_alg": payload.get("enc_alg"),
        "archived_at": payload.get("archived_at"),
    })
    return view


async def list_records(vault) -> list[dict]:
    """All notarized records (flattened views), newest last."""
    from algovoi_doc_archive import signing
    out: list[dict] = []
    for env in await vault.archive.list_entries():
        try:
            payload = signing.open_envelope(env)[0]
        except Exception:  # noqa: BLE001
            continue
        out.append(_record_view(payload))
    return out


async def posture(vault) -> dict:
    """Summary counts for the header + dashboard tile."""
    if vault is None:
        return {"available": False, "records": 0, "held": 0, "disposable": 0, "verified": None}
    from algovoi_records_vault.legal_hold import RetentionPolicy
    records = await list_records(vault)
    holds = vault.holds(retention_days=_retention_days(), use_env_bridge=False)
    try:
        active = await holds.active_holds()
    except Exception:  # noqa: BLE001
        active = []
    chain_ok = None
    try:
        chain_ok = bool((await vault.archive.verify_chain()).valid)
    except Exception:  # noqa: BLE001
        chain_ok = None
    # count records disposable now (retention elapsed AND not held), verifying the holds chain once
    retention = RetentionPolicy(_retention_days())
    now = datetime.now(timezone.utc)
    disposable = 0
    try:
        await _ensure_holds_valid(holds)
        for r in records:
            if retention.is_disposable(r, now=now, held=await holds.is_held(r, verify=False)):
                disposable += 1
    except Exception:  # noqa: BLE001
        disposable = 0
    return {"available": True, "records": len(records), "held_matters": len(active),
            "disposable": disposable, "verified": chain_ok, "retention_days": _retention_days()}


async def _ensure_holds_valid(holds) -> None:
    """Verify the holds chain once (fail-closed) before a bulk disposition sweep reads it repeatedly."""
    # is_held(verify=True) does this per-call; for a sweep we verify once then pass verify=False.
    from algovoi_records_vault.vault import ensure_chain_valid
    await ensure_chain_valid(holds._stream, "holds")


async def notarize_record(vault, *, title: str, content_type: str, data: bytes,
                          subject_ref: str = "") -> dict:
    """Notarize (and store, encrypted) a document into the archive + trusted-timestamp the receipt."""
    metadata = {"subject_ref": subject_ref} if subject_ref else {}
    res = await vault.notarize(data=data, title=title, content_type=content_type,
                              metadata=metadata, time_stamp=True)
    entry = res["archive"]
    return {"seq": entry["seq"], "doc_hash": entry["doc_hash"], "stored": entry["stored"],
            "archived_at": entry["archived_at"], "timestamped": res.get("tsa") is not None}


async def retrieve_record(vault, *, doc_hash: str) -> dict:
    """Retrieve + decrypt a stored document, returning its bytes base64 (the operator saves them).
    A signed read-access event is appended first, whether granted or denied."""
    data = await vault.retrieve(doc_hash=doc_hash, reason="console retrieve")
    return {"doc_hash": doc_hash, "size": len(data), "data_b64": base64.b64encode(data).decode()}


async def verify_all(vault) -> dict:
    """Offline whole-vault verification: the archive chain and every evidence stream."""
    res = await vault.verify_all_chains()
    return {name: {"valid": bool(r.valid), "length": r.length,
                   "reason": getattr(r, "reason", None)} for name, r in res.items()}


# ── themed console panels ─────────────────────────────────────────────────────────

def _unavailable(user, active, what: str) -> str:
    from algovoi_command_center import theme
    body = (f'<div class="panel"><h2>{html.escape(what)}</h2><div class="desc">The '
            '<code>algovoi-records-vault</code> product is not installed or not licensed on this '
            'console.</div></div>')
    return theme.page(what, body, user=user, active=active)


def _chain_pill(ok) -> str:
    if ok is None:
        return '<span class="pill neutral">&#9679; not yet verified</span>'
    return ('<span class="pill ok">&#10003; chain verified</span>' if ok
            else '<span class="pill bad">&#9888; verification failed</span>')


async def render_records_page(vault, user: dict, *, can_manage: bool) -> str:
    from algovoi_command_center import theme
    if vault is None:
        return _unavailable(user, "records", "Records")
    p = await posture(vault)
    records = await list_records(vault)
    holds = vault.holds(retention_days=_retention_days(), use_env_bridge=False)
    # verify the holds chain once, then test each record without re-verifying
    held_flags: dict[int, bool] = {}
    try:
        await _ensure_holds_valid(holds)
        for r in records:
            held_flags[r["seq"]] = await holds.is_held(r, verify=False)
    except Exception:  # noqa: BLE001
        held_flags = {}
    rows = []
    for r in reversed(records):
        h = r.get("doc_hash") or ""
        held = held_flags.get(r["seq"], False)
        badge = ' <span class="pill bad" title="under legal hold">hold</span>' if held else ""
        btn = ""
        if can_manage and r.get("stored"):
            btn = (f"<form method='post' action='/records/retrieve' style='display:inline'>"
                   f"<input type='hidden' name='doc_hash' value='{html.escape(h)}'>"
                   f"<button class='btn' type='submit'>Retrieve</button></form>")
        rows.append(
            f'<tr><td class="rt mono">{r.get("seq")}</td>'
            f'<td>{html.escape(r.get("title") or "")}{badge}</td>'
            f'<td class="mono faint">{html.escape(h[:22])}</td>'
            f'<td class="muted">{html.escape(r.get("content_type") or "")}</td>'
            f'<td class="rt muted">{r.get("doc_size") if r.get("doc_size") is not None else "&mdash;"}</td>'
            f'<td class="muted mono">{html.escape(r.get("archived_at") or "")}</td>'
            f'<td class="rt">{btn}</td></tr>')
    table = ('<div class="panel"><h2>Notarized records</h2>'
             '<div class="desc">Each row is a Falcon-signed, hash-linked archive receipt. '
             'Retrieve decrypts a stored document and writes a signed read-access event.</div>'
             '<table><thead><tr><th class="rt">#</th><th>Title</th><th>Doc hash</th>'
             '<th>Type</th><th class="rt">Bytes</th><th>Archived</th><th></th></tr></thead>'
             f'<tbody>{"".join(rows) or "<tr><td class=muted>No records notarized yet.</td></tr>"}'
             '</tbody></table></div>')
    add = ""
    if can_manage:
        add = (
            '<div class="panel"><h2>Notarize a record</h2>'
            '<form method="post" action="/records/notarize">'
            '<label>Title</label><input name="title" placeholder="Q3 board minutes" required>'
            '<label>Subject reference (optional)</label>'
            '<input name="subject_ref" placeholder="customer-4821">'
            '<div class="hint">A subject reference lets a legal hold or erasure request target this '
            'record precisely.</div>'
            '<label>Content type</label><input name="content_type" value="text/plain">'
            '<label>Document contents</label><textarea name="doc_text" required></textarea>'
            '<label>Confirm your password</label>'
            '<input name="confirm_password" type="password" autocomplete="current-password" required>'
            '<div class="hint">Notarizing a record requires re-entering your password.</div>'
            '<button class="btn primary" type="submit" style="margin-top:16px">Notarize &amp; timestamp</button>'
            '</form></div>')
    subtitle = (f'{p["records"]} record(s) &middot; {p["held_matters"]} active hold(s) &middot; '
                f'{p["disposable"]} disposable now')
    right = (_chain_pill(p["verified"])
             + '<a class="btn" href="/records/holds">Legal holds</a>'
             + '<a class="btn" href="/records/disposition">Disposition</a>'
             + '<a class="btn" href="/records/evidence">Evidence</a>')
    return theme.page("Records", table + add, user=user, active="records",
                      subtitle=subtitle, extra_right=right)


async def render_holds_page(vault, user: dict, *, can_manage: bool) -> str:
    from algovoi_command_center import theme
    if vault is None:
        return _unavailable(user, "records", "Legal holds")
    holds = vault.holds(retention_days=_retention_days(), use_env_bridge=False)
    try:
        chain_ok = bool((await holds.verify_chain()).valid)
        active = await holds.active_holds()
    except Exception:  # noqa: BLE001
        chain_ok, active = None, []
    rows = []
    for h in active:
        q = h.get("query") or {}
        scope = ", ".join(f"{k}={v}" for k, v in q.items()) if q else "all records (full custodial)"
        blocked = h.get("release_blocked_until") or "&mdash;"
        rel = ""
        if can_manage:
            mid = html.escape(h.get("matter_id") or "")
            rel = (f"<form method='post' action='/records/holds/release' style='display:inline' "
                   f"onsubmit=\"return confirm('Release hold on matter {mid}?')\">"
                   f"<input type='hidden' name='matter_id' value='{mid}'>"
                   f"<input type='hidden' name='reason' value='released via console'>"
                   f"<button class='btn danger' type='submit'>Release</button></form>")
        rows.append(
            f'<tr><td class="mono">{html.escape(h.get("matter_id") or "")}</td>'
            f'<td class="muted">{html.escape(scope)}</td>'
            f'<td>{html.escape(h.get("reason") or "")}</td>'
            f'<td class="muted mono">{html.escape(h.get("hold_set_at") or "")}</td>'
            f'<td class="muted mono">{html.escape(str(blocked))}</td>'
            f'<td class="rt">{rel}</td></tr>')
    table = ('<div class="panel"><h2>Active legal holds</h2>'
             '<div class="desc">A litigation / investigation hold overrides routine disposal: a held '
             'record can never be purged, and a hold cannot be released before its preservation floor. '
             'Every set and release is a signed, append-only chain entry.</div>'
             '<table><thead><tr><th>Matter</th><th>Scope</th><th>Reason</th><th>Set</th>'
             '<th>Release blocked until</th><th></th></tr></thead>'
             f'<tbody>{"".join(rows) or "<tr><td class=muted>No active holds.</td></tr>"}'
             '</tbody></table></div>')
    place = ""
    if can_manage:
        place = (
            '<div class="panel"><h2>Place a legal hold</h2>'
            '<form method="post" action="/records/holds/place">'
            '<label>Matter ID</label><input name="matter_id" placeholder="LIT-2026-014" required>'
            '<label>Scope &mdash; subject reference (optional)</label>'
            '<input name="subject_ref" placeholder="customer-4821">'
            '<div class="hint">Leave scope empty for a full custodial hold over every record.</div>'
            '<label>Reason</label><input name="reason" placeholder="anticipated litigation" required>'
            '<label>Preservation floor (days, optional)</label>'
            '<input name="preservation_days" inputmode="numeric" placeholder="1825">'
            '<div class="hint">The hold cannot be released until this many days pass '
            f'(defaults to the {_retention_days()}-day retention window).</div>'
            '<label>Confirm your password</label>'
            '<input name="confirm_password" type="password" autocomplete="current-password" required>'
            '<button class="btn primary" type="submit" style="margin-top:16px">Place hold</button>'
            '</form></div>')
    right = _chain_pill(chain_ok) + '<a class="btn" href="/records">Records</a>'
    return theme.page("Legal holds", table + place, user=user, active="records",
                      subtitle=f"{len(active)} active hold(s)", extra_right=right)


async def render_disposition_page(vault, user: dict, *, can_manage: bool) -> str:
    from algovoi_command_center import theme
    if vault is None:
        return _unavailable(user, "records", "Disposition")
    from algovoi_records_vault.legal_hold import RetentionPolicy
    records = await list_records(vault)
    holds = vault.holds(retention_days=_retention_days(), use_env_bridge=False)
    retention = RetentionPolicy(_retention_days())
    now = datetime.now(timezone.utc)
    chain_ok = None
    due, held_blocked = [], 0
    try:
        chain_ok = bool((await holds.verify_chain()).valid)
        await _ensure_holds_valid(holds)
        for r in records:
            is_held = await holds.is_held(r, verify=False)
            disp_at = retention.disposable_at(r)
            if disp_at is None:
                continue
            if now >= disp_at:
                if is_held:
                    held_blocked += 1
                else:
                    due.append((r, disp_at))
    except Exception:  # noqa: BLE001
        chain_ok = None
    rows = []
    for r, disp_at in due:
        rows.append(
            f'<tr><td class="rt mono">{r.get("seq")}</td>'
            f'<td>{html.escape(r.get("title") or "")}</td>'
            f'<td class="mono faint">{html.escape((r.get("doc_hash") or "")[:22])}</td>'
            f'<td class="muted mono">{html.escape(r.get("archived_at") or "")}</td>'
            f'<td class="muted mono">{html.escape(disp_at.strftime("%Y-%m-%dT%H:%M:%SZ"))}</td></tr>')
    table = ('<div class="panel"><h2>Eligible for disposition</h2>'
             f'<div class="desc">Retention window is {_retention_days()} days. These records have passed '
             'it and are under no legal hold. Disposition is a deliberate, operator-driven action &mdash; '
             'the queue never purges automatically.</div>'
             '<table><thead><tr><th class="rt">#</th><th>Title</th><th>Doc hash</th>'
             '<th>Archived</th><th>Disposable since</th></tr></thead>'
             f'<tbody>{"".join(rows) or "<tr><td class=muted>Nothing is eligible for disposition.</td></tr>"}'
             '</tbody></table></div>')
    note = (f'<div class="callout"><span>&#128274;</span><div>{held_blocked} record(s) have passed '
            'retention but are <b>preserved under an active legal hold</b> and are therefore not '
            'disposable.</div></div>') if held_blocked else ""
    right = _chain_pill(chain_ok) + '<a class="btn" href="/records">Records</a>'
    return theme.page("Disposition", table + note, user=user, active="records",
                      subtitle=f"{len(due)} eligible &middot; {held_blocked} hold-preserved",
                      extra_right=right)


async def render_evidence_page(vault, user: dict) -> str:
    """Read-only surfacing of the vault's signed evidence streams: consent receipts, chain-of-custody,
    key custody + rotation proofs, and redaction / crypto-shred records. Each is offline-verifiable."""
    from algovoi_command_center import theme
    if vault is None:
        return _unavailable(user, "records", "Evidence streams")
    checks = await verify_all(vault)
    counts: dict[str, int] = {}
    for name, getter in (("consent", vault.consent), ("custody", vault.custody),
                         ("keyring", vault.keyring), ("redaction", vault.redaction),
                         ("access", vault.access_log)):
        try:
            stream = getter()._stream
            counts[name] = (await stream.head())["seq_count"]
        except Exception:  # noqa: BLE001
            counts[name] = 0
    label = {"archive": "Archive receipts", "tsa": "Trusted timestamps",
             "access": "Read-access events", "holds": "Legal holds",
             "keyring": "Key custody + rotation", "consent": "Consent receipts",
             "custody": "Chain of custody", "redaction": "Redactions / crypto-shred"}
    rows = []
    for name in ("archive", "tsa", "access", "holds", "keyring", "consent", "custody", "redaction"):
        c = checks.get(name, {})
        ok = c.get("valid")
        pill = ('<span class="vbadge">&#10003; verified</span>' if ok
                else '<span class="vbadge bad">&#9888; ' + html.escape(str(c.get("reason") or "failed"))
                     + '</span>')
        n = c.get("length", counts.get(name, 0))
        rows.append(
            f'<tr><td>{html.escape(label.get(name, name))}</td>'
            f'<td class="rt">{n}</td><td class="rt">{pill}</td></tr>')
    table = ('<div class="panel"><h2>Signed evidence streams</h2>'
             '<div class="desc">Every compliance concern is its own append-only, Falcon-signed, '
             'hash-linked chain, all verifiable offline with the one published console public key.</div>'
             '<table><thead><tr><th>Stream</th><th class="rt">Entries</th>'
             '<th class="rt">Integrity</th></tr></thead>'
             f'<tbody>{"".join(rows)}</tbody></table></div>')
    allok = all(v.get("valid") for v in checks.values())
    right = ((('<span class="pill ok">&#10003; all streams verified</span>') if allok
              else '<span class="pill bad">&#9888; a stream failed verification</span>')
             + '<a class="btn" href="/records">Records</a>')
    return theme.page("Evidence streams", table, user=user, active="records",
                      subtitle="Consent, custody, key rotation, redaction &middot; offline-verifiable",
                      extra_right=right)
