"""Server-rendered dashboard for the Compliance Command Center.

Renders a :class:`~algovoi_command_center.posture.Posture` as a standalone HTML page using the shared
console theme. Every figure is shown with its verification status — the posture is evidence-backed, not
asserted.
"""
from __future__ import annotations

import html

from algovoi_command_center import theme
from algovoi_command_center.posture import Posture


def _icon(ok: bool) -> str:
    cls = "vbadge" if ok else "vbadge bad"
    word = "Verified" if ok else "FAILED"
    return f'<span class="{cls}">&#10003; {word}</span>'


def _live(up: bool) -> str:
    cls = "vbadge" if up else "vbadge bad"
    word = "Live" if up else "Down"
    return f'<span class="{cls}">&#9679; {word}</span>'


def render_dashboard(p: Posture, user: dict | None = None, *, can_export: bool = True,
                     services: list | None = None) -> str:
    e = html.escape
    cards = "".join(
        f'<div class="card"><div class="lbl">{e(m.label)}</div>'
        f'<div class="val">{m.value:,}</div>'
        f'<div class="vf">{"&#10003; chain verified" if m.verified else "&#9888; unverified"}</div></div>'
        for m in p.metrics) or '<div class="card"><div class="lbl">No evidence ingested</div></div>'

    rows = "".join(
        f'<tr><td class="muted">{e(c.name)}</td>'
        f'<td class="rt mono faint">{e((c.head or str(c.entries))[:14])}</td>'
        f'<td class="rt">{_icon(c.verified)}</td></tr>'
        for c in p.chains) or '<tr><td class="muted">No signed chains yet.</td></tr>'

    deltas = "".join(
        f'<div class="delta"><span class="ic">&#9679;</span><span style="flex:1">{e(d.text)}</span>'
        f'<span class="muted" style="font-size:12px">signed</span></div>'
        for d in p.deltas) or '<div class="muted" style="font-size:13px">No recent changes.</div>'

    if p.packs == 0:
        status = '<span class="pill neutral">&#9679; no evidence ingested yet &middot; nothing to verify</span>'
    elif p.all_verified:
        status = '<span class="pill ok">&#9989; all evidence offline-verifiable</span>'
    else:
        status = '<span class="pill bad">&#9888; verification failed &middot; review below</span>'

    svc_rows = "".join(
        f'<tr><td class="muted">{e(s.get("name", ""))}</td>'
        f'<td class="muted">{e(s.get("type", ""))}</td>'
        f'<td class="rt mono faint">{e(s.get("url", ""))}</td>'
        f'<td class="rt">{_live(bool(s.get("up")))}</td></tr>'
        for s in (services or [])) or \
        '<tr><td class="muted">No products registered yet.</td></tr>'

    export_btn = '<a class="btn" href="/export">&#8681; Export auditor pack</a>' if can_export else ""
    body = (
        f'<div class="cards">{cards}</div>'
        '<div class="panel"><h2>Evidence integrity</h2>'
        '<div class="desc">Verified offline, public key only.</div>'
        f'<table><tbody>{rows}</tbody></table></div>'
        '<div class="panel"><h2>Live service health</h2>'
        '<div class="desc">Polled on load, not asserted.</div>'
        f'<table><tbody>{svc_rows}</tbody></table></div>'
        f'<div class="panel"><h2>Recent posture changes</h2>{deltas}</div>'
        '<div class="callout"><span>&#128274;</span><div>Nothing on this screen is <em>asserted</em>. '
        'Every figure is recomputed from a Falcon-1024 signed, hash-linked chain; your auditor '
        're-verifies the exported pack offline, with no AlgoVoi software or service.</div></div>')
    return theme.page(
        "Overview", body, user=user, active="dashboard", head_title="Compliance Command Center",
        subtitle=f"Estate: {e(p.estate)} &middot; {p.packs} evidence pack(s) &middot; self-hosted, air-gapped",
        extra_right=f"{status}{export_btn}")


def render_login(error: str = "") -> str:
    msg = (f'<div class="pill bad" style="display:block;padding:10px 12px;margin-bottom:14px">'
           f'{html.escape(error)}</div>') if error else ""
    body = (
        '<div class="brand" style="margin-bottom:18px"><span class="mark">AV</span>'
        '<div><h1>Compliance Command Center</h1><div class="sub">Sign in to continue</div></div></div>'
        f'<div class="panel">{msg}<form method="post" action="/login">'
        '<label>Username</label><input name="username" autofocus autocomplete="username">'
        '<label>Password</label><input name="password" type="password" autocomplete="current-password">'
        '<button class="btn primary" type="submit" style="width:100%;margin-top:16px;justify-content:center">'
        'Sign in</button></form></div>')
    return theme.bare("Sign in", body, max_width=380)


def _siem_panel(siem: dict | None) -> str:
    """A read-only status card for live SIEM forwarding of this signed audit chain."""
    if not siem:
        return ""
    e = html.escape
    if not siem.get("enabled"):
        return ('<div class="panel"><h2>SIEM forwarding</h2>'
                '<div class="desc">Off. This appliance is not streaming the audit chain to a SIEM. '
                'Configure a syslog (RFC 5424 / CEF) or webhook sink to enable live forwarding to your '
                'SOC; air-gapped installs can leave it off.</div></div>')
    sinks = ", ".join(e(s) for s in siem.get("sinks", [])) or "none"
    err = siem.get("last_error") or ""
    err_row = (f'<div class="delta"><span class="ic">&#9888;</span>'
               f'<span style="flex:1" class="muted">last error: {e(err)}</span></div>' if err else "")
    return ('<div class="panel"><h2>SIEM forwarding</h2>'
            '<div class="desc">Streaming every signed audit entry to your SOC, live. Each record carries '
            'its <code>seq</code> and <code>sha256</code> so it ties back to this tamper-evident chain.</div>'
            '<table><tbody>'
            f'<tr><td class="muted">Sinks</td><td class="mono">{sinks}</td></tr>'
            f'<tr><td class="muted">Forwarded through seq</td><td class="rt">{siem.get("last_forwarded_seq")}</td></tr>'
            f'<tr><td class="muted">Sent / queued / dropped</td>'
            f'<td class="rt">{siem.get("sent")} / {siem.get("queued")} / {siem.get("dropped")}</td></tr>'
            f'</tbody></table>{err_row}</div>')


def render_audit(entries: list[dict], verified: bool, reason: str, user: dict | None = None,
                 *, siem: dict | None = None) -> str:
    e = html.escape
    rows = "".join(
        f'<tr><td class="muted mono">{e(str(x.get("recorded_at","")))}</td>'
        f'<td>{e(str(x.get("principal","")))} <span class="muted">{e(str(x.get("role","")))}</span></td>'
        f'<td>{e(str(x.get("action","")))}</td>'
        f'<td class="muted">{e(str(x.get("detail","")))}</td></tr>'
        for x in reversed(entries)) or '<tr><td class="muted">No console activity yet.</td></tr>'
    badge = ('<span class="pill ok">&#10003; audit chain verified</span>' if verified
             else f'<span class="pill bad">&#9888; {e(reason)}</span>')
    body = (_siem_panel(siem) + '<div class="panel"><table>'
            '<thead><tr><th>Time</th><th>Principal</th><th>Action</th><th>Detail</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>')
    return theme.page("Console audit log", body, user=user, active="audit",
                      subtitle="Every console action, Falcon-signed and hash-linked &middot; offline-verifiable",
                      extra_right=badge)
