"""Shared visual theme for the Compliance Command Center console.

One CSS + one page shell + one top nav, so every server-rendered page (dashboard, containers, updates,
audit, results) looks identical: same font, same palette, same header. Air-gap friendly — a system font
stack, no external font or asset fetch.
"""
from __future__ import annotations

import html

BRAND = "Compliance Command Center"

# Single source of truth for the console's look. Muted, professional, print-legible.
STYLE = """
:root{--bg:#fbfbfa;--surface:#fff;--text:#1d1d1b;--muted:#514f48;--faint:#6c6a62;--line:#e0dfd9;
--ok:#0f6e56;--ok-bg:#e1f5ee;--warn:#854f0b;--warn-bg:#fbf1e0;--bad:#a32d2d;--bad-bg:#fceaea;
--info:#185fa5;--info-bg:#e6f1fb;--wrap:1180px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,"Noto Sans",sans-serif;
-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:var(--info)}
.wrap{max-width:var(--wrap);margin:0 auto;padding:26px 24px 56px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;
padding-bottom:14px;margin-bottom:20px;border-bottom:0.5px solid var(--line)}
.brandname{font-weight:600;font-size:15px;letter-spacing:-0.01em}
.pagehead{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:22px;min-height:38px}
.pageactions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px}
.brand .mark{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,#1d1d1b,#3a3a36);
color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700}
h1{font-size:19px;font-weight:600;margin:0;letter-spacing:-0.01em}
.sub{font-size:13px;color:var(--muted);margin-top:3px}
h2{font-size:15px;font-weight:600;margin:0 0 12px}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.chip{font-size:12px;color:var(--muted);padding:5px 4px}
.btn{font-size:13px;line-height:1;padding:8px 13px;border:0.5px solid var(--line);background:var(--surface);
border-radius:8px;color:var(--text);text-decoration:none;cursor:pointer;white-space:nowrap;
display:inline-flex;align-items:center;gap:6px;font-family:inherit}
.btn:hover{background:#f3f2ee}
.btn.active{background:var(--text);color:#fff;border-color:var(--text)}
.btn.primary{background:var(--info);color:#fff;border-color:var(--info)}
.btn.primary:hover{filter:brightness(1.06)}
.btn.danger{color:var(--bad);border-color:#eccaca}
.btn.danger:hover{background:var(--bad-bg)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:5px 11px;border-radius:8px}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.bad{background:var(--bad-bg);color:var(--bad)}
.pill.neutral{background:#eef1f5;color:#5b6470}
.pill.warn{background:var(--warn-bg);color:var(--warn)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.card{background:#f3f2ee;border-radius:10px;padding:14px 16px}
.card .lbl{font-size:13px;color:var(--muted)}
.card .val{font-size:26px;font-weight:600;margin-top:2px;letter-spacing:-0.01em}
.card .vf{font-size:12px;color:var(--ok);margin-top:5px}
.panel{background:var(--surface);border:0.5px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
.panel .desc{font-size:13px;color:var(--muted);margin:-4px 0 14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;padding:8px 10px;border-bottom:0.5px solid var(--line)}
td{padding:9px 10px;border-bottom:0.5px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}
.muted{color:var(--muted)}
.faint{color:var(--faint)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.rt{text-align:right}
.vbadge{color:var(--ok);font-size:12px}
.vbadge.bad{color:var(--bad)}
.delta{display:flex;align-items:center;gap:10px;font-size:13px;padding:6px 0}
.delta .ic{width:18px;text-align:center;color:var(--muted)}
.callout{display:flex;gap:10px;background:var(--info-bg);color:var(--info);border-radius:10px;padding:14px 16px;font-size:13px;line-height:1.6}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 5px}
input[type=text],input[type=password],input:not([type]),textarea,select{width:100%;font:inherit;
padding:9px 11px;border:1px solid #b7b5ac;border-radius:8px;background:#f7f6f2;color:var(--text)}
input::placeholder,textarea::placeholder{color:#9a988f}
input:hover,textarea:hover,select:hover{border-color:#9d9b91}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--info);background:var(--surface);
box-shadow:0 0 0 3px rgba(24,95,165,.12)}
textarea{min-height:88px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.form-row{margin-bottom:6px}
.hint{font-size:12px;color:var(--muted);margin-top:4px}
"""

_NAV = (("/", "Dashboard", "dashboard"), ("/records", "Records", "records"),
        ("/ingest", "Import", "ingest"), ("/containers", "Containers", "containers"),
        ("/users", "Users", "users"), ("/updates", "Updates", "updates"),
        ("/audit", "Audit", "audit"), ("/mfa", "Security", "security"))


def nav(user: dict | None, active: str = "") -> str:
    """The shared right-side navigation: a right-aligned column with the tab-button row on top and the
    signed-in identity chip directly beneath it, so the buttons sit directly above ``user · role``."""
    if not user:
        return ""
    e = html.escape
    links = "".join(
        f'<a class="btn{" active" if active == key else ""}" href="{href}">{label}</a>'
        for href, label, key in _NAV)
    row = (f'<div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">'
           f'{links}<a class="btn" href="/logout">Sign out</a></div>')
    chip = (f'<span class="chip" style="padding:0 2px">'
            f'{e(user.get("username",""))} &middot; {e(user.get("role",""))}</span>')
    return (f'<div class="nav" style="flex-direction:column;align-items:flex-end;gap:4px">'
            f'{row}{chip}</div>')


def topbar(user: dict | None, active: str) -> str:
    """The constant top bar: brand on the left, the same nav in the same place on every page."""
    brand = f'<div class="brand"><span class="mark">AV</span><span class="brandname">{BRAND}</span></div>'
    return f'<div class="topbar">{brand}{nav(user, active)}</div>'


def pagehead(title: str, subtitle: str, extra_right: str) -> str:
    """Second row: the page title + subtitle on the left, page-specific actions in a fixed right slot."""
    e = html.escape
    sub = f'<div class="sub">{subtitle}</div>' if subtitle else ""
    return (f'<div class="pagehead"><div><h1>{e(title)}</h1>{sub}</div>'
            f'<div class="pageactions">{extra_right}</div></div>')


def page(title: str, body: str, *, user: dict | None = None, active: str = "",
         subtitle: str = "", extra_right: str = "", head_title: str | None = None) -> str:
    """Full themed document: constant top bar (brand + nav) + page header + body."""
    bar = topbar(user, active) if user else ""
    return (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(head_title or title)} &middot; {BRAND}</title>'
            f'<style>{STYLE}</style></head><body><div class="wrap">'
            f'{bar}{pagehead(title, subtitle, extra_right)}{body}</div></body></html>')


def bare(title: str, body: str, *, max_width: int = 420) -> str:
    """Themed document with no nav header (login / standalone notices)."""
    return (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)} &middot; {BRAND}</title><style>{STYLE}</style></head>'
            f'<body><div class="wrap" style="max-width:{max_width}px;margin-top:8vh">{body}</div></body></html>')


def notice(title: str, message_html: str, *, user: dict | None = None, active: str = "",
           back_href: str = "/", back_label: str = "Back") -> str:
    """A themed one-panel result/notice page used by the ad-hoc handlers."""
    body = (f'<div class="panel">{message_html}'
            f'<p style="margin-top:14px"><a class="btn" href="{back_href}">&#8592; {html.escape(back_label)}</a></p></div>')
    return page(title, body, user=user, active=active)
