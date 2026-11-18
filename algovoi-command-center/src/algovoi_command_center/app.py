"""Compliance Command Center — self-hosted web app (v1, with auth + RBAC + signed console audit).

Reads exported evidence packs from a watched ingest directory, re-verifies every chain offline, and
serves the compliance-posture dashboard, a posture API, and a consolidated auditor-pack export — behind
local-accounts auth + role-based access control. Every console action is appended to a Falcon-signed,
offline-verifiable audit chain.

Phase e adds LDAP/AD + OIDC/SAML SSO; phase f moves the console signing key into an HSM/KMS/Vault.
"""
from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import json
import os
import secrets
import socket
import time
import urllib.request
from urllib.parse import quote, urlparse
from typing import Annotated

from fastapi import FastAPI, Form, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel

from algovoi_command_center import __version__, factors, licensing, roles, theme
from algovoi_command_center.audit import ConsoleAuditLog, LocalSigner
from algovoi_command_center.auth import (
    authenticate, make_pending, make_session, make_stepup, read_pending, read_session, read_stepup)
from algovoi_command_center.dashboard import render_audit, render_dashboard, render_login
from algovoi_command_center.engine import ingest
from algovoi_command_center.export import build_auditor_pack
from algovoi_command_center.posture import build_posture
from algovoi_command_center.store import get_store
from algovoi_command_center.validation import build_ccc_validation_pack

_COOKIE = "cc_session"
_STEPUP = "cc_stepup"   # short-lived cookie proving a fresh password re-check for sensitive actions
_PENDING = "cc_pending"  # short-lived cookie after a correct password when 2FA is required (pre-session)

# Content-Security-Policy: same-origin only. The console renders inline <style> and small inline
# on* handlers, so style-src/script-src allow 'unsafe-inline'; there is no external asset fetch.
# frame-ancestors 'none' blocks clickjacking; form-action 'self' pins where forms may post.
_CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def _req_secure(request: Request) -> bool:
    """Should the auth cookies carry the ``Secure`` flag for this request? True when the browser reached
    the console over HTTPS, either directly or through a TLS-terminating proxy (``X-Forwarded-Proto``).
    Over plain HTTP (local/air-gapped dev, test client) it stays False so the cookie still works."""
    xfp = (request.headers.get("x-forwarded-proto", "") or "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or xfp == "https"


def _ingest_dir() -> str:
    return os.environ.get("COMMAND_CENTER_INGEST_DIR", "./evidence-ingest")


def _estate() -> str:
    return os.environ.get("COMMAND_CENTER_ESTATE", "estate")


def _load():
    d = _ingest_dir()
    packs = ingest(d, get_store()) if os.path.isdir(d) else []
    return d, packs, build_posture(packs, estate=_estate())


def _env_or_file(name: str) -> str:
    v = os.environ.get(name)
    if v:
        return v
    f = os.environ.get(name + "_FILE")
    if f and os.path.exists(f):
        return open(f, encoding="utf-8").read().strip()
    raise RuntimeError(f"BYO-key custody needs {name} (or {name}_FILE)")


class ServiceIn(BaseModel):
    """A product self-registering with the console's live service bridge."""
    name: str
    type: str = "product"
    base_url: str
    health_path: str = "/health"


def _service_token() -> str:
    """The bearer token a product uses to self-register (POST /v1/services). A
    dedicated, narrowly-scoped token — not a full RBAC login. Set it explicitly via
    ``COMMAND_CENTER_SERVICE_TOKEN``, or let it bootstrap once into the data dir
    (0600) so a bare deployment comes up able to accept registrations."""
    v = os.environ.get("COMMAND_CENTER_SERVICE_TOKEN", "").strip()
    if v:
        return v
    base = os.environ.get("COMMAND_CENTER_DATA_DIR", ".")
    path = os.path.join(base, "command-center-service-token")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    os.makedirs(base, exist_ok=True)
    tok = secrets.token_urlsafe(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(tok)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return tok


def _provisioning_token() -> str:
    """The bearer token an IdP uses for the SCIM provisioning endpoint (``/scim/v2``). A dedicated,
    narrowly-scoped token — separate from human sign-in and from the service-registration token. Set it
    explicitly via ``COMMAND_CENTER_SCIM_TOKEN`` (rotate by replacing it), or let it bootstrap once into
    the data dir (0600), mirroring the service token. Rotating = set a new value and restart."""
    v = os.environ.get("COMMAND_CENTER_SCIM_TOKEN", "").strip()
    if v:
        return v
    base = os.environ.get("COMMAND_CENTER_DATA_DIR", ".")
    path = os.path.join(base, "command-center-scim-token")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    os.makedirs(base, exist_ok=True)
    tok = secrets.token_urlsafe(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(tok)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return tok


def _mount_provisioning(app: "FastAPI", audit: "ConsoleAuditLog") -> list[str]:
    """Discover and mount provisioning add-ons (e.g. ``algovoi-command-center-scim``) via the
    ``algovoi_command_center.provisioning`` entry-point group — the same adopt-by-install path the 2FA
    factors use. Each add-on is licence-gated in its own constructor; an unlicensed or broken add-on
    raises and is simply skipped, so its endpoints stay unreachable (fail-closed). Returns the names
    mounted (for logging/tests)."""
    import importlib.metadata as _im
    group = "algovoi_command_center.provisioning"
    try:
        eps = _im.entry_points(group=group)
    except TypeError:  # pragma: no cover - Python < 3.10 selection API
        eps = _im.entry_points().get(group, [])  # type: ignore[attr-defined]
    mounted: list[str] = []
    token = _provisioning_token()
    for ep in eps:
        try:
            provisioner = ep.load()()  # licence gate fires here; fail-closed
            router = provisioner.build_router(audit=audit, bearer_token=token)
            app.include_router(router)
            mounted.append(getattr(provisioner, "name", ep.name))
        except Exception:  # noqa: BLE001 — a broken/unlicensed add-on must never take the console down
            continue
    return mounted


def _probe_target_ok(base_url: str) -> bool:
    """SSRF guard for health probes. This console legitimately polls INTERNAL services (records-vault
    on localhost / RFC1918 on the deployment network), so private and loopback targets must stay
    allowed. What must NOT be reachable is the cloud metadata service and other link-local/multicast
    targets — a registered ``base_url`` of http://169.254.169.254/… would otherwise turn the console
    into a fetch-and-reflect proxy for instance credentials. Block only those; only http(s)."""
    try:
        p = urlparse(base_url)
    except Exception:  # noqa: BLE001
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except Exception:  # noqa: BLE001
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
    return True


def _probe(name: str, svc: dict, timeout: float = 3.0) -> dict:
    """Synchronously poll one service's health (stdlib urllib — no extra runtime dep).
    Run off the event loop via asyncio.to_thread; never raises."""
    url = svc["base_url"].rstrip("/") + svc["health_path"]
    entry = {"name": name, "type": svc.get("type", ""), "url": url,
             "registered_at": svc.get("registered_at")}
    if not _probe_target_ok(svc["base_url"]):
        entry["up"] = False
        entry["detail"] = "blocked: probe target is not a public host"
        return entry
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310  # nosec B310 - trusted URL (indexer constant / operator-config hub); scheme is fixed http(s)
            entry["up"] = 200 <= r.status < 300
            raw = r.read(2048).decode("utf-8", "replace")
        try:
            entry["detail"] = json.loads(raw)
        except Exception:
            entry["detail"] = raw[:120]
    except Exception as exc:  # noqa: BLE001
        entry["up"] = False
        entry["detail"] = f"unreachable: {type(exc).__name__}"
    return entry


async def _poll_services() -> list[dict]:
    """Poll every registered service's health concurrently, on demand (no background
    loop). Mirrors the substrate-2 control plane's /v1/posture."""
    svcs = get_store().services_load()
    if not svcs:
        return []
    return list(await asyncio.gather(*(asyncio.to_thread(_probe, n, s) for n, s in svcs.items())))


def _console_signer():
    """Build the console's signer. ``COMMAND_CENTER_KEY_CUSTODY`` selects custody:

    - ``local`` (default): Falcon key in a local key file (bootstrapped on first run);
    - ``kms`` / ``vault`` / ``pkcs11``: BYO-key — the console public key + a *wrapped* secret key
      held in your AWS KMS / HashiCorp Vault / PKCS#11 HSM, unwrapped only at sign time (the existing
      ``algovoi-doc-archive-{kms,vault,pkcs11}`` adapters). The clear key never sits at rest.
    """
    custody = os.environ.get("COMMAND_CENTER_KEY_CUSTODY", "local")
    if custody == "local":
        path = os.environ.get("COMMAND_CENTER_KEY_FILE", "./command-center-key.json")
        if os.path.exists(path):
            d = json.load(open(path, encoding="utf-8"))
            return LocalSigner(base64.b64decode(d["pk"]), base64.b64decode(d["sk"]))
        from pqcrypto.sign.falcon_1024 import generate_keypair
        pk, sk = generate_keypair()
        # This is the console's root signing key (it signs the tamper-evident audit chain and the
        # records archive). Write it 0600 and atomically, so it is never briefly world-readable and a
        # crash can't leave a half-written key in place. Mirrors the SCIM-token bootstrap above.
        blob = json.dumps({"pk": base64.b64encode(pk).decode(),
                           "sk": base64.b64encode(sk).decode()}).encode()
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        try:
            os.chmod(path, 0o600)  # tighten even if the file pre-existed with looser perms
        except OSError:
            pass
        return LocalSigner(pk, sk)

    pk = base64.b64decode(_env_or_file("COMMAND_CENTER_CONSOLE_PUBKEY"))
    wrapped = base64.b64decode(_env_or_file("COMMAND_CENTER_CONSOLE_WRAPPED_KEY"))
    if custody == "kms":
        from algovoi_doc_archive_kms import kms_signer
        return kms_signer(pk, wrapped, key_id=os.environ["COMMAND_CENTER_KMS_KEY_ID"])
    if custody == "vault":
        from algovoi_doc_archive_vault import vault_signer
        return vault_signer(pk, wrapped, key_name=os.environ["COMMAND_CENTER_VAULT_KEY"],
                            url=os.environ.get("VAULT_ADDR"), token=os.environ.get("VAULT_TOKEN"))
    if custody == "pkcs11":
        raise RuntimeError("pkcs11 custody needs an integrator-supplied python-pkcs11 session; "
                           "construct the signer with algovoi_doc_archive_pkcs11.pkcs11_signer and "
                           "pass it to create_app() directly.")
    raise RuntimeError(f"unknown COMMAND_CENTER_KEY_CUSTODY: {custody!r}")


def create_app(signer=None) -> FastAPI:
    licensing.require_license()  # fail-closed — no valid Command Center licence, no app
    app = FastAPI(title="AlgoVoi Compliance Command Center", version=__version__)
    console_signer = signer or _console_signer()
    _audit_file = os.environ.get("COMMAND_CENTER_AUDIT_FILE")
    # optional live SIEM forwarding of the signed audit chain (off unless COMMAND_CENTER_SIEM_* is set)
    from algovoi_command_center.siem import Forwarder
    siem_forwarder = Forwarder.from_env(product_version=__version__)
    audit = ConsoleAuditLog(_audit_file if _audit_file else get_store(), console_signer,
                            forwarder=siem_forwarder)
    if siem_forwarder.enabled:
        siem_forwarder.start()
        try:  # backfill anything appended while forwarding was off / a sink was down
            from algovoi_command_center import audit as _audit_mod
            _payloads = audit.entries()
            _hashes = [_audit_mod._payload_hash(_p) for _p in _payloads]
            siem_forwarder.backfill(_payloads, _hashes)
        except Exception:  # noqa: BLE001 — backfill is best-effort
            pass

    service_token = _service_token()

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy", _CSP)
        return resp

    # Best-effort brute-force backoff for the credential endpoints (/login, /verify). Per (client, user)
    # sliding window, in-memory: after too many failures within the window the endpoint returns 429 for a
    # cool-off. Not a substitute for a network WAF, but it blunts online password guessing on an exposed
    # console. Resets on restart and is per-process (single-writer console); PBKDF2 already rate-limits.
    _fails: dict[str, list[float]] = {}
    _MAX_FAILS, _WINDOW = 10, 300.0

    def _throttle_key(request: Request, who: str) -> str:
        ip = request.client.host if request.client else "?"
        return f"{ip}|{who}"

    def _throttled(key: str) -> bool:
        now = time.monotonic()
        hist = [t for t in _fails.get(key, []) if now - t < _WINDOW]
        _fails[key] = hist
        return len(hist) >= _MAX_FAILS

    def _note_fail(key: str) -> None:
        _fails.setdefault(key, []).append(time.monotonic())

    def _clear_fail(key: str) -> None:
        _fails.pop(key, None)

    def user_of(request: Request) -> dict | None:
        return read_session(request.cookies.get(_COOKIE))

    def _is_service(authorization: str | None) -> bool:
        token = (authorization[7:].strip()
                 if authorization and authorization.startswith("Bearer ") else None)
        return bool(token) and secrets.compare_digest(token, service_token)

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if user_of(request):
            return RedirectResponse("/", status_code=303)
        return HTMLResponse(render_login())

    @app.post("/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...)):
        key = _throttle_key(request, username)
        if _throttled(key):
            audit.append(action="login_blocked", principal=username, detail="too many attempts")
            return HTMLResponse(render_login("Too many attempts. Wait a few minutes and try again."),
                                status_code=429)
        u = authenticate(username, password)
        if not u:
            _note_fail(key)
            audit.append(action="login_failed", principal=username, detail="bad credentials")
            return HTMLResponse(render_login("Invalid username or password."), status_code=401)
        _clear_fail(key)
        # First factor passed. If the user has an active second factor, hold the session behind a 2FA
        # challenge: issue only a short-lived pending token (grants no access) and redirect to /mfa/challenge.
        if factors.has_active(u["username"]):
            audit.append(action="login_2fa_required", principal=u["username"], role=u["role"])
            resp = RedirectResponse("/mfa/challenge", status_code=303)
            resp.set_cookie(_PENDING, make_pending(u["username"], u["role"]), httponly=True,
                            samesite="lax", max_age=300, secure=_req_secure(request))
            return resp
        audit.append(action="login", principal=u["username"], role=u["role"])
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(_COOKIE, make_session(u["username"], u["role"]), httponly=True,
                        samesite="lax", secure=_req_secure(request))
        return resp

    @app.get("/logout")
    async def logout(request: Request):
        u = user_of(request)
        if u:
            audit.append(action="logout", principal=u["username"], role=u["role"])
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(_COOKIE)
        return resp

    # ── Step-up: a fresh password re-check before a sensitive download or create ──
    def _stepup_ok(request: Request, u: dict) -> bool:
        return read_stepup(request.cookies.get(_STEPUP), u["username"])

    def _safe_next(nxt: str) -> str:
        # Only same-origin absolute paths. Reject scheme-relative ("//host") and backslash variants
        # ("/\\host", "\\host") that some browsers normalise into an off-site redirect.
        nxt = nxt or "/"
        if not nxt.startswith("/") or nxt.startswith("//"):
            return "/"
        if "\\" in nxt or "\t" in nxt or "\n" in nxt or "\r" in nxt:
            return "/"
        return nxt

    def _render_verify(u: dict, nxt: str, error: str = "") -> str:
        msg = (f'<div class="pill bad" style="display:block;padding:10px 12px;margin-bottom:12px">'
               f'{html.escape(error)}</div>' if error else "")
        body = (f'<div class="panel" style="max-width:440px">'
                f'<div class="desc">Confirm your identity to continue. Signed in as '
                f'<b>{html.escape(u["username"])}</b>.</div>{msg}'
                f'<form method="post" action="/verify">'
                f'<input type="hidden" name="next" value="{html.escape(nxt)}">'
                f'<label>Password</label>'
                f'<input name="password" type="password" autofocus autocomplete="current-password" required>'
                f'<button class="btn primary" type="submit" style="margin-top:14px">Verify &amp; continue</button>'
                f'</form></div>')
        return theme.page("Confirm your identity", body, user=u)

    @app.get("/verify", response_class=HTMLResponse)
    async def verify_page(request: Request, next: str = "/"):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(_render_verify(u, _safe_next(next)))

    @app.post("/verify")
    async def verify_submit(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        nxt = _safe_next(form.get("next", "/") or "/")
        key = _throttle_key(request, u["username"] + "|stepup")
        if _throttled(key):
            audit.append(action="stepup_verify", principal=u["username"], role=u["role"], detail="blocked")
            return HTMLResponse(_render_verify(u, nxt, "Too many attempts. Wait a few minutes."),
                                status_code=429)
        if authenticate(u["username"], form.get("password", "") or ""):
            _clear_fail(key)
            audit.append(action="stepup_verify", principal=u["username"], role=u["role"], detail="ok")
            resp = RedirectResponse(nxt, status_code=303)
            resp.set_cookie(_STEPUP, make_stepup(u["username"]), httponly=True, samesite="lax",
                            max_age=300, secure=_req_secure(request))
            return resp
        _note_fail(key)
        audit.append(action="stepup_verify", principal=u["username"], role=u["role"], detail="failed")
        return HTMLResponse(_render_verify(u, nxt, "Incorrect password."), status_code=401)

    # ── Two-factor authentication: discovered add-on factors, enrollment, and the login challenge ──
    def _mfa_challenge_page(u: dict, error: str = "") -> str:
        msg = (f'<div class="pill bad" style="display:block;padding:10px 12px;margin-bottom:12px">'
               f'{html.escape(error)}</div>' if error else "")
        body = ('<div class="brand" style="margin-bottom:18px"><span class="mark">AV</span>'
                '<div><h1>Two-factor authentication</h1>'
                '<div class="sub">Enter the code from your authenticator app</div></div></div>'
                f'<div class="panel">{msg}<form method="post" action="/mfa/challenge">'
                '<label>Authentication code</label>'
                '<input name="code" inputmode="numeric" autocomplete="one-time-code" autofocus '
                'pattern="[0-9]*" placeholder="123456">'
                '<button class="btn primary" type="submit" style="width:100%;margin-top:16px;'
                'justify-content:center">Verify</button></form>'
                '<p style="margin-top:12px"><a class="btn" href="/logout">Cancel</a></p></div>')
        return theme.bare("Two-factor authentication", body, max_width=380)

    @app.get("/mfa/challenge", response_class=HTMLResponse)
    async def mfa_challenge_page(request: Request):
        p = read_pending(request.cookies.get(_PENDING))
        if not p:
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(_mfa_challenge_page(p))

    @app.post("/mfa/challenge")
    async def mfa_challenge(request: Request):
        p = read_pending(request.cookies.get(_PENDING))
        if not p:
            return RedirectResponse("/login", status_code=303)
        key = _throttle_key(request, p["username"] + "|2fa")
        if _throttled(key):
            audit.append(action="login_2fa", principal=p["username"], role=p["role"], detail="blocked")
            return HTMLResponse(_mfa_challenge_page(p, "Too many attempts. Wait a few minutes."),
                                status_code=429)
        form = await request.form()
        if not factors.verify_code(p["username"], (form.get("code", "") or "")):
            _note_fail(key)
            audit.append(action="login_2fa", principal=p["username"], role=p["role"], detail="failed")
            return HTMLResponse(_mfa_challenge_page(p, "Incorrect code."), status_code=401)
        _clear_fail(key)
        audit.append(action="login", principal=p["username"], role=p["role"], detail="2fa ok")
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(_COOKIE, make_session(p["username"], p["role"]), httponly=True,
                        samesite="lax", secure=_req_secure(request))
        resp.delete_cookie(_PENDING)
        return resp

    @app.get("/mfa", response_class=HTMLResponse)
    async def mfa_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        st = factors.status(u["username"])
        if not factors.available():
            body = ('<div class="panel"><h2>Two-factor authentication</h2>'
                    '<div class="desc">No 2FA method is installed on this console. An administrator can '
                    'add one, for example <code>pip install algovoi-command-center-totp</code>, and it is '
                    'discovered automatically with no configuration.</div></div>')
            return HTMLResponse(theme.page("Security", body, user=u, active="security"))
        _how = {"totp": "Time-based 6-digit codes from an authenticator app (RFC 6238). No SMS or email; "
                        "works fully offline."}
        rows = []
        for s in st:
            if s["active"]:
                state = '<span class="pill ok">&#10003; active</span>'
                act = (f"<form method='post' action='/mfa/disable/{html.escape(s['name'])}' "
                       "style='display:inline' onsubmit=\"return confirm('Turn off this second factor?')\">"
                       "<button class='btn danger' type='submit'>Disable</button></form>")
            else:
                state = '<span class="pill neutral">not enrolled</span>'
                act = f"<a class='btn primary' href='/mfa/enroll/{html.escape(s['name'])}'>Enroll</a>"
            how = _how.get(s["name"], "Adds a second step at sign-in after your password.")
            rows.append(f'<tr><td>{html.escape(s["label"])}</td><td class="muted">{how}</td>'
                        f'<td>{state}</td><td class="rt">{act}</td></tr>')
        body = ('<div class="panel"><h2>Two-factor authentication</h2>'
                '<div class="desc">A second factor is required at sign-in after your password, so a leaked '
                'password alone cannot get in. Enrollment is per user and optional; once you enroll a '
                'method it is required at every sign-in.</div>'
                '<table><thead><tr><th>Method</th><th>How it works</th><th>Status</th><th></th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table></div>'
                '<div class="callout"><span>&#128274;</span><div>Two-factor methods install as add-ons the '
                'console discovers automatically, so an administrator can add one with no configuration. '
                'Every enrollment and two-factor sign-in is written to the signed console audit chain.</div></div>')
        return HTMLResponse(theme.page("Security", body, user=u, active="security",
                                       subtitle="Manage your second factor"))

    @app.get("/mfa/enroll/{name}", response_class=HTMLResponse)
    async def mfa_enroll_page(name: str, request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        try:
            data = factors.begin_enroll(u["username"], name)
        except KeyError as exc:
            return HTMLResponse(theme.notice("Enroll", f"<span class='pill bad'>{html.escape(str(exc))}</span>",
                                             user=u, active="security", back_href="/mfa", back_label="Security"),
                                status_code=404)
        audit.append(action="mfa_enroll_begin", principal=u["username"], role=u["role"], detail=name)
        uri = html.escape(data["provisioning_uri"])
        secret = html.escape(data["secret"])
        # If the factor supplies a QR (our TOTP add-on does when segno is installed), show it as the
        # primary path; the setup key stays as the type-it-by-hand fallback. qr_svg is our own trusted
        # markup generated from our own otpauth URI, so it is embedded inline rather than escaped.
        qr = data.get("qr_svg")
        qr_block = (f'<div style="display:flex;justify-content:center;margin:6px 0 4px">'
                    f'<div style="width:200px;height:200px">{qr}</div></div>' if qr else "")
        body = (
            '<div class="panel"><h2>Set up your authenticator app</h2>'
            '<div class="desc">Two-factor sign-in uses a 6-digit code that changes every 30 seconds, '
            'from an authenticator app on your phone (Google Authenticator, Authy, Microsoft '
            'Authenticator, 1Password, and so on).</div>'
            '<ol class="desc" style="margin:0 0 14px 18px;padding:0">'
            '<li>Open your authenticator app and add an account.</li>'
            f'<li>{"Scan this QR code" if qr else "Enter the setup key below"}, or add the key by hand.</li>'
            '<li>Enter the 6-digit code the app shows, below, to activate.</li></ol>'
            f'{qr_block}'
            '<label>Setup key (if you cannot scan)</label>'
            f'<div class="mono" style="word-break:break-all;padding:10px 11px;border:1px solid #b7b5ac;'
            f'border-radius:8px;background:#f7f6f2">{secret}</div>'
            f'<form method="post" action="/mfa/enroll/{html.escape(name)}" style="margin-top:16px">'
            '<label>6-digit code from your authenticator app</label>'
            '<input name="code" inputmode="numeric" autocomplete="one-time-code" autofocus '
            'pattern="[0-9]{6}" maxlength="6" placeholder="123456" required '
            'title="Enter the 6-digit code shown in your authenticator app, not your password">'
            '<div class="hint">This is the rotating code in your app, not your password.</div>'
            '<button class="btn primary" type="submit" style="margin-top:14px">Activate</button>'
            ' <a class="btn" href="/mfa">Cancel</a>'
            '<details style="margin-top:14px"><summary class="hint" style="cursor:pointer">'
            'Add manually / setup URI</summary>'
            f'<div class="mono faint" style="word-break:break-all;font-size:11px;margin-top:8px">{uri}</div>'
            '</details></form></div>')
        return HTMLResponse(theme.page("Security", body, user=u, active="security"))

    @app.post("/mfa/enroll/{name}")
    async def mfa_enroll_confirm(name: str, request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        if factors.confirm_enroll(u["username"], name, (form.get("code", "") or "")):
            audit.append(action="mfa_enroll_activate", principal=u["username"], role=u["role"], detail=name)
            return HTMLResponse(theme.notice(
                "Two-factor enabled", "<span class='pill ok'>&#10003; second factor active</span>"
                "<div class='desc' style='margin-top:10px'>Your next sign-in will ask for a code.</div>",
                user=u, active="security", back_href="/mfa", back_label="Security"))
        audit.append(action="mfa_enroll_activate", principal=u["username"], role=u["role"], detail=f"{name} failed")
        return HTMLResponse(theme.notice(
            "Enroll", "<span class='pill bad'>that code did not verify</span>"
            "<div class='desc' style='margin-top:10px'>Check your device clock and try enrolling again.</div>",
            user=u, active="security", back_href="/mfa", back_label="Security"), status_code=401)

    @app.post("/mfa/disable/{name}")
    async def mfa_disable(name: str, request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        # Turning off your own second factor is sensitive: require a fresh step-up first.
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/mfa')}", status_code=303)
        factors.disable(u["username"], name)
        audit.append(action="mfa_disable", principal=u["username"], role=u["role"], detail=name)
        return RedirectResponse("/mfa", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_dashboard"):
            return HTMLResponse("Forbidden", status_code=403)
        audit.append(action="view_dashboard", principal=u["username"], role=u["role"])
        _d, _packs, posture = _load()
        services = await _poll_services()
        return HTMLResponse(render_dashboard(posture, u, can_export=roles.can(u["role"], "export_pack"),
                                             services=services))

    # ── Live service bridge: products self-register, the console polls their health ──
    @app.post("/v1/services")
    async def register_service(body: ServiceIn,
                               authorization: Annotated[str | None, Header()] = None):
        if not _is_service(authorization):
            return JSONResponse({"error": "service token required"}, status_code=401)
        registered_at = int(time.time())
        get_store().service_register(body.name, body.type, body.base_url.rstrip("/"),
                                     body.health_path, registered_at)
        audit.append(action="service_register", principal=body.name, role="service",
                     detail=body.base_url.rstrip("/"))
        return JSONResponse({"name": body.name, "registered": True})

    @app.get("/v1/services")
    async def list_services():
        # NOTE: intentionally open, read-only (products and operators list the registry without a
        # credential; the authenticated dashboard uses /api/services). The audit flagged this as a
        # low-severity inventory disclosure (internal hostnames); gating it is a deliberate,
        # potentially breaking API change for customer integrations, so it is left as-is pending a
        # product decision rather than hardened unilaterally.
        return JSONResponse({"services": [{"name": n, **v}
                                          for n, v in get_store().services_load().items()]})

    @app.delete("/v1/services/{name}")
    async def remove_service(name: str,
                             authorization: Annotated[str | None, Header()] = None):
        if not _is_service(authorization):
            return JSONResponse({"error": "service token required"}, status_code=401)
        if name not in get_store().services_load():
            return JSONResponse({"error": "unknown service"}, status_code=404)
        get_store().service_remove(name)
        audit.append(action="service_remove", principal=name, role="service", detail="removed")
        return JSONResponse({"name": name, "removed": True})

    @app.get("/api/services")
    async def api_services(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "view_dashboard"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        services = await _poll_services()
        return JSONResponse({"services": services,
                             "all_up": bool(services) and all(s["up"] for s in services)})

    @app.get("/api/posture")
    async def api_posture(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "view_evidence"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        _d, _packs, posture = _load()
        return JSONResponse({
            "estate": posture.estate, "packs": posture.packs, "all_verified": posture.all_verified,
            "metrics": [{"key": m.key, "label": m.label, "value": m.value, "verified": m.verified}
                        for m in posture.metrics],
            "chains": [{"name": c.name, "type": c.entry_type, "entries": c.entries,
                        "verified": c.verified, "head": c.head} for c in posture.chains]})

    @app.get("/export")
    async def export(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "export_pack"):
            return Response("Forbidden: your role cannot export evidence.", status_code=403)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/export')}", status_code=303)
        d, packs, posture = _load()
        audit.append(action="export_auditor_pack", principal=u["username"], role=u["role"],
                     detail=f"{posture.packs} pack(s)")
        blob = build_auditor_pack(d, packs, posture)
        return Response(content=blob, media_type="application/zip", headers={
            "Content-Disposition": 'attachment; filename="auditor-evidence-pack.zip"'})

    @app.get("/validation/pack")
    async def validation_pack(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "export_pack"):
            return Response("Forbidden: your role cannot export the validation pack.", status_code=403)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/validation/pack')}", status_code=303)
        _d, _packs, posture = _load()
        audit.append(action="export_validation_pack", principal=u["username"], role=u["role"])
        blob = build_ccc_validation_pack(console_signer, audit, posture)
        return Response(content=blob, media_type="application/zip", headers={
            "Content-Disposition": 'attachment; filename="system-validation-pack.zip"'})

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_audit"):
            return HTMLResponse("Forbidden", status_code=403)
        ok, reason = audit.verify()
        return HTMLResponse(render_audit(audit.entries(), ok, reason, u,
                                         siem=siem_forwarder.status()))

    # ── Sealed .acv records containers: create + revoke, signed by the console key ──
    from algovoi_command_center import containers as _containers

    def _may_manage(request: Request, authorization: str | None) -> dict | bool | None:
        if _is_service(authorization):
            return True
        u = user_of(request)
        return u if (u and roles.can(u["role"], "manage_containers")) else None

    def _guard_sensitive_container_op(request: Request, who):
        """Gate the escrow-recover and revoke operations. These decrypt records with the console
        escrow key / destroy a container, so they require an *interactive* admin with a fresh step-up,
        enforced identically on the JSON and HTML paths. A service-registration token (non-dict
        ``who``) cannot step up and is refused outright — it must not stand in for a human here.
        Returns a Response to send back when the caller is not cleared, or None to proceed."""
        if not isinstance(who, dict):
            return JSONResponse(
                {"error": "interactive admin required; service tokens may not recover or revoke"},
                status_code=403)
        if not _stepup_ok(request, who):
            if "text/html" in request.headers.get("accept", ""):
                return RedirectResponse(f"/verify?next={quote('/containers')}", status_code=303)
            return JSONResponse({"error": "step-up required: re-authenticate at /verify"},
                                status_code=401)
        return None

    @app.get("/containers", response_class=HTMLResponse)
    async def containers_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_dashboard"):
            return HTMLResponse("Forbidden", status_code=403)
        reg = _containers.get_registry(console_signer)
        return HTMLResponse(_containers.render_containers_page(
            reg, u, can_manage=roles.can(u["role"], "manage_containers")))

    @app.get("/api/containers")
    async def api_containers(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "view_dashboard"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        reg = _containers.get_registry(console_signer)
        return JSONResponse({"posture": _containers.posture(reg),
                             "containers": reg.list_containers() if reg else []})

    @app.post("/v1/containers")
    async def api_create_container(body: dict, request: Request,
                                   authorization: Annotated[str | None, Header()] = None):
        who = _may_manage(request, authorization)
        if not who:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        reg = _containers.get_registry(console_signer)
        if reg is None:
            return JSONResponse({"error": "container add-on not installed"}, status_code=501)
        try:
            out = _containers.create_from_request(reg, body)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"error": str(exc)}, status_code=400)
        audit.append(action="container_create",
                     principal=(who["username"] if isinstance(who, dict) else "service"),
                     role=(who["role"] if isinstance(who, dict) else "service"),
                     detail=out["container_id"])
        return JSONResponse(out)

    @app.post("/v1/containers/{container_id}/revoke")
    async def api_revoke_container(container_id: str, request: Request,
                                   authorization: Annotated[str | None, Header()] = None):
        who = _may_manage(request, authorization)
        if not who:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        blocked = _guard_sensitive_container_op(request, who)
        if blocked is not None:
            return blocked
        reg = _containers.get_registry(console_signer)
        if reg is None:
            return JSONResponse({"error": "container add-on not installed"}, status_code=501)
        reason = ""
        try:
            form = await request.form()
            reason = form.get("reason", "") or ""
        except Exception:  # noqa: BLE001
            pass
        try:
            r = reg.revoke(container_id, reason=reason)
        except KeyError:
            return JSONResponse({"error": "unknown container_id"}, status_code=404)
        audit.append(action="container_revoke",
                     principal=(who["username"] if isinstance(who, dict) else "service"),
                     role=(who["role"] if isinstance(who, dict) else "service"), detail=container_id)
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse("/containers", status_code=303)
        return JSONResponse(r)

    @app.post("/v1/containers/{container_id}/recover")
    async def api_recover_container(container_id: str, request: Request,
                                    authorization: Annotated[str | None, Header()] = None):
        who = _may_manage(request, authorization)
        if not who:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        blocked = _guard_sensitive_container_op(request, who)
        if blocked is not None:
            return blocked
        reg = _containers.get_registry(console_signer)
        if reg is None:
            return JSONResponse({"error": "container add-on not installed"}, status_code=501)
        try:
            out = _containers.recover_from_console(reg, container_id)
        except KeyError:
            return JSONResponse({"error": "unknown container_id"}, status_code=404)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"error": str(exc)}, status_code=400)
        audit.append(action="container_recover",
                     principal=(who["username"] if isinstance(who, dict) else "service"),
                     role=(who["role"] if isinstance(who, dict) else "service"), detail=container_id)
        if "text/html" in request.headers.get("accept", ""):
            items = "".join(f"<li class='mono'>{html.escape(d['name'])} ({len(d['data_b64'])} b64 chars)</li>"
                            for d in out["documents"])
            msg = (f"<h2>Recovered {html.escape(container_id)} from the console</h2>"
                   f"<div class='desc'>{len(out['documents'])} document(s) recovered via the console escrow "
                   "key. Fetch the bytes via <code>POST /v1/containers/{id}/recover</code> to save them.</div>"
                   f"<ul>{items}</ul>")
            return HTMLResponse(theme.notice("Recovered", msg, user=who if isinstance(who, dict) else None,
                                             active="containers", back_href="/containers", back_label="Containers"))
        return JSONResponse(out)

    @app.get("/v1/containers/crl")
    async def api_container_crl(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "view_dashboard"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/v1/containers/crl')}", status_code=303)
        reg = _containers.get_registry(console_signer)
        if reg is None:
            return JSONResponse({"error": "container add-on not installed"}, status_code=501)
        return Response(content=reg.current_crl(), media_type="text/plain",
                        headers={"Content-Disposition": 'attachment; filename="container-crl.txt"'})

    @app.post("/containers/create")
    async def html_create_container(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_containers"):
            return HTMLResponse("Forbidden", status_code=403)
        reg = _containers.get_registry(console_signer)
        if reg is None:
            return HTMLResponse("Container add-on not installed. <a href='/containers'>back</a>",
                                status_code=501)
        form = await request.form()
        if not authenticate(u["username"], (form.get("confirm_password", "") or "")):
            audit.append(action="container_create", principal=u["username"], role=u["role"],
                         detail="blocked: password confirmation failed")
            return HTMLResponse(theme.notice(
                "Create container", "<span class='pill bad'>password confirmation failed</span>"
                "<div class='desc' style='margin-top:10px'>Re-enter your own password to create a container.</div>",
                user=u, active="containers", back_href="/containers", back_label="Containers"), status_code=401)
        recovery = None
        rk, rn = (form.get("recovery_k") or "").strip(), (form.get("recovery_n") or "").strip()
        if rk and rn:
            try:
                recovery = {"threshold_k": int(rk), "total_n": int(rn)}
            except ValueError:
                recovery = None
        body = {"recipient_public_key_b64": (form.get("recipient_public_key_b64", "") or "").strip(),
                "title": form.get("title") or None, "recovery": recovery,
                "console_recoverable": bool(form.get("console_recoverable")),
                "documents": [{"name": form.get("doc_name", "record.txt"),
                               "data_b64": base64.b64encode((form.get("doc_text", "") or "").encode()).decode()}]}
        try:
            out = _containers.create_from_request(reg, body)
        except Exception:  # noqa: BLE001
            return HTMLResponse("Could not create container (check the recipient key and recovery k/n). "
                                "<a href='/containers'>back</a>", status_code=400)
        audit.append(action="container_create", principal=u["username"], role=u["role"],
                     detail=out["container_id"])
        rec = out.get("recovery")
        if rec:
            # Recovery shares are shown exactly once and never stored — the operator distributes them now.
            items = "".join(f"<li class='mono' style='margin:6px 0'>{html.escape(s)}</li>" for s in rec["shares"])
            msg = (f"<h2>Container {html.escape(out['container_id'])} created</h2>"
                   f"<p><span class='pill warn'>&#9888; shown once</span></p>"
                   f"<div class='desc'>Recovery shares ({rec['threshold_k']} of {rec['total_n']}). Never "
                   "stored. Distribute one to each custodian; any "
                   f"{rec['threshold_k']} together can recover this container if the recipient key is lost.</div>"
                   f"<ol>{items}</ol>")
            return HTMLResponse(theme.notice("Recovery shares", msg, user=u, active="containers",
                                             back_href="/containers", back_label="Containers"))
        return RedirectResponse("/containers", status_code=303)

    # ── Records Vault: browse + verify records, retrieve, legal holds, disposition, evidence ──
    from algovoi_command_center import records as _records

    @app.get("/records", response_class=HTMLResponse)
    async def records_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_dashboard"):
            return HTMLResponse("Forbidden", status_code=403)
        vault = _records.get_vault(console_signer)
        return HTMLResponse(await _records.render_records_page(
            vault, u, can_manage=roles.can(u["role"], "manage_records")))

    @app.get("/records/holds", response_class=HTMLResponse)
    async def records_holds_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_dashboard"):
            return HTMLResponse("Forbidden", status_code=403)
        vault = _records.get_vault(console_signer)
        return HTMLResponse(await _records.render_holds_page(
            vault, u, can_manage=roles.can(u["role"], "manage_holds")))

    @app.get("/records/disposition", response_class=HTMLResponse)
    async def records_disposition_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_dashboard"):
            return HTMLResponse("Forbidden", status_code=403)
        vault = _records.get_vault(console_signer)
        return HTMLResponse(await _records.render_disposition_page(
            vault, u, can_manage=roles.can(u["role"], "manage_records")))

    @app.get("/records/evidence", response_class=HTMLResponse)
    async def records_evidence_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_evidence"):
            return HTMLResponse("Forbidden", status_code=403)
        vault = _records.get_vault(console_signer)
        return HTMLResponse(await _records.render_evidence_page(vault, u))

    @app.get("/api/records")
    async def api_records(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "view_dashboard"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        vault = _records.get_vault(console_signer)
        return JSONResponse(await _records.posture(vault))

    @app.post("/records/notarize")
    async def records_notarize(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_records"):
            return HTMLResponse("Forbidden", status_code=403)
        vault = _records.get_vault(console_signer)
        if vault is None:
            return HTMLResponse("Records Vault not installed. <a href='/records'>back</a>", status_code=501)
        form = await request.form()
        if not authenticate(u["username"], (form.get("confirm_password", "") or "")):
            audit.append(action="record_notarize", principal=u["username"], role=u["role"],
                         detail="blocked: password confirmation failed")
            return HTMLResponse(theme.notice(
                "Notarize record", "<span class='pill bad'>password confirmation failed</span>"
                "<div class='desc' style='margin-top:10px'>Re-enter your own password to notarize a record.</div>",
                user=u, active="records", back_href="/records", back_label="Records"), status_code=401)
        try:
            out = await _records.notarize_record(
                vault, title=(form.get("title", "") or ""),
                content_type=(form.get("content_type") or "text/plain"),
                subject_ref=(form.get("subject_ref", "") or ""),
                data=(form.get("doc_text", "") or "").encode())
        except Exception as exc:  # noqa: BLE001
            return HTMLResponse(f"Could not notarize record: {html.escape(str(exc))}. "
                                "<a href='/records'>back</a>", status_code=400)
        audit.append(action="record_notarize", principal=u["username"], role=u["role"],
                     detail=f"seq={out['seq']} {out['doc_hash']}")
        return RedirectResponse("/records", status_code=303)

    @app.post("/records/retrieve")
    async def records_retrieve(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_records"):
            return HTMLResponse("Forbidden", status_code=403)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/records')}", status_code=303)
        vault = _records.get_vault(console_signer)
        if vault is None:
            return HTMLResponse("Records Vault not installed. <a href='/records'>back</a>", status_code=501)
        form = await request.form()
        doc_hash = (form.get("doc_hash", "") or "").strip()
        try:
            out = await _records.retrieve_record(vault, doc_hash=doc_hash)
        except Exception as exc:  # noqa: BLE001
            audit.append(action="record_retrieve", principal=u["username"], role=u["role"],
                         detail=f"denied {doc_hash}: {exc}")
            return HTMLResponse(theme.notice(
                "Retrieve", f"<span class='pill bad'>retrieve failed</span>"
                f"<div class='desc' style='margin-top:10px'>{html.escape(str(exc))}</div>",
                user=u, active="records", back_href="/records", back_label="Records"), status_code=400)
        audit.append(action="record_retrieve", principal=u["username"], role=u["role"],
                     detail=f"{doc_hash} ({out['size']} bytes)")
        msg = (f"<h2>Retrieved document</h2>"
               f"<div class='desc'>{out['size']} bytes decrypted from the archive with the console "
               "key. A signed read-access event was recorded. The base64 is shown once for you to save.</div>"
               f"<p class='mono' style='word-break:break-all'>{html.escape(out['data_b64'])}</p>")
        return HTMLResponse(theme.notice("Retrieved", msg, user=u, active="records",
                                         back_href="/records", back_label="Records"))

    @app.post("/records/holds/place")
    async def records_place_hold(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_holds"):
            return HTMLResponse("Forbidden", status_code=403)
        vault = _records.get_vault(console_signer)
        if vault is None:
            return HTMLResponse("Records Vault not installed. <a href='/records/holds'>back</a>", status_code=501)
        form = await request.form()
        if not authenticate(u["username"], (form.get("confirm_password", "") or "")):
            audit.append(action="hold_place", principal=u["username"], role=u["role"],
                         detail="blocked: password confirmation failed")
            return HTMLResponse(theme.notice(
                "Place hold", "<span class='pill bad'>password confirmation failed</span>",
                user=u, active="records", back_href="/records/holds", back_label="Legal holds"),
                status_code=401)
        subject = (form.get("subject_ref", "") or "").strip()
        query = {"subject_ref": subject} if subject else {}
        pd = (form.get("preservation_days", "") or "").strip()
        preservation_days = int(pd) if pd.isdigit() else None
        try:
            holds = vault.holds(retention_days=_records._retention_days(), use_env_bridge=False)
            await holds.place_hold(matter_id=(form.get("matter_id", "") or "").strip(),
                                   query=query, reason=(form.get("reason", "") or ""),
                                   preservation_days=preservation_days)
        except Exception as exc:  # noqa: BLE001
            return HTMLResponse(f"Could not place hold: {html.escape(str(exc))}. "
                                "<a href='/records/holds'>back</a>", status_code=400)
        audit.append(action="hold_place", principal=u["username"], role=u["role"],
                     detail=(form.get("matter_id", "") or ""))
        return RedirectResponse("/records/holds", status_code=303)

    @app.post("/records/holds/release")
    async def records_release_hold(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_holds"):
            return HTMLResponse("Forbidden", status_code=403)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/records/holds')}", status_code=303)
        vault = _records.get_vault(console_signer)
        if vault is None:
            return HTMLResponse("Records Vault not installed. <a href='/records/holds'>back</a>", status_code=501)
        form = await request.form()
        matter_id = (form.get("matter_id", "") or "").strip()
        try:
            holds = vault.holds(retention_days=_records._retention_days(), use_env_bridge=False)
            await holds.release_hold(matter_id=matter_id, reason=(form.get("reason", "") or ""))
        except Exception as exc:  # noqa: BLE001
            audit.append(action="hold_release", principal=u["username"], role=u["role"],
                         detail=f"blocked {matter_id}: {exc}")
            return HTMLResponse(theme.notice(
                "Release hold", f"<span class='pill bad'>release refused</span>"
                f"<div class='desc' style='margin-top:10px'>{html.escape(str(exc))}</div>",
                user=u, active="records", back_href="/records/holds", back_label="Legal holds"),
                status_code=400)
        audit.append(action="hold_release", principal=u["username"], role=u["role"], detail=matter_id)
        return RedirectResponse("/records/holds", status_code=303)

    # ── Volume import / folder watcher / SFTP-rsync landing zone (manage_records) ──
    from algovoi_command_center import ingest as _ingest

    @app.get("/ingest", response_class=HTMLResponse)
    async def ingest_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        archive = _records.get_archive(console_signer)
        return HTMLResponse(_ingest.render_ingest_page(
            archive is not None, user=u, can_manage=roles.can(u["role"], "manage_records")))

    @app.post("/ingest/import")
    async def ingest_import(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_records"):
            return RedirectResponse("/ingest", status_code=303)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/ingest')}", status_code=303)
        form = await request.form()
        try:
            batch = int(form.get("batch_size") or "1000")
        except ValueError:
            batch = 1000
        archive = _records.get_archive(console_signer)
        if archive is None:
            return RedirectResponse("/ingest", status_code=303)
        job_id, msg = _ingest.start_import(
            archive, (form.get("path") or "").strip(), strategy=form.get("strategy") or "merkle",
            mode=form.get("mode") or "bridge", batch_size=batch, principal=u["username"])
        audit.append(action="volume_import_start", principal=u["username"], role=u["role"],
                     detail=(job_id or msg))
        return RedirectResponse("/ingest", status_code=303)

    @app.post("/ingest/watch/start")
    async def ingest_watch_start(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_records"):
            return RedirectResponse("/ingest", status_code=303)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/ingest')}", status_code=303)
        form = await request.form()
        archive = _records.get_archive(console_signer)
        if archive is None:
            return RedirectResponse("/ingest", status_code=303)
        ok, msg = _ingest.start_watch(
            archive, (form.get("path") or "").strip(), strategy=form.get("strategy") or "merkle",
            mode=form.get("mode") or "bridge")
        audit.append(action="watcher_start", principal=u["username"], role=u["role"], detail=msg)
        return RedirectResponse("/ingest", status_code=303)

    @app.post("/ingest/watch/stop")
    async def ingest_watch_stop(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_records"):
            return RedirectResponse("/ingest", status_code=303)
        _ingest.stop_watch()
        audit.append(action="watcher_stop", principal=u["username"], role=u["role"], detail="")
        return RedirectResponse("/ingest", status_code=303)

    @app.get("/api/ingest")
    async def api_ingest(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "view_dashboard"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse({"available": _ingest.available(), "landing_zones": _ingest.landing_zones(),
                             "jobs": _ingest.jobs(), "watcher": _ingest.watch_state()})

    # ── Local-accounts management (manage_users) ──
    from algovoi_command_center import users as _users

    @app.get("/users", response_class=HTMLResponse)
    async def users_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "manage_users"):
            return HTMLResponse("Forbidden", status_code=403)
        return HTMLResponse(_users.render_users_page(u))

    @app.post("/users/add")
    async def users_add(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_users"):
            return HTMLResponse("Forbidden", status_code=403)
        form = await request.form()
        if not authenticate(u["username"], (form.get("confirm_password", "") or "")):
            audit.append(action="user_add", principal=u["username"], role=u["role"],
                         detail="blocked: password confirmation failed")
            return HTMLResponse(_users.render_users_page(u, error="Re-enter your own password to add an account."),
                                status_code=401)
        try:
            _users.add_user((form.get("username", "") or ""), (form.get("password", "") or ""),
                            (form.get("role", "") or ""))
        except ValueError as exc:
            return HTMLResponse(_users.render_users_page(u, error=str(exc)), status_code=400)
        audit.append(action="user_add", principal=u["username"], role=u["role"],
                     detail=f"{form.get('username','')} as {form.get('role','')}")
        return RedirectResponse("/users", status_code=303)

    @app.post("/users/role")
    async def users_role(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_users"):
            return HTMLResponse("Forbidden", status_code=403)
        form = await request.form()
        target = (form.get("username", "") or "")
        try:
            _users.set_role(target, (form.get("role", "") or ""), acting_user=u["username"])
        except ValueError as exc:
            return HTMLResponse(_users.render_users_page(u, error=str(exc)), status_code=400)
        audit.append(action="user_role", principal=u["username"], role=u["role"],
                     detail=f"{target} -> {form.get('role','')}")
        return RedirectResponse("/users", status_code=303)

    @app.post("/users/remove")
    async def users_remove(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_users"):
            return HTMLResponse("Forbidden", status_code=403)
        form = await request.form()
        target = (form.get("username", "") or "")
        try:
            _users.remove_user(target, acting_user=u["username"])
        except ValueError as exc:
            return HTMLResponse(_users.render_users_page(u, error=str(exc)), status_code=400)
        audit.append(action="user_remove", principal=u["username"], role=u["role"], detail=target)
        return RedirectResponse("/users", status_code=303)

    # ── Operator-controlled updates (offline by default; only contacts pip.algovoi.co.uk on demand) ──
    from algovoi_command_center import updates as _updates

    @app.get("/updates", response_class=HTMLResponse)
    async def updates_page(request: Request):
        u = user_of(request)
        if not u:
            return RedirectResponse("/login", status_code=303)
        if not roles.can(u["role"], "view_dashboard"):
            return HTMLResponse("Forbidden", status_code=403)
        return HTMLResponse(_updates.render_updates_page(
            _updates.state(), can_manage=roles.can(u["role"], "manage_updates"), user=u))

    @app.get("/api/updates")
    async def api_updates(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "view_dashboard"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse(_updates.state())   # no network

    @app.post("/v1/updates/policy")
    async def api_update_policy(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_updates"):
            return HTMLResponse("Forbidden", status_code=403) if "text/html" in request.headers.get("accept", "") \
                else JSONResponse({"error": "forbidden"}, status_code=403)
        form = await request.form()
        enabled = (form.get("online_enabled", "") or "").strip() in ("1", "true", "on", "yes")
        _updates.set_online(enabled)
        audit.append(action="update_policy", principal=u["username"], role=u["role"],
                     detail=f"online_checks={'on' if enabled else 'off'}")
        if "text/html" in request.headers.get("accept", ""):
            return RedirectResponse("/updates", status_code=303)
        return JSONResponse({"online_enabled": enabled})

    @app.post("/v1/updates/check")
    async def api_update_check(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_updates"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        wants_html = "text/html" in request.headers.get("accept", "")
        try:
            summary = await asyncio.to_thread(_updates.check_online)   # the only egress, on explicit action
        except _updates.UpdatesDisabled as exc:
            audit.append(action="update_check", principal=u["username"], role=u["role"], detail="blocked: disabled")
            msg = str(exc)
            return HTMLResponse(theme.notice("Update check", f"<span class='pill neutral'>online checks "
                                             f"disabled</span><div class='desc' style='margin-top:10px'>{html.escape(msg)}"
                                             "</div>", user=u, active="updates", back_href="/updates",
                                             back_label="Updates")) \
                if wants_html else JSONResponse({"error": msg}, status_code=409)
        except Exception as exc:  # noqa: BLE001
            audit.append(action="update_check", principal=u["username"], role=u["role"], detail=f"error: {exc}")
            return HTMLResponse(theme.notice("Update check", "<span class='pill bad'>check failed</span>"
                                             f"<div class='desc' style='margin-top:10px'>{html.escape(str(exc))}</div>",
                                             user=u, active="updates", back_href="/updates", back_label="Updates"),
                                status_code=502) \
                if wants_html else JSONResponse({"error": str(exc)}, status_code=502)
        audit.append(action="update_check", principal=u["username"], role=u["role"],
                     detail=f"available={summary['available']} version={summary.get('version')}")
        if wants_html:
            return HTMLResponse(_updates.render_result_page(
                title="Update check", summary=summary, can_manage=True, user=u))
        summary.pop("_manifest", None)
        return JSONResponse(summary)

    @app.post("/v1/updates/apply")
    async def api_update_apply(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_updates"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        # Applying an update runs pip install (host code execution); require a fresh step-up, matching
        # the other sensitive actions rather than riding an 8h session.
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/updates')}", status_code=303)
        try:
            report = await asyncio.to_thread(_updates.apply_online)
        except Exception as exc:  # noqa: BLE001
            audit.append(action="update_apply", principal=u["username"], role=u["role"], detail=f"error: {exc}")
            return HTMLResponse(theme.notice("Update", "<span class='pill bad'>update failed</span>"
                                             f"<div class='desc' style='margin-top:10px'>{html.escape(str(exc))}</div>",
                                             user=u, active="updates", back_href="/updates", back_label="Updates"),
                                status_code=502)
        audit.append(action="update_apply", principal=u["username"], role=u["role"],
                     detail=f"applied={report.get('applied')} version={report.get('version')}")
        report["available"] = False
        return HTMLResponse(_updates.render_result_page(title="Update applied", summary=report, can_manage=True, user=u))

    @app.post("/v1/updates/apply-offline")
    async def api_update_apply_offline(request: Request):
        u = user_of(request)
        if not u or not roles.can(u["role"], "manage_updates"):
            return HTMLResponse("Forbidden", status_code=403)
        if not _stepup_ok(request, u):
            return RedirectResponse(f"/verify?next={quote('/updates')}", status_code=303)
        form = await request.form()
        manifest = (form.get("manifest", "") or "").strip()
        algv_path = (form.get("algv_path", "") or "").strip()
        try:
            report = await asyncio.to_thread(_updates.apply_offline, manifest, algv_path)
        except Exception as exc:  # noqa: BLE001
            audit.append(action="update_apply_offline", principal=u["username"], role=u["role"],
                         detail=f"error: {exc}")
            return HTMLResponse(theme.notice("Offline update", "<span class='pill bad'>update failed</span>"
                                             f"<div class='desc' style='margin-top:10px'>{html.escape(str(exc))}</div>",
                                             user=u, active="updates", back_href="/updates", back_label="Updates"),
                                status_code=400)
        audit.append(action="update_apply_offline", principal=u["username"], role=u["role"],
                     detail=f"applied={report.get('applied')} version={report.get('version')}")
        report["available"] = False
        return HTMLResponse(_updates.render_result_page(title="Offline update applied", summary=report,
                                                        can_manage=True, user=u))

    # Mount discovered provisioning add-ons (SCIM, ...) last, so they share the console's signed audit
    # chain. Licence-gated per add-on; absent/unlicensed add-ons leave no /scim routes (fail-closed).
    _mount_provisioning(app, audit)

    return app


app = create_app()


def main() -> None:
    """Console entry point — serve the command center (``algovoi-command-center``)."""
    import uvicorn
    # SECURITY (2026-08-20): default to loopback, and refuse a non-loopback (public) bind unless the
    # service token is explicitly set — the console exposes admin/audit/provisioning surfaces, so a
    # 0.0.0.0 default must not put them on the network without deliberate, authenticated opt-in.
    host = os.environ.get("COMMAND_CENTER_HOST", "127.0.0.1")
    token = os.environ.get("COMMAND_CENTER_SERVICE_TOKEN", "").strip() or None
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            "refusing to bind the command center to a non-loopback address without "
            "COMMAND_CENTER_SERVICE_TOKEN set (the admin / audit / provisioning API would be exposed). "
            "Set COMMAND_CENTER_SERVICE_TOKEN for a public bind, or keep the default loopback host.")
    uvicorn.run("algovoi_command_center.app:app", host=host,
                port=int(os.environ.get("COMMAND_CENTER_PORT", "8200")))
