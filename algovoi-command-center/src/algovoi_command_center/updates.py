"""Operator-controlled update mechanism for the AlgoVoi on-prem suite, driven entirely from the
Compliance Command Center.

Design constraints (deliberate, for a self-hosted compliance product):

* **No phone-home.** The console never contacts the network on its own. Online update checks are
  **disabled by default** and must be explicitly enabled by an operator in the console. Even when
  enabled, the network is touched *only* on an explicit operator action (Check / Apply) — there is no
  timer and no background poll.
* **One destination, pinned.** The only host the updater will ever contact is ``pip.algovoi.co.uk``
  over HTTPS. A signed manifest that points a download anywhere else is refused.
* **Signed, verified before install.** A release is an ``algovoi_release_manifest`` Falcon-1024-signed
  by the same AlgoVoi issuer key that signs licences. The manifest signature is verified first; then the
  downloaded bundle's sha256 and every wheel's sha256 are checked against the signed manifest; only then
  are the wheels installed. Nothing unsigned is ever executed.
* **Offline-capable.** Airgapped sites apply the identical signed manifest + ``.algv`` from local files
  with no network at all.
* **Operator-approved.** Updates are never auto-applied; the console surfaces "update available" and an
  operator applies it. The previous wheels are retained for rollback and every action is written to the
  signed console audit chain.

Wheel-bundle scope only: this upgrades the suite's Python wheels (the ``.algv`` bundle). It does not
touch service container images.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── constants ────────────────────────────────────────────────────────────────
ALLOWED_HOST = "pip.algovoi.co.uk"                 # the ONLY host the updater will ever contact
CHANNEL_DEFAULT = f"https://{ALLOWED_HOST}/updates/vcs/release.json"
_ALGV_MAGIC = b"ALGV1\0"
_ALGV_AAD = b"algovoi-onprem-bundle/v1"
RELEASE_TYPE = "algovoi_release_manifest"

# AlgoVoi issuer Falcon-1024 PUBLIC key (kid fd79e270ffc02162) — the same key that signs licences and
# the bundle. Public key only, safe to embed; release manifests are verified against it.
_ISSUER_PUBKEY_B64 = (
    "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"
    "+iYU1rgSmfE12ec=")
_PUBLIC_KEY_BYTES = 1793


class UpdatesDisabled(RuntimeError):
    """Raised when an online action is attempted while online checks are disabled."""


class UpdateError(RuntimeError):
    """Raised on any verification or install failure (fail-closed)."""


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _issuer_pk() -> bytes:
    return base64.b64decode(_ISSUER_PUBKEY_B64)


# ── policy (persisted; default is fully offline) ─────────────────────────────
def _policy_path() -> str:
    return os.environ.get(
        "COMMAND_CENTER_UPDATE_POLICY_FILE",
        os.path.join(os.environ.get("COMMAND_CENTER_DATA_DIR", "."), "command-center-update-policy.json"))


def load_policy() -> dict:
    p = _policy_path()
    pol = {"online_enabled": False, "channel_url": CHANNEL_DEFAULT, "last_check": None}
    if os.path.exists(p):
        try:
            pol.update(json.load(open(p, encoding="utf-8")))
        except Exception:  # noqa: BLE001
            pass
    # channel is host-pinned no matter what is persisted
    if urlparse(pol.get("channel_url") or "").hostname != ALLOWED_HOST:
        pol["channel_url"] = CHANNEL_DEFAULT
    return pol


def save_policy(pol: dict) -> None:
    p = _policy_path()
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(pol, fh, indent=2)
    os.replace(tmp, p)


def set_online(enabled: bool) -> dict:
    pol = load_policy()
    pol["online_enabled"] = bool(enabled)
    save_policy(pol)
    return pol


# ── installed inventory + version diffing ────────────────────────────────────
def installed_versions() -> dict:
    """Every installed ``algovoi-*`` distribution and its version (the suite inventory)."""
    from importlib import metadata
    out: dict[str, str] = {}
    for dist in metadata.distributions():
        name = (dist.metadata.get("Name") or "").strip()
        if name.lower().startswith("algovoi"):
            out[_canon(name)] = dist.version
    return out


def _canon(name: str) -> str:
    return name.lower().replace("_", "-")


def _installed_version(name: str) -> str | None:
    """The installed version of a single distribution by name, or None. Unlike ``installed_versions``
    (which inventories only ``algovoi-*`` dists for the suite panel), this resolves any package the
    release manifest ships — notably the ``substrate2`` core, which has no ``algovoi`` prefix and would
    otherwise read as not installed and be offered as a spurious upgrade."""
    from importlib import metadata
    for cand in (name, name.replace("-", "_"), name.replace("_", "-")):
        try:
            return metadata.version(cand)
        except Exception:  # noqa: BLE001 — PackageNotFound or odd metadata: try the next spelling
            continue
    return None


def _wheel_name_version(filename: str) -> tuple[str, str]:
    """('algovoi_records_vault_container-0.2.2-py3-none-any.whl') -> ('algovoi-records-vault-container','0.2.2')."""
    base = os.path.basename(filename)
    parts = base[:-4].split("-") if base.endswith(".whl") else base.split("-")
    return _canon(parts[0]), (parts[1] if len(parts) > 1 else "")


def _is_newer(candidate: str, installed: str | None) -> bool:
    if not installed:
        return True
    try:
        from packaging.version import Version
        return Version(candidate) > Version(installed)
    except Exception:  # noqa: BLE001
        return candidate != installed


# ── signed release manifest verification ─────────────────────────────────────
def verify_release(envelope: str, issuer_pk: bytes | None = None) -> dict | None:
    """Return the validated release payload, or ``None`` if the envelope is malformed, not a release
    manifest, or the Falcon signature does not verify against the AlgoVoi issuer key."""
    try:
        from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
        import rfc8785
    except Exception:  # noqa: BLE001
        raise UpdateError("verification deps missing (pqcrypto, rfc8785)")
    pk = issuer_pk or _issuer_pk()
    if len(pk) != _PUBLIC_KEY_BYTES:
        return None
    try:
        env = json.loads(_b64u_decode(envelope))
        payload = env["payload"]
        sig = _b64u_decode(env["sig"])
    except Exception:  # noqa: BLE001
        return None
    if payload.get("type") != RELEASE_TYPE or env.get("alg") != "Falcon-1024":
        return None
    try:
        if not bool(_falcon_verify(pk, rfc8785.dumps(payload), sig)):
            return None
    except Exception:  # noqa: BLE001
        return None
    return payload


def _diff(payload: dict) -> list[dict]:
    """Per-wheel upgrade list vs what is installed now."""
    inst = installed_versions()
    ups = []
    for w in payload.get("wheels", []):
        name, ver = _wheel_name_version(w["name"])
        cur = inst.get(name) or _installed_version(name)
        if _is_newer(ver, cur):
            ups.append({"package": name, "from": cur, "to": ver, "wheel": w["name"], "sha256": w.get("sha256")})
    return ups


def _summarize(payload: dict) -> dict:
    ups = _diff(payload)
    return {"available": bool(ups), "channel": payload.get("channel"), "bundle": payload.get("bundle"),
            "version": payload.get("version"), "released_at": payload.get("released_at"),
            "notes": payload.get("notes", ""), "bundle_url": payload.get("bundle_url"),
            "bundle_sha256": payload.get("bundle_sha256"), "wheels": payload.get("wheels", []),
            "upgrades": ups}


# ── network (host-pinned; the ONLY egress in the whole module) ───────────────
def _fetch(url: str, timeout: float) -> bytes:
    u = urlparse(url or "")
    if u.scheme != "https" or u.hostname != ALLOWED_HOST:
        raise UpdateError(f"refusing to contact {u.hostname!r}; updates only reach {ALLOWED_HOST} over https")
    req = urllib.request.Request(url, headers={"User-Agent": "algovoi-ccc-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — host-pinned above  # nosec B310 - trusted URL (indexer constant / operator-config hub); scheme is fixed http(s)
        return r.read()


def check_online(policy: dict | None = None, *, timeout: float = 10.0) -> dict:
    """Explicit online check. Contacts ``pip.algovoi.co.uk`` exactly once. Refuses if online checks are
    disabled (fail-closed, no egress). Returns a summary of any available upgrade."""
    pol = policy or load_policy()
    if not pol.get("online_enabled"):
        raise UpdatesDisabled(
            "online update checks are disabled. Enable them in the console to allow a one-off request to "
            f"{ALLOWED_HOST}; nothing is contacted until you do.")
    raw = _fetch(pol.get("channel_url", CHANNEL_DEFAULT), timeout).decode("utf-8").strip()
    payload = verify_release(raw)
    if payload is None:
        raise UpdateError("release manifest did not verify against the AlgoVoi issuer key")
    summary = _summarize(payload)
    summary["_manifest"] = raw
    return summary


# ── apply (verify-then-install; the licence key supplies the bundle CEK) ─────
def _cek_from_licence(licence_key: str) -> bytes:
    try:
        payload = json.loads(_b64u_decode(licence_key))["payload"]
        return base64.b64decode(payload["cek_b64"])
    except Exception as exc:  # noqa: BLE001
        raise UpdateError(f"licence does not carry a bundle content key: {exc}") from exc


def _decrypt_algv(blob: bytes, cek: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if blob[:len(_ALGV_MAGIC)] != _ALGV_MAGIC:
        raise UpdateError("not an AlgoVoi bundle (bad magic)")
    nonce, ct = blob[len(_ALGV_MAGIC):len(_ALGV_MAGIC) + 12], blob[len(_ALGV_MAGIC) + 12:]
    try:
        return AESGCM(cek).decrypt(nonce, ct, _ALGV_AAD)
    except Exception as exc:  # noqa: BLE001
        raise UpdateError("bundle decryption failed (wrong licence or corrupt/tampered bundle)") from exc


def _licence_key() -> str:
    key = os.environ.get("ALGOVOI_LICENSE_KEY", "").strip()
    if not key:
        f = os.environ.get("ALGOVOI_LICENSE_FILE")
        if f and os.path.exists(f):
            key = open(f, encoding="utf-8").read().strip()
    if not key:
        raise UpdateError("no bundle licence available to decrypt the update (ALGOVOI_LICENSE_KEY)")
    return key


def apply_release(manifest_env: str, algv_bytes: bytes, *, licence_key: str | None = None,
                  do_install: bool = True) -> dict:
    """Verify a signed release manifest, verify the ``.algv`` bytes against it, extract the wheels, and
    ``pip install --upgrade`` them. Every hash is checked against the *signed* manifest before install.
    Returns an install report. Fail-closed on any mismatch."""
    payload = verify_release(manifest_env)
    if payload is None:
        raise UpdateError("release manifest did not verify against the AlgoVoi issuer key")
    # 1) the transported bundle must match the sha256 the signed manifest commits to
    if payload.get("bundle_sha256"):
        got = hashlib.sha256(algv_bytes).hexdigest()
        if got != payload["bundle_sha256"]:
            raise UpdateError(f"bundle sha256 mismatch (manifest {payload['bundle_sha256'][:12]}… got {got[:12]}…)")
    # 2) decrypt with the licence CEK and extract wheels
    cek = _cek_from_licence(licence_key or _licence_key())
    tar_bytes = _decrypt_algv(algv_bytes, cek)
    want = {w["name"]: w.get("sha256") for w in payload.get("wheels", [])}
    staging = os.path.join(os.environ.get("COMMAND_CENTER_DATA_DIR", "."), "update-staging")
    os.makedirs(staging, exist_ok=True)
    written: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not (m.name.startswith("wheels/") and m.name.endswith(".whl")):
                continue
            name = os.path.basename(m.name)
            data = tf.extractfile(m).read()
            # 3) every wheel must match the sha256 the SIGNED manifest commits to
            if name in want and want[name] and hashlib.sha256(data).hexdigest() != want[name]:
                raise UpdateError(f"wheel {name} failed signed-manifest integrity check")
            dest = os.path.join(staging, name)
            with open(dest, "wb") as fh:
                fh.write(data)
            written.append(dest)
    # only install the wheels the manifest lists (the upgrade set); ignore any extras defensively
    to_install = [p for p in written if os.path.basename(p) in want] or written
    report = {"version": payload.get("version"), "released_at": payload.get("released_at"),
              "upgrades": _diff(payload), "wheels": [os.path.basename(p) for p in to_install],
              "installed": False}
    if do_install:
        rc = subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade", *to_install])
        if rc != 0:
            raise UpdateError("pip install of the update wheels failed")
        report["installed"] = True
    return report


def apply_online(policy: dict | None = None, *, timeout: float = 30.0,
                 licence_key: str | None = None, do_install: bool = True) -> dict:
    """Explicit online apply: check, download the signed bundle from ``pip.algovoi.co.uk`` (host-pinned),
    verify, and install. Refuses if online checks are disabled."""
    summary = check_online(policy, timeout=timeout)
    if not summary["available"]:
        return {"applied": False, "reason": "already up to date", "version": summary.get("version")}
    if not summary.get("bundle_url"):
        raise UpdateError("release manifest carries no bundle_url to download")
    algv = _fetch(summary["bundle_url"], timeout)   # host-pinned again inside _fetch
    report = apply_release(summary["_manifest"], algv, licence_key=licence_key, do_install=do_install)
    report["applied"] = report.get("installed", False)
    return report


def apply_offline(manifest_env: str, algv_path: str, *, licence_key: str | None = None,
                  do_install: bool = True) -> dict:
    """Apply a signed update from local files with NO network (airgapped sites). ``manifest_env`` is the
    signed release manifest string; ``algv_path`` is the transferred ``.algv``."""
    with open(algv_path, "rb") as fh:
        algv = fh.read()
    report = apply_release(manifest_env, algv, licence_key=licence_key, do_install=do_install)
    report["applied"] = report.get("installed", False)
    report["offline"] = True
    return report


def state() -> dict:
    """Console-facing state with NO network access: policy + installed inventory."""
    pol = load_policy()
    return {"online_enabled": pol.get("online_enabled", False),
            "channel_url": pol.get("channel_url", CHANNEL_DEFAULT),
            "allowed_host": ALLOWED_HOST, "last_check": pol.get("last_check"),
            "installed": installed_versions()}


# ── themed console panel ─────────────────────────────────────────────────────
def render_updates_page(st: dict, *, can_manage: bool, user: dict | None = None) -> str:
    import html
    from algovoi_command_center import theme
    e = html.escape
    on = st.get("online_enabled")
    inv = st.get("installed", {})
    rows = "".join(f'<tr><td class="mono">{e(k)}</td><td class="mono">{e(v)}</td></tr>'
                   for k, v in sorted(inv.items())) or '<tr><td class="muted">No packages found.</td></tr>'
    badge = ('<span class="pill ok">enabled</span>' if on else '<span class="pill neutral">disabled</span>')
    controls = []
    if can_manage:
        nxt = "0" if on else "1"
        label = "Disable online checks" if on else "Enable online checks"
        controls.append(f'<form method="post" action="/v1/updates/policy" style="display:inline">'
                        f'<input type="hidden" name="online_enabled" value="{nxt}">'
                        f'<button class="btn" type="submit">{label}</button></form>')
    if can_manage and on:
        controls.append('<form method="post" action="/v1/updates/check" style="display:inline">'
                        '<button class="btn primary" type="submit">Check pip.algovoi.co.uk now</button></form>')
    policy_panel = (
        '<div class="panel"><h2>Update channel</h2>'
        f'<p style="margin:0 0 10px">Online update checks are {badge}'
        f'{" &nbsp; " + " ".join(controls) if controls else ""}</p>'
        f'<div class="desc" style="margin:0">The console contacts <code>{e(st.get("allowed_host", ALLOWED_HOST))}'
        '</code> only when you press Check or Apply, and only while online checks are enabled. It never '
        'contacts anything on its own, and every update is verified against the AlgoVoi signing key before '
        'install.</div></div>')
    inv_panel = ('<div class="panel"><h2>Installed suite packages</h2>'
                 '<table><thead><tr><th>Package</th><th>Version</th></tr></thead>'
                 f'<tbody>{rows}</tbody></table></div>')
    offline = ""
    if can_manage:
        offline = (
            '<div class="panel"><h2>Apply an offline update package</h2>'
            '<div class="desc">For airgapped sites: transfer the signed release manifest and the '
            '<code>.algv</code> onto this host, paste the manifest and give the file path. No network is used.</div>'
            '<form method="post" action="/v1/updates/apply-offline">'
            '<label>Signed release manifest</label><textarea name="manifest" required></textarea>'
            '<label>Path to the .algv on this host</label>'
            '<input name="algv_path" required placeholder="/opt/algovoi/updates/bundle.algv">'
            '<button class="btn primary" type="submit" style="margin-top:14px" '
            "onclick=\"return confirm('Verify and install this update?')\">Verify &amp; apply</button></form></div>")
    return theme.page("Updates", policy_panel + inv_panel + offline, user=user, active="updates",
                      subtitle="Operator-controlled &middot; offline by default")


def render_result_page(*, title: str, summary: dict, can_manage: bool, user: dict | None = None) -> str:
    import html
    from algovoi_command_center import theme
    e = html.escape
    ups = summary.get("upgrades", [])
    if not ups and not summary.get("applied") and not summary.get("available", True):
        body = '<div class="panel"><span class="pill ok">&#10003; up to date</span>' \
               '<p style="margin-top:12px">You are already on the latest release.</p></div>'
        return theme.page(title, body, user=user, active="updates")
    rows = "".join(
        f'<tr><td class="mono">{e(u["package"])}</td>'
        f'<td class="muted">{e(u.get("from") or "(not installed)")}</td>'
        f'<td>{e(u.get("to") or "")}</td></tr>' for u in ups)
    table = ('<table><thead><tr><th>Package</th><th>Installed</th><th>Available</th></tr></thead>'
             f'<tbody>{rows}</tbody></table>') if rows else ""
    apply_btn = ""
    if can_manage and summary.get("available") and not summary.get("applied") and summary.get("_manifest"):
        apply_btn = ('<form method="post" action="/v1/updates/apply" style="margin-top:14px">'
                     '<button class="btn primary" type="submit" onclick="return confirm(\'Download, verify and '
                     'install this update from pip.algovoi.co.uk?\')">Apply update</button></form>')
    note = ('<p style="margin-top:12px"><span class="pill ok">&#10003; update applied</span> '
            'Restart the console to load the new version.</p>' if summary.get("applied") else "")
    ver = e(str(summary.get("version") or ""))
    rel = f' &middot; {e(summary.get("released_at") or "")}' if summary.get("released_at") else ""
    notes = f'<div class="desc">{e(summary.get("notes") or "")}</div>' if summary.get("notes") else ""
    body = (f'<div class="panel"><h2>Release {ver}{rel}</h2>{notes}{table}{note}{apply_btn}</div>')
    return theme.page(title, body, user=user, active="updates")
