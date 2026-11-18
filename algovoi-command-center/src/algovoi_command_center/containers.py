"""Compliance Command Center binding for sealed ``.acv`` records containers.

Lets an operator **create** a portable, ML-KEM-sealed encrypted container from a set of records and
**revoke** it later, both signed with the console key. The heavy lifting lives in the
``algovoi-records-vault-container`` add-on; this module is a thin, lazily-imported binding so the console
still runs if the add-on is not installed (the feature simply reports as unavailable).
"""
from __future__ import annotations

import base64
import html
import json
import os

_REGISTRY = None


def _escrow_keypair():
    """Load or bootstrap the console escrow ML-KEM keypair (the 'recover from console' key). Stored at
    COMMAND_CENTER_CONTAINER_RECOVERY_KEY_FILE. Returns (public, secret) or (None, None) if the add-on
    is absent. Whoever holds this secret can recover any console-recoverable container, so protect it
    like the console signing key (a KMS/Vault/PKCS#11-backed file is recommended in production)."""
    try:
        from algovoi_doc_archive.encryption import generate_mlkem_keypair
    except Exception:  # noqa: BLE001
        return None, None
    path = os.environ.get("COMMAND_CENTER_CONTAINER_RECOVERY_KEY_FILE",
                          os.path.join(os.environ.get("COMMAND_CENTER_CONTAINER_DIR",
                                                       "./command-center-containers"), "escrow-key.json"))
    if os.path.exists(path):
        d = json.load(open(path, encoding="utf-8"))
        return base64.b64decode(d["pk"]), base64.b64decode(d["sk"])
    pk, sk = generate_mlkem_keypair()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"pk": base64.b64encode(pk).decode(), "sk": base64.b64encode(sk).decode()}, fh)
    try:
        os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001
        pass
    return pk, sk


def available() -> bool:
    try:
        import algovoi_records_vault_container  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def get_registry(console_signer):
    """A process-wide ContainerRegistry signed by the console key, or None if the add-on is absent."""
    global _REGISTRY
    if _REGISTRY is not None:
        return _REGISTRY
    if not available():
        return None
    from algovoi_records_vault_container import ContainerRegistry
    base = os.environ.get("COMMAND_CENTER_CONTAINER_DIR", "./command-center-containers")
    epk, esk = _escrow_keypair()
    _REGISTRY = ContainerRegistry(
        index_path=os.path.join(base, "index.jsonl"),
        out_dir=os.path.join(base, "acv"),
        issuer_signer=console_signer,
        registry=os.environ.get("COMMAND_CENTER_CONTAINER_REGISTRY", "default"),
        escrow_public_key=epk, escrow_secret_key=esk,
    )
    return _REGISTRY


def create_from_request(reg, body: dict) -> dict:
    """Create a container from an API body: ``recipient_public_key_b64`` + ``documents`` (each
    ``{"name", "data_b64"}``), optional ``title`` / ``expires_at`` / ``container_id``, and optional
    ``recovery`` = ``{"threshold_k", "total_n", "include_algovoi_support"?}``. When recovery is set the
    response carries one-time ``recovery.shares`` to hand to custodians (they are never stored)."""
    recipient = base64.b64decode(body["recipient_public_key_b64"])
    documents = [{"name": d["name"], "data": base64.b64decode(d["data_b64"])} for d in body["documents"]]
    if not documents:
        raise ValueError("no documents")
    man = reg.create(documents=documents, recipient_public_key=recipient,
                     container_id=body.get("container_id"), title=body.get("title"),
                     expires_at=body.get("expires_at"), recovery=body.get("recovery"),
                     console_recoverable=bool(body.get("console_recoverable")))
    out = {"container_id": man["container_id"], "recipient_kid": man["recipient_kid"],
           "documents": man["documents"], "sha256": man["sha256"], "created_at": man["created_at"],
           "download_path": man["path"], "console_recoverable": bool(man.get("escrow", {}).get("enabled"))}
    rec = man.get("recovery") or {}
    if rec.get("enabled"):
        out["recovery"] = {"threshold_k": rec["threshold_k"], "total_n": rec["total_n"],
                           "shares": rec["shares"]}   # one-time — distribute to custodians, never stored
    return out


def recover_from_console(reg, container_id: str) -> dict:
    """Recover a console-recoverable container 100% from the console escrow key. Returns the decrypted
    documents as base64 (the operator saves them). Raises if the container is not console-recoverable."""
    _payload, docs = reg.recover(container_id)
    return {"container_id": container_id,
            "documents": [{"name": n, "data_b64": base64.b64encode(d).decode()} for n, d in docs.items()]}


def posture(reg) -> dict:
    return reg.posture() if reg else {"issued": 0, "revoked": 0, "active": 0, "available": False}


# ── Themed console panel ─────────────────────────────────────────────────────────

def render_containers_page(reg, user: dict, *, can_manage: bool) -> str:
    from algovoi_command_center import theme
    if reg is None:
        body = ('<div class="panel"><h2>Sealed containers</h2><div class="desc">The '
                '<code>algovoi-records-vault-container</code> add-on is not installed on this console.</div></div>')
        return theme.page("Sealed containers", body, user=user, active="containers")
    p = reg.posture()
    rows = []
    for c in reg.list_containers():
        status = ('<span class="pill bad">revoked</span>' if c["revoked"]
                  else '<span class="pill ok">active</span>')
        cid = html.escape(c["container_id"])
        btns = []
        if can_manage and not c["revoked"]:
            btns.append(
                f"<form method='post' action='/v1/containers/{cid}/revoke' style='display:inline' "
                f"onsubmit=\"return confirm('Revoke this container?')\">"
                f"<input type='hidden' name='reason' value='revoked via console'>"
                f"<button class='btn danger' type='submit'>Revoke</button></form>")
        if can_manage and c.get("console_recoverable"):
            btns.append(
                f"<form method='post' action='/v1/containers/{cid}/recover' style='display:inline' "
                f"onsubmit=\"return confirm('Recover this container from the console escrow key?')\">"
                f"<button class='btn' type='submit'>Recover</button></form>")
        rec_mark = ' <span title="console-recoverable">&#128273;</span>' if c.get("console_recoverable") else ""
        rows.append(
            f'<tr><td class="mono">{cid}{rec_mark}</td>'
            f'<td>{html.escape(c.get("title") or "")}</td>'
            f'<td class="rt">{c["documents"]}</td>'
            f'<td class="mono faint">{html.escape(c["recipient_kid"])}</td>'
            f'<td class="muted mono">{html.escape(c["created_at"])}</td>'
            f'<td>{status}</td><td class="rt">{" ".join(btns)}</td></tr>')
    table = ('<div class="panel"><h2>Issued containers</h2>'
             '<table><thead><tr><th>Container</th><th>Title</th><th class="rt">Docs</th>'
             '<th>Recipient</th><th>Created</th><th>Status</th><th></th></tr></thead>'
             f'<tbody>{"".join(rows) or "<tr><td class=muted>No containers issued yet.</td></tr>"}</tbody></table></div>')
    create = ""
    if can_manage:
        create = (
            '<div class="panel"><h2>Create a sealed container</h2>'
            '<form method="post" action="/containers/create">'
            '<label>Title</label><input name="title" placeholder="Q3 disclosure to auditor">'
            '<label>Recipient ML-KEM public key (base64)</label>'
            '<textarea name="recipient_public_key_b64" required></textarea>'
            '<label>Document name</label><input name="doc_name" value="record.txt" required>'
            '<label>Document contents</label><textarea name="doc_text" required></textarea>'
            '<label>Recovery (optional)</label>'
            '<div style="display:flex;gap:8px;align-items:center">threshold '
            '<input name="recovery_k" style="width:64px" inputmode="numeric"> of '
            '<input name="recovery_n" style="width:64px" inputmode="numeric"></div>'
            '<div class="hint">If set, k of n Shamir custodian shares are shown once to distribute.</div>'
            '<label style="display:flex;gap:8px;align-items:center;margin-top:14px">'
            '<input type="checkbox" name="console_recoverable" value="1" style="width:auto">'
            'Console-recoverable</label>'
            '<div class="hint">Also seal to the console escrow key so this container can be recovered here '
            'without the recipient key. Anyone holding the console recovery key can then decrypt it.</div>'
            '<label>Confirm your password</label>'
            '<input name="confirm_password" type="password" autocomplete="current-password" required>'
            '<div class="hint">Creating a container requires re-entering your password.</div>'
            '<button class="btn primary" type="submit" style="margin-top:16px">Seal &amp; issue</button>'
            '</form></div>')
    subtitle = (f'{p["issued"]} issued &middot; {p["active"]} active &middot; {p["revoked"]} revoked')
    crl = '<a class="btn" href="/v1/containers/crl">&#8681; Signed revocation list</a>'
    return theme.page("Sealed containers", table + create, user=user, active="containers",
                      subtitle=subtitle, extra_right=crl)
