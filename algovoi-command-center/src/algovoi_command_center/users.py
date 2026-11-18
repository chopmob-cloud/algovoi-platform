"""Local-accounts management page for the Compliance Command Center (``manage_users`` permission).

The console already authenticates against local accounts (PBKDF2-hashed) stored in the pluggable store;
this page is the operator surface for that store: list accounts, add one, change a role, or remove one.
It edits the same ``load_users`` / ``save_users`` dict the local auth provider reads, so a change takes
effect immediately. LDAP / SSO-mapped users are governed by the directory, not here.

Guardrails, enforced in the routes: the console must never be left without an administrator, and an
operator cannot remove or demote their own account (which would lock them out mid-session).
"""
from __future__ import annotations

import html

from algovoi_command_center import auth as _auth
from algovoi_command_center import roles as _roles
from algovoi_command_center import theme


def admin_count(users: dict) -> int:
    return sum(1 for v in users.values() if v.get("role") == _roles.ADMIN)


def add_user(username: str, password: str, role: str) -> None:
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")
    if role not in _roles.ROLES:
        raise ValueError(f"unknown role {role!r}")
    users = _auth.load_users()
    if username in users:
        raise ValueError(f"user {username!r} already exists")
    pwd_hex, salt = _auth.hash_password(password)
    users[username] = {"pwd": pwd_hex, "salt": salt, "role": role}
    _auth.save_users(users)


def set_role(username: str, role: str, *, acting_user: str) -> None:
    if role not in _roles.ROLES:
        raise ValueError(f"unknown role {role!r}")
    users = _auth.load_users()
    if username not in users:
        raise ValueError(f"unknown user {username!r}")
    if username == acting_user and role != _roles.ADMIN:
        raise ValueError("you cannot remove your own administrator role")
    if users[username].get("role") == _roles.ADMIN and role != _roles.ADMIN and admin_count(users) <= 1:
        raise ValueError("cannot demote the last administrator")
    users[username]["role"] = role
    _auth.save_users(users)


def remove_user(username: str, *, acting_user: str) -> None:
    users = _auth.load_users()
    if username not in users:
        raise ValueError(f"unknown user {username!r}")
    if username == acting_user:
        raise ValueError("you cannot remove your own account")
    if users[username].get("role") == _roles.ADMIN and admin_count(users) <= 1:
        raise ValueError("cannot remove the last administrator")
    del users[username]
    _auth.save_users(users)


def render_users_page(user: dict, *, error: str = "") -> str:
    users = _auth.load_users()
    me = user["username"]
    msg = (f'<div class="pill bad" style="display:block;padding:10px 12px;margin-bottom:14px">'
           f'{html.escape(error)}</div>') if error else ""
    rows = []
    for name in sorted(users):
        role = users[name].get("role", "")
        is_me = name == me
        opts = "".join(
            f'<option value="{r}"{" selected" if r == role else ""}>{html.escape(_roles.ROLE_LABEL.get(r, r))}</option>'
            for r in _roles.ROLES)
        role_form = (
            f"<form method='post' action='/users/role' style='display:flex;gap:6px;align-items:center'>"
            f"<input type='hidden' name='username' value='{html.escape(name)}'>"
            f"<select name='role' style='width:auto;padding:5px 8px'>{opts}</select>"
            f"<button class='btn' type='submit'>Set</button></form>")
        rm = ("<span class='muted' style='font-size:12px'>current session</span>" if is_me else
              f"<form method='post' action='/users/remove' style='display:inline' "
              f"onsubmit=\"return confirm('Remove user {html.escape(name)}?')\">"
              f"<input type='hidden' name='username' value='{html.escape(name)}'>"
              f"<button class='btn danger' type='submit'>Remove</button></form>")
        rows.append(
            f'<tr><td>{html.escape(name)}{" <span class=chip>you</span>" if is_me else ""}</td>'
            f'<td class="muted">local</td>'
            f'<td>{role_form}</td><td class="rt">{rm}</td></tr>')
    table = ('<div class="panel"><h2>Local accounts</h2>'
             '<div class="desc">Accounts stored on this appliance and used by the local auth provider. '
             'LDAP / SSO users are governed by your directory, not here.</div>'
             '<table><thead><tr><th>Username</th><th>Source</th><th>Role</th><th></th></tr></thead>'
             f'<tbody>{"".join(rows) or "<tr><td class=muted>No local accounts.</td></tr>"}'
             '</tbody></table></div>')
    opts = "".join(f'<option value="{r}">{html.escape(_roles.ROLE_LABEL.get(r, r))}</option>'
                   for r in _roles.ROLES)
    add = ('<div class="panel"><h2>Add a local account</h2>'
           '<form method="post" action="/users/add">'
           '<label>Username</label><input name="username" autocomplete="off" required>'
           '<label>Temporary password</label>'
           '<input name="password" type="password" autocomplete="new-password" required>'
           f'<label>Role</label><select name="role">{opts}</select>'
           '<label>Confirm your password</label>'
           '<input name="confirm_password" type="password" autocomplete="current-password" required>'
           '<div class="hint">Adding an account requires re-entering your own password.</div>'
           '<button class="btn primary" type="submit" style="margin-top:16px">Add account</button>'
           '</form></div>')
    return theme.page("Users", msg + table + add, user=user, active="users",
                      subtitle=f"{len(users)} local account(s) &middot; {admin_count(users)} administrator(s)")
