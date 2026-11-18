"""Phase-e test (standalone, runnable): LDAP/AD provider + auth provider chain.

Uses an injected fake directory (``bind_and_groups``) so no live LDAP server is needed.
Run: python tests/test_sso.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from algovoi_command_center import licensing as _lic  # noqa: E402
_lic.require_license = lambda: {"test": True}

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def main():
    work = tempfile.mkdtemp(prefix="cce-")
    os.environ["COMMAND_CENTER_USERS_FILE"] = os.path.join(work, "users.json")

    import algovoi_command_center.providers as prov
    from algovoi_command_center.providers import LdapProvider, LocalProvider
    from algovoi_command_center import roles
    from algovoi_command_center.auth import hash_password, save_users

    directory = {
        "alice": ("pw1", ["cn=cc-admins,ou=groups,dc=acme"]),
        "bob": ("pw2", ["cn=cc-auditors,ou=groups,dc=acme"]),
        "carol": ("pw3", ["cn=interns,ou=groups,dc=acme"]),
    }

    def fake_bind(username, user_dn, password):
        rec = directory.get(username)
        if not rec or rec[0] != password:
            return None
        return rec[1]

    ldap = LdapProvider(url="ldap://x", user_dn_template="uid={username},dc=acme",
                        group_role_map={"cc-admins": roles.ADMIN, "cc-auditors": roles.AUDITOR},
                        default_role=roles.VIEWER, bind_and_groups=fake_bind)

    check("admin group maps to admin role", (ldap.authenticate("alice", "pw1") or {}).get("role") == roles.ADMIN)
    check("auditor group maps to auditor role", (ldap.authenticate("bob", "pw2") or {}).get("role") == roles.AUDITOR)
    check("unmapped group falls to default role", (ldap.authenticate("carol", "pw3") or {}).get("role") == roles.VIEWER)
    check("bad password fails closed", ldap.authenticate("alice", "WRONG") is None)
    check("empty password rejected (no anonymous bind)", ldap.authenticate("alice", "") is None)
    check("unknown user rejected", ldap.authenticate("mallory", "x") is None)

    no_default = LdapProvider(url="x", user_dn_template="{username}",
                              group_role_map={"cc-admins": roles.ADMIN}, default_role=None,
                              bind_and_groups=fake_bind)
    check("authenticated, no matching group, no default -> None",
          no_default.authenticate("carol", "pw3") is None)

    ph, sa = hash_password("localpw")
    save_users({"localguy": {"pwd": ph, "salt": sa, "role": roles.COMPLIANCE_OFFICER}})
    prov.build_chain = lambda: [ldap, LocalProvider()]  # LDAP first, local fallback
    check("chain: LDAP user authenticates via the first provider",
          (prov.authenticate("alice", "pw1") or {}).get("role") == roles.ADMIN)
    check("chain: local-only user falls through to the local provider",
          (prov.authenticate("localguy", "localpw") or {}).get("role") == roles.COMPLIANCE_OFFICER)
    check("chain: unknown everywhere -> None", prov.authenticate("nobody", "x") is None)

    import shutil
    shutil.rmtree(work, ignore_errors=True)
    print(f"\n=== PHASE-E (SSO / LDAP) RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
