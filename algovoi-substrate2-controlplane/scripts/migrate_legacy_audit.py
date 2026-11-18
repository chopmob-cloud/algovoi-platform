"""Explicitly reconcile legacy audit snapshots before upgrading the control plane.

Run with the production S2CP_DATA_DIR and S2CP_AUDIT_KEY while the service is stopped:
    python scripts/migrate_legacy_audit.py

The script refuses a broken HMAC chain. It records the current persisted state as a
new authenticated state_reconcile event, after which the runtime can replay both
legacy history and the full current snapshot. This is an operator-approved repair;
it is deliberately not automatic because the database may have been tampered with.
"""
from __future__ import annotations

import os
import sys

from algovoi_substrate2_controlplane.service import (
    _AUDIT_KEY,
    _audit_anchor_ok,
    _audit_tail,
    _store,
    _verify_audit_chain,
    _write_audit_anchor,
)


def main() -> int:
    entries = _store.audit_load()
    if not _verify_audit_chain(entries):
        print("REFUSED: existing audit chain is invalid", file=sys.stderr)
        return 2
    state = _store.state_load()
    anchor_path = os.path.join(os.environ.get("S2CP_DATA_DIR", "/app/data"), "audit_anchor.json")
    if not os.path.exists(anchor_path):
        print("REFUSED: an existing audit database must have audit_anchor.json", file=sys.stderr)
        return 3
    if not _audit_anchor_ok(entries, bootstrap_allowed=False):
        print("REFUSED: existing audit anchor does not match the audit tail", file=sys.stderr)
        return 3
    detail = {
        "issuers": state["issuers"],
        "services": state["services"],
        "substrates": state["substrates"],
        "policy": state["policy"],
        "keystone": state["keystone"],
    }
    entry = _store.audit_append("state_reconcile", detail, _AUDIT_KEY)
    new_entries = _store.audit_load()
    _write_audit_anchor(new_entries)
    print(f"RECONCILED seq={entry['seq']} tail={_audit_tail(new_entries)[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
