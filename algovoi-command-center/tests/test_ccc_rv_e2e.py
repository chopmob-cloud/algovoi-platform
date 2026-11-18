"""Phase 3 clean-box e2e: Records Vault + Command Center, end to end, on real sockets.

Runs BOTH real services in one box and proves the whole bridge together:

  * the Command Center ingests a signed evidence pack (evidence posture), and
  * Records Vault boots, self-registers via its serve layer, and the Command Center
    polls its real /health (live posture),

then checks the console dashboard shows BOTH postures as distinct sections — live
service health alongside evidence integrity — which is the acceptance bar in the plan.

Fully local (no VM, no network beyond loopback).

Run: python tests/test_ccc_rv_e2e.py
   (needs pqcrypto + rfc8785 + httpx + uvicorn, and the doc-archive + records-vault src trees)
"""
import base64
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import time

CC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLATFORM = os.path.dirname(CC_ROOT)
sys.path.insert(0, os.path.join(CC_ROOT, "src"))
sys.path.insert(0, os.path.join(PLATFORM, "algovoi-doc-archive", "src"))
sys.path.insert(0, os.path.join(PLATFORM, "algovoi-records-vault", "src"))

SVC_TOKEN = "e2e-shared-service-token"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


CCC_PORT = _free_port()
RV_PORT = _free_port()
_WORK = tempfile.mkdtemp(prefix="ccc-rv-e2e-")
_INGEST = os.path.join(_WORK, "ingest")
os.makedirs(_INGEST, exist_ok=True)

# --- Command Center env (set before importing it) ---
os.environ["COMMAND_CENTER_DB"] = "sqlite:///" + os.path.join(_WORK, "cc.db")
os.environ["COMMAND_CENTER_DATA_DIR"] = _WORK
os.environ["COMMAND_CENTER_KEY_FILE"] = os.path.join(_WORK, "cc-key.json")
os.environ["COMMAND_CENTER_INGEST_DIR"] = _INGEST
os.environ["COMMAND_CENTER_ESTATE"] = "estate-e2e"
os.environ["COMMAND_CENTER_SERVICE_TOKEN"] = SVC_TOKEN
os.environ["COMMAND_CENTER_SECRET"] = "e2e-fixed-session-secret"

# --- Records Vault serve env: point it at the Command Center ---
os.environ["RV_ARCHIVE_DIR"] = os.path.join(_WORK, "rv-archive")
os.environ["CCC_HUB_URL"] = f"http://127.0.0.1:{CCC_PORT}"
os.environ["CCC_HUB_TOKEN"] = SVC_TOKEN
os.environ["CCC_HUB_NAME"] = "records-vault"
os.environ["CCC_HUB_SELF_URL"] = f"http://127.0.0.1:{RV_PORT}"

from algovoi_command_center import licensing as _cclic  # noqa: E402
_cclic.require_license = lambda *a, **k: {"test": True}
from algovoi_doc_archive import licensing as _dalic  # noqa: E402
_dalic.require_license = lambda *a, **k: {"test": True}

import httpx  # noqa: E402
import rfc8785  # noqa: E402
import uvicorn  # noqa: E402
from pqcrypto.sign.falcon_1024 import generate_keypair, sign  # noqa: E402

from algovoi_command_center import roles  # noqa: E402
from algovoi_command_center.app import create_app as cc_create_app  # noqa: E402
from algovoi_command_center.audit import LocalSigner  # noqa: E402
from algovoi_command_center.auth import make_session  # noqa: E402
from algovoi_records_vault import serve as rv_serve  # noqa: E402

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _phash(payload):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _chain(pk, sk, etype, rows):
    envs, prev = [], None
    for i, fields in enumerate(rows):
        payload = {**fields, "type": etype, "seq": i, "prev_entry_hash": prev}
        env = {"payload": payload, "sig": _b64u(sign(sk, rfc8785.dumps(payload))),
               "kid": hashlib.sha256(pk).hexdigest()[:16]}
        envs.append(_b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()))
        prev = _phash(payload)
    return envs


def _seed_evidence_pack():
    """A signed evidence pack the Command Center will ingest (the evidence posture)."""
    d = os.path.join(_INGEST, "records-vault-estate")
    os.makedirs(d, exist_ok=True)
    pk, sk = generate_keypair()
    open(os.path.join(d, "public_key.b64"), "w").write(base64.b64encode(pk).decode())
    json.dump(_chain(pk, sk, "archive_entry", [{"doc_hash": "sha256:aa"}, {"doc_hash": "sha256:bb"}]),
              open(os.path.join(d, "archive_chain.json"), "w"))
    json.dump(_chain(pk, sk, "vault_access_event", [{"decision": "granted"}, {"decision": "denied"}]),
              open(os.path.join(d, "access_chain.json"), "w"))
    json.dump(_chain(pk, sk, "vault_legal_hold", [{"action": "set", "matter_id": "M-1"}]),
              open(os.path.join(d, "holds_chain.json"), "w"))


def _serve(app, port):
    uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")).run()


def _wait_up(base):
    for _ in range(80):
        try:
            if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                return True
        except Exception:
            time.sleep(0.2)
    return False


def main():
    cc_base = f"http://127.0.0.1:{CCC_PORT}"
    rv_base = f"http://127.0.0.1:{RV_PORT}"

    _seed_evidence_pack()

    # Command Center (its own signer so its audit chain verifies)
    pk, sk = generate_keypair()
    cc_app = cc_create_app(signer=LocalSigner(pk, sk))
    threading.Thread(target=_serve, args=(cc_app, CCC_PORT), daemon=True).start()
    check("command center is live", _wait_up(cc_base))

    # Records Vault serve layer — self-registers with the command center on startup
    threading.Thread(target=_serve, args=(rv_serve.app, RV_PORT), daemon=True).start()
    check("records vault is live", _wait_up(rv_base))

    # give startup self-registration a moment to land
    registered = False
    for _ in range(50):
        names = {s["name"] for s in httpx.get(f"{cc_base}/v1/services", timeout=5).json()["services"]}
        if "records-vault" in names:
            registered = True
            break
        time.sleep(0.1)
    check("records vault self-registered with the command center", registered)

    cookies = {"cc_session": make_session("admin", roles.ADMIN)}

    # live posture: the command center polls the vault's real /health
    poll = httpx.get(f"{cc_base}/api/services", cookies=cookies, timeout=10).json()
    rv = next((s for s in poll["services"] if s["name"] == "records-vault"), None)
    check("command center polls the vault live and sees it UP", bool(rv) and rv["up"] is True)
    check("the live health detail comes from the real vault",
          bool(rv) and isinstance(rv.get("detail"), dict) and rv["detail"].get("app") == "doc-archive")

    # evidence posture: the ingested pack verifies
    posture = httpx.get(f"{cc_base}/api/posture", cookies=cookies, timeout=10).json()
    check("evidence posture is all-verified", posture.get("all_verified") is True)
    metrics = {m["key"]: m["value"] for m in posture.get("metrics", [])}
    check("evidence metric records_preserved == 2", metrics.get("records_preserved") == 2)

    # the dashboard shows BOTH postures, as distinct sections
    page = httpx.get(f"{cc_base}/", cookies=cookies, timeout=10).text
    check("dashboard shows the Live service health section", "Live service health" in page)
    check("dashboard shows the Evidence integrity section", "Evidence integrity" in page)
    check("dashboard shows the live vault by name", "records-vault" in page)
    check("dashboard shows the vault as Live", "Live</span>" in page)

    print(f"\n=== CCC+RV E2E RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
