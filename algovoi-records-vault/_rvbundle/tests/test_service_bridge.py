"""Acceptance test for the Command Center live service bridge (Phase 1).

Runs the REAL Command Center over a real socket, plus a tiny health stub standing in
for a product (e.g. Records Vault), and exercises the whole bridge end to end:

  hub_client self-register -> POST /v1/services -> store -> on-demand /health poll
  -> /api/services -> dashboard "Live service health" panel -> signed console audit.

It proves the two postures stay distinct (live health vs evidence integrity), the
service token gates registration, unreachable products read as Down (not an error),
removal works, and every registration is appended to the offline-verifiable audit chain.

Run: python tests/test_service_bridge.py   (needs pqcrypto + rfc8785 + httpx + uvicorn)
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

SVC_TOKEN = "test-service-token-123"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


CCC_PORT = _free_port()
HEALTH_PORT = _free_port()
DOWN_PORT = _free_port()  # never bound -> simulates an unreachable product

# Configure the console before importing it: temp DB + data dir, fixed token + session secret.
_WORK = tempfile.mkdtemp(prefix="cc-bridge-")
os.environ["COMMAND_CENTER_DB"] = "sqlite:///" + os.path.join(_WORK, "cc.db")
os.environ["COMMAND_CENTER_DATA_DIR"] = _WORK
os.environ["COMMAND_CENTER_KEY_FILE"] = os.path.join(_WORK, "key.json")
os.environ["COMMAND_CENTER_SERVICE_TOKEN"] = SVC_TOKEN
os.environ["COMMAND_CENTER_SECRET"] = "fixed-test-secret-for-session-hmac"

from algovoi_command_center import licensing as _lic  # noqa: E402
_lic.require_license = lambda: {"test": True}

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from pqcrypto.sign.falcon_1024 import generate_keypair  # noqa: E402

from algovoi_command_center import hub_client, roles  # noqa: E402
from algovoi_command_center.app import create_app  # noqa: E402
from algovoi_command_center.audit import LocalSigner  # noqa: E402
from algovoi_command_center.auth import make_session  # noqa: E402

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            body = json.dumps({"status": "ok", "app": "records-vault-sim"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # silence
        pass


def _serve_health():
    HTTPServer(("127.0.0.1", HEALTH_PORT), _HealthHandler).serve_forever()


def main():
    base = f"http://127.0.0.1:{CCC_PORT}"
    rv_url = f"http://127.0.0.1:{HEALTH_PORT}"
    down_url = f"http://127.0.0.1:{DOWN_PORT}"

    # 1. the product's health stub
    threading.Thread(target=_serve_health, daemon=True).start()

    # 2. the REAL command center over a real socket (our own signer, so audit verifies)
    pk, sk = generate_keypair()
    app = create_app(signer=LocalSigner(pk, sk))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=CCC_PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()

    ready = False
    for _ in range(60):
        try:
            if httpx.get(f"{base}/health", timeout=1).status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.2)
    check("command center comes up live (GET /health 200)", ready)

    # admin session cookie (same process -> same COMMAND_CENTER_SECRET as the server)
    cookies = {"cc_session": make_session("admin", roles.ADMIN)}

    # 3. a product self-registers via the shipped hub_client (real POST /v1/services)
    ok = hub_client.register(hub_url=base, token=SVC_TOKEN, name="records-vault",
                             self_url=rv_url, health_path="/health")
    check("hub_client self-registers the product", ok is True)

    # an unreachable product also registers fine (health is polled separately)
    ok_down = hub_client.register(hub_url=base, token=SVC_TOKEN, name="down-svc", self_url=down_url)
    check("a second (unreachable) product registers", ok_down is True)

    # 4. the service token gates registration
    bad = httpx.post(f"{base}/v1/services",
                     json={"name": "rogue", "base_url": rv_url}, timeout=5)
    check("registration without the token is rejected (401)", bad.status_code == 401)
    bad2 = httpx.post(f"{base}/v1/services", headers={"Authorization": "Bearer wrong"},
                      json={"name": "rogue", "base_url": rv_url}, timeout=5)
    check("registration with a wrong token is rejected (401)", bad2.status_code == 401)

    # 5. the registry lists both products (open, read-only)
    listed = httpx.get(f"{base}/v1/services", timeout=5).json()["services"]
    names = {s["name"] for s in listed}
    check("registry lists both products", {"records-vault", "down-svc"} <= names)
    check("rogue product was never registered", "rogue" not in names)

    # 6. on-demand live poll: reachable -> up, unreachable -> down (not an error)
    poll = httpx.get(f"{base}/api/services", cookies=cookies, timeout=10).json()
    by_name = {s["name"]: s for s in poll["services"]}
    check("records-vault polls UP", by_name["records-vault"]["up"] is True)
    check("down-svc polls DOWN", by_name["down-svc"]["up"] is False)
    check("not all services up", poll["all_up"] is False)
    check("/api/services needs a session (401 without cookie)",
          httpx.get(f"{base}/api/services", timeout=5).status_code == 401)

    # 7. dashboard keeps the two postures as distinct, labelled sections
    page = httpx.get(f"{base}/", cookies=cookies, timeout=10).text
    check("dashboard shows the Live service health section", "Live service health" in page)
    check("dashboard still shows the Evidence integrity section", "Evidence integrity" in page)
    check("dashboard lists the live product", "records-vault" in page)

    # 8. every registration is on the signed, offline-verifiable console audit chain
    audit_page = httpx.get(f"{base}/audit", cookies=cookies, timeout=5).text
    check("audit chain records service_register", "service_register" in audit_page)
    check("audit chain still verifies", "audit chain verified" in audit_page)

    # 9. removal works, and only with the token
    no_tok = httpx.delete(f"{base}/v1/services/down-svc", timeout=5)
    check("removal without the token is rejected (401)", no_tok.status_code == 401)
    gone = httpx.delete(f"{base}/v1/services/down-svc",
                        headers={"Authorization": f"Bearer {SVC_TOKEN}"}, timeout=5)
    check("removal with the token succeeds (200)", gone.status_code == 200)
    after = {s["name"] for s in httpx.get(f"{base}/v1/services", timeout=5).json()["services"]}
    check("removed product is gone from the registry", "down-svc" not in after)
    missing = httpx.delete(f"{base}/v1/services/nope",
                           headers={"Authorization": f"Bearer {SVC_TOKEN}"}, timeout=5)
    check("removing an unknown product is 404", missing.status_code == 404)

    # 10. hub_client is safe to call unconfigured (boot-time no-op)
    for k in ("CCC_HUB_URL", "CCC_HUB_TOKEN", "CCC_HUB_NAME", "CCC_HUB_SELF_URL"):
        os.environ.pop(k, None)
    check("hub_client.register_from_env() is a no-op when unconfigured",
          hub_client.register_from_env() is False)

    print(f"\n=== SERVICE-BRIDGE RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
