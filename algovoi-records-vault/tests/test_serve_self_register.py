"""Phase 2 acceptance: the Records Vault serve layer self-registers with the Command
Center on boot, and exposes a pollable /health — without touching the doc-archive base.

Stands up a stub Command Center (records POST /v1/services), points the vault at it via
CCC_HUB_*, fires the vault's FastAPI startup, and checks the registration arrived with
the right name/url/token and that /health answers 200.

Run: python tests/test_serve_self_register.py   (needs the [serve] + [dev] extras)
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
sys.path.insert(0, os.path.join(os.path.dirname(ROOT), "algovoi-doc-archive", "src"))

SVC_TOKEN = "rv-test-service-token"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


CCC_PORT = _free_port()
_WORK = tempfile.mkdtemp(prefix="rv-serve-")

os.environ["RV_ARCHIVE_DIR"] = _WORK
os.environ["CCC_HUB_URL"] = f"http://127.0.0.1:{CCC_PORT}"
os.environ["CCC_HUB_TOKEN"] = SVC_TOKEN
os.environ["CCC_HUB_NAME"] = "records-vault"
os.environ["CCC_HUB_SELF_URL"] = "http://records-vault:8000"

# doc-archive fail-closes on licence; stub it for the test
from algovoi_doc_archive import licensing as _dalic  # noqa: E402
_dalic.require_license = lambda *a, **k: {"test": True}

from fastapi.testclient import TestClient  # noqa: E402

from algovoi_records_vault import serve  # noqa: E402

PASS = FAIL = 0
RECEIVED: list[dict] = []


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


class _StubCCC(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        if self.path != "/v1/services":
            self.send_response(404)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n).decode() or "{}")
        RECEIVED.append({"auth": self.headers.get("Authorization", ""), "body": body})
        ok = self.headers.get("Authorization") == f"Bearer {SVC_TOKEN}"
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"registered": true}' if ok else b'{"error": "nope"}')

    def log_message(self, *a):
        pass


def main():
    threading.Thread(
        target=HTTPServer(("127.0.0.1", CCC_PORT), _StubCCC).serve_forever, daemon=True).start()
    time.sleep(0.2)

    # entering the TestClient context fires the FastAPI startup event -> self-register
    with TestClient(serve.app) as client:
        for _ in range(50):
            if RECEIVED:
                break
            time.sleep(0.05)
        h = client.get("/health")
        check("vault serves a pollable /health (200)", h.status_code == 200)
        check("/health reports the archive app", h.json().get("app") == "doc-archive")

    check("vault self-registered with the Command Center on boot", len(RECEIVED) == 1)
    if RECEIVED:
        reg = RECEIVED[0]
        check("registration carried the service token", reg["auth"] == f"Bearer {SVC_TOKEN}")
        check("registered under the configured name", reg["body"].get("name") == "records-vault")
        check("registered its self URL", reg["body"].get("base_url") == "http://records-vault:8000")
        check("registered the /health path", reg["body"].get("health_path") == "/health")
        check("registered as type records-vault", reg["body"].get("type") == "records-vault")

    # without the hub env, registration is a safe no-op
    for k in ("CCC_HUB_URL", "CCC_HUB_TOKEN", "CCC_HUB_NAME", "CCC_HUB_SELF_URL"):
        os.environ.pop(k, None)
    check("self-register is a no-op when unconfigured",
          serve.hub_client.register_from_env() is False)

    print(f"\n=== RV-SERVE RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
