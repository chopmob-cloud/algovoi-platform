"""Serve-bind security test (standalone, runnable): the console entrypoint must default to loopback
and refuse a non-loopback (public) bind without RV_ARCHIVE_TOKEN.

Run: python tests/test_serve_bind.py   (needs fastapi, uvicorn, and the doc-archive sibling)
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda *a, **k: {"test": True}
from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda *a, **k: {"test": True}

import uvicorn  # noqa: E402
from algovoi_records_vault import serve  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


def _run_main():
    captured = {}
    uvicorn.run = lambda *a, **k: captured.update(k)  # never actually start a server
    serve.main()
    return captured


def main():
    for k in ("RV_SERVE_HOST", "RV_ARCHIVE_TOKEN"):
        os.environ.pop(k, None)

    # 1. default bind is loopback
    cap = _run_main()
    check("default host is loopback", cap.get("host") == "127.0.0.1")

    # 2. public bind without a token is refused
    os.environ["RV_SERVE_HOST"] = "0.0.0.0"
    os.environ.pop("RV_ARCHIVE_TOKEN", None)
    refused = False
    try:
        _run_main()
    except RuntimeError as exc:
        refused = "non-loopback" in str(exc)
    check("public bind without token refused", refused)

    # 3. public bind WITH a token is allowed
    os.environ["RV_ARCHIVE_TOKEN"] = "rv-token-explicit"
    cap = _run_main()
    check("public bind with token allowed", cap.get("host") == "0.0.0.0")

    print(f"=== SERVE-BIND RESULT: {PASS} passed, {FAIL} failed ===")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
