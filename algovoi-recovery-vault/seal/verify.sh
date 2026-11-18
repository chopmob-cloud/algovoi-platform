#!/usr/bin/env bash
# Verify the sealed appliance: (1) sensitive sources absent + native modules present;
# (2) the API serves a full generate -> split -> recover flow end to end.
# Uses the REAL baked AlgoVoi support recovery key (no env needed).
set -euo pipefail
IMAGE="${IMAGE:-algovoi-recovery-vault:0.1.0}"
NAME="rv-verify-$$"
PORT="${PORT:-18077}"

echo "== seal check: sensitive sources must be GONE, native .so present =="
docker run --rm "$IMAGE" sh -c '
  S=/usr/local/lib/python3.11/site-packages
  for f in algovoi_doc_archive/signing algovoi_doc_archive/encryption algovoi_doc_archive/recovery algovoi_recovery_vault/vault; do
    if [ -f "$S/$f.py" ]; then echo "LEAK: $f.py present"; exit 1; fi
    ls "$S/$f".*.so >/dev/null 2>&1 || { echo "MISSING native module: $f"; exit 1; }
  done
  echo "seal OK: sensitive sources absent, native modules present"
'

echo "== API e2e =="
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "${PORT}:8077" \
  -e VAULT_UNLOCK_SECRET=verify-secret -e VAULT_API_TOKEN=verify-token "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break; sleep 1; done

AUTH="Authorization: Bearer verify-token"
B="http://127.0.0.1:${PORT}"
curl -fsS -H "$AUTH" -X POST "$B/v1/archives" -H 'content-type: application/json' -d '{"name":"primary"}' >/dev/null
SPLIT=$(curl -fsS -H "$AUTH" -X POST "$B/v1/archives/primary/split" -H 'content-type: application/json' -d '{"threshold_k":2,"total_n":3}')
python3 - "$B" "$SPLIT" <<'PY'
import json, sys, urllib.request
base, split = sys.argv[1], json.loads(sys.argv[2])
assert split["envelope"]["support_assisted"] is True, "expected baked AlgoVoi share"
shares = split["shares"]; assert len(shares) == 2, shares
req = urllib.request.Request(base + "/v1/archives/primary/recover",
    data=json.dumps({"shares": shares}).encode(),
    headers={"content-type":"application/json","authorization":"Bearer verify-token"})
out = json.loads(urllib.request.urlopen(req).read())
assert out.get("recovered") is True, out
print("API e2e OK: generate -> split(2of3,+AlgoVoi) -> recover -> recovered=True")
PY
echo "SEALED APPLIANCE VERIFIED"
