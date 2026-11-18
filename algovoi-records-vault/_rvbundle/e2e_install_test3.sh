#!/usr/bin/env bash
# Runs ON VM1. Fresh token (deployment_limit=3) + a full buyer-style `pip install` on a container with
# BOTH the internal private index and PyPI egress. Confirms the earlier 403 was just the limit=1 cap.
set -u
cd /opt/algovoi
C=rv-e2e3-$$
cleanup(){ docker rm -f "$C" >/dev/null 2>&1; }
trap cleanup EXIT

TOKEN=$(grep -E '^SUITE_FULFILMENT_TOKEN=' .env | head -1 | cut -d= -f2-)
TOKEN="${TOKEN%\"}"; TOKEN="${TOKEN#\"}"; TOKEN="${TOKEN%\'}"; TOKEN="${TOKEN#\'}"
[ -n "$TOKEN" ] || { echo NO_FULFILMENT_TOKEN; exit 2; }
NET=$(docker network ls --format '{{.Name}}' | grep -i internal | head -1)

MINT=$(docker run --rm --network "$NET" curlimages/curl:8.10.1 -s -X POST http://fulfilment:8088/v1/fulfill \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package":"algovoi-records-vault","licensee":"e2e-test@algovoi.local","order_ref":"e2e-records-vault-fullinstall","tier":"starter","deployment_limit":3,"ttl_secs":3600}')
IDX=$(echo "$MINT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('index_token',''))" 2>/dev/null)
[ -n "$IDX" ] || { echo "MINT_FAILED: $(echo "$MINT" | head -c 200)"; exit 3; }
echo "[*] fresh token (limit=3), length ${#IDX}"
SIMPLE="http://$IDX:@package-index:8089/simple/"

echo "[*] full buyer install: index + PyPI ..."
docker run -d --network "$NET" --name "$C" python:3.11-slim sleep 600 >/dev/null
docker network connect bridge "$C" 2>/dev/null
docker exec "$C" sh -c "
  pip install --no-cache-dir --index-url $SIMPLE --trusted-host package-index --extra-index-url https://pypi.org/simple/ algovoi-records-vault \
  && python -c 'import algovoi_records_vault as r; print(\"  installed records-vault\", r.__version__)' \
  && python -c 'import algovoi_doc_archive; print(\"  private dep algovoi-doc-archive resolved through the index\")' \
  && python -c 'import pqcrypto, rfc8785; print(\"  public deps resolved from PyPI\")' \
  && echo END_TO_END_OK
"
echo "[*] full-install exit: $?"
