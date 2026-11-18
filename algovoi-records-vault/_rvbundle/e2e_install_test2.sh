#!/usr/bin/env bash
# Runs ON VM1. Proves purchase->download end to end. Mints a real entitlement token for
# algovoi-records-vault, then:
#   PROOF A: token-gated `pip download` of the whole private stack from the index (no internet) —
#            the definitive "the token resolves + serves the purchased package and its entitled deps".
#   PROOF B: a full buyer-style `pip install` in a container with BOTH the internal index and PyPI.
set -u
cd /opt/algovoi
C=rv-e2e-$$
cleanup(){ docker rm -f "$C" >/dev/null 2>&1; }
trap cleanup EXIT

TOKEN=$(grep -E '^SUITE_FULFILMENT_TOKEN=' .env | head -1 | cut -d= -f2-)
TOKEN="${TOKEN%\"}"; TOKEN="${TOKEN#\"}"; TOKEN="${TOKEN%\'}"; TOKEN="${TOKEN#\'}"
[ -n "$TOKEN" ] || { echo NO_FULFILMENT_TOKEN; exit 2; }
NET=$(docker network ls --format '{{.Name}}' | grep -i internal | head -1)
echo "[*] internal network: $NET"

echo "[*] minting entitlement token for algovoi-records-vault ..."
MINT=$(docker run --rm --network "$NET" curlimages/curl:8.10.1 -s -X POST http://fulfilment:8088/v1/fulfill \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package":"algovoi-records-vault","licensee":"e2e-test@algovoi.local","order_ref":"e2e-records-vault-verify","tier":"starter","deployment_limit":1,"ttl_secs":3600}')
IDX=$(echo "$MINT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('index_token',''))" 2>/dev/null)
[ -n "$IDX" ] || { echo "MINT_FAILED: $(echo "$MINT" | head -c 200)"; exit 3; }
echo "[*] minted index_token (length ${#IDX})"
SIMPLE="http://$IDX:@package-index:8089/simple/"

echo
echo "===== PROOF A: token-gated download of the private stack from the index (no PyPI) ====="
docker run --rm --network "$NET" python:3.11-slim sh -c "
  pip download --no-deps --no-cache-dir --index-url $SIMPLE --trusted-host package-index -d /tmp/dl \
    algovoi-records-vault algovoi-doc-archive algovoi-doc-archive-s3 algovoi-archive-auditor \
  && echo '--- wheels served by the token-gated index: ---' && ls -1 /tmp/dl
"
echo "[*] PROOF A exit: $?"

echo
echo "===== PROOF B: full buyer install (private index + PyPI for public deps) ====="
docker run -d --network "$NET" --name "$C" python:3.11-slim sleep 600 >/dev/null
docker network connect bridge "$C" 2>/dev/null
docker exec "$C" sh -c "
  pip install --no-cache-dir --index-url $SIMPLE --trusted-host package-index --extra-index-url https://pypi.org/simple/ algovoi-records-vault \
  && python -c 'import algovoi_records_vault as r; print(\"  installed records-vault\", r.__version__)' \
  && python -c 'import algovoi_doc_archive; print(\"  private dep algovoi-doc-archive resolved through the index\")' \
  && echo END_TO_END_OK
"
echo "[*] PROOF B exit: $?"
