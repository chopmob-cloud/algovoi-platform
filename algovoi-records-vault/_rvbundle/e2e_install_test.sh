#!/usr/bin/env bash
# Runs ON VM1. Proves purchase->download end to end: mint a real entitlement token for
# algovoi-records-vault via the fulfilment service, then token-gated `pip install` through the private
# index in a throwaway container — confirming the package AND its entitled deps resolve. Mints ONE test
# licence (licensee e2e-test@algovoi.local, ttl 1h) as a deliberate side effect.
set -u
cd /opt/algovoi

TOKEN=$(grep -E '^SUITE_FULFILMENT_TOKEN=' .env | head -1 | cut -d= -f2-)
TOKEN="${TOKEN%\"}"; TOKEN="${TOKEN#\"}"; TOKEN="${TOKEN%\'}"; TOKEN="${TOKEN#\'}"
[ -n "$TOKEN" ] || { echo NO_FULFILMENT_TOKEN; exit 2; }
NET=$(docker network ls --format '{{.Name}}' | grep -i internal | head -1)
echo "[*] internal network: $NET"

echo "[*] minting entitlement token for algovoi-records-vault ..."
MINT=$(docker run --rm --network "$NET" curlimages/curl:8.10.1 -s -X POST http://fulfilment:8088/v1/fulfill \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"package":"algovoi-records-vault","licensee":"e2e-test@algovoi.local","order_ref":"e2e-records-vault-verify","tier":"starter","deployment_limit":1,"ttl_secs":3600}')
INDEX_TOKEN=$(echo "$MINT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('index_token',''))" 2>/dev/null)
[ -n "$INDEX_TOKEN" ] || { echo "MINT_FAILED: $(echo "$MINT" | head -c 200)"; exit 3; }
echo "[*] minted index_token (length ${#INDEX_TOKEN})"

echo "[*] token-gated pip install in a fresh python:3.11-slim ..."
docker run --rm --network "$NET" python:3.11-slim bash -c "
  set -e
  IDX=http://$INDEX_TOKEN:@package-index:8089/simple/
  echo '--- pip install algovoi-records-vault (the purchased package) ---'
  pip install --quiet --no-cache-dir --index-url \$IDX --trusted-host package-index --extra-index-url https://pypi.org/simple/ algovoi-records-vault
  python -c 'import algovoi_records_vault as r; print(\"  installed records-vault\", r.__version__)'
  python -c 'import algovoi_doc_archive; print(\"  private dep algovoi-doc-archive resolved through the index\")'
  echo '--- same token installs the rest of the stack (bundle entitlement via _SUITE_DEPS) ---'
  pip install --quiet --no-cache-dir --index-url \$IDX --trusted-host package-index --extra-index-url https://pypi.org/simple/ algovoi-doc-archive-s3 algovoi-archive-auditor
  python -c 'import algovoi_doc_archive_s3, algovoi_archive_auditor; print(\"  s3 + auditor installed via the SAME token\")'
  echo 'END_TO_END_OK'
"
echo "[*] e2e exit: $?"
