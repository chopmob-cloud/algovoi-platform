#!/bin/bash
set -euo pipefail
# Live bridge proof: the lean substrate-2 control plane coordinating the ACTUAL
# running federation-validator + zkp-receipt services over a docker network.
CP=algovoi-substrate2-controlplane:clean
FED=algovoi-federation-validator:clean
ZKP=algovoi-zkp-receipt:clean
NET=s2-bridge

cleanup() { for c in s2cp federation-validator zkp-receipt; do docker rm -f "$c" >/dev/null 2>&1; done; docker network rm "$NET" >/dev/null 2>&1; }
cleanup
docker network create "$NET" >/dev/null

echo "STEP 1 - start the lean CP + the two substrate-2 services on one network (all bootstrap clean)"
docker run -d --name s2cp --network "$NET" "$CP" >/dev/null
docker run -d --name federation-validator --network "$NET" -e FEDERATION_ISSUER_PKS='{}' "$FED" >/dev/null
docker run -d --name zkp-receipt --network "$NET" "$ZKP" >/dev/null
sleep 8
TOKEN=$(docker exec s2cp cat /app/data/admin_token)

echo "STEP 2 - register an issuer in the trust hub + bridge the two running services"
PK=$(docker exec s2cp python -c "import os,base64;print(base64.b64encode(os.urandom(1793)).decode())")
docker exec s2cp curl -s -X POST localhost:8094/v1/issuers -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"did\":\"did:web:bridge-issuer\",\"public_key_b64\":\"$PK\"}" >/dev/null
docker exec s2cp curl -s -X POST localhost:8094/v1/services -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"federation-validator","type":"federation","base_url":"http://federation-validator:8092"}' >/dev/null
docker exec s2cp curl -s -X POST localhost:8094/v1/services -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"zkp-receipt","type":"zkp-receipt","base_url":"http://zkp-receipt:8093"}' >/dev/null

echo "STEP 3 - federation-validator pulls its trust set from the CP hub (the bridge in action)"
echo -n "  federation can read CP /v1/issuer-pks: "
docker exec federation-validator sh -c 'curl -s http://s2cp:8094/v1/issuer-pks' 2>/dev/null | head -c 120; echo

echo "STEP 4 - CP posture: polls the real /health of both bridged services"
POSTURE=$(docker exec s2cp sh -c "curl -s -H 'Authorization: Bearer $TOKEN' localhost:8094/v1/posture")
echo "$POSTURE" | python3 -m json.tool 2>/dev/null || echo "$POSTURE"

echo
echo "=== VERDICT ==="
if ! echo "$POSTURE" | grep -q '"all_up": true'; then
  echo "[FAIL] CP bridges both running services, posture not all_up" >&2
  cleanup
  exit 1
fi
echo "[PASS] CP bridges both running services, posture all_up"
cleanup
echo done
