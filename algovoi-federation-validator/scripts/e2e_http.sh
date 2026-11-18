#!/bin/bash
# Full HTTP issue -> compose -> verify e2e for the Federation Validator.
#
# Topology (all over a docker network, real uvicorn HTTP, no in-process shortcuts):
#   - issuance step  : mints 2 real cross-issuer Phase-2 credentials
#   - federation-validator service : started with the issuers registered (secret bootstrapped)
#   - client container : POSTs the credentials to /compose, /verify, and a negative case
IMG=algovoi-federation-validator:clean
NET=fed-e2e-net
WORK=/root/fedval-e2e
VAL=fedval-e2e

cleanup() { docker rm -f "$VAL" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
cleanup
rm -rf "$WORK" && mkdir -p "$WORK" && chmod 777 "$WORK"
docker network create "$NET" >/dev/null

echo "STEP 1 - issuance side: mint 2 real cross-issuer Phase-2 credentials"
docker run --rm -v "$WORK":/out "$IMG" python scripts/acceptance.py --emit-e2e /out

echo "STEP 2 - start federation-validator service (secret bootstrapped, issuers registered)"
docker run -d --name "$VAL" --network "$NET" \
  -e FEDERATION_ISSUER_PKS="$(cat "$WORK"/issuer_pks.json)" \
  -e FEDERATION_MIN_CREDENTIALS=2 "$IMG" >/dev/null
H=""
for _ in $(seq 1 20); do
  H=$(docker exec "$VAL" curl -s http://localhost:8092/health 2>/dev/null || true)
  echo "$H" | grep -q '"status":"ok"' && break
  sleep 1
done
echo "  health: $H"

echo "STEP 3 - HTTP flow from a SEPARATE client container over the network"
RESULT=$(docker run --rm --network "$NET" -e VAL="$VAL" -v "$WORK":/in "$IMG" sh -c '
  set -e
  TOKEN=$(curl -s -X POST http://$VAL:8092/compose -H "Content-Type: application/json" --data @/in/compose.json | python -c "import sys,json;print(json.load(sys.stdin).get(\"token\") or \"\")")
  [ -n "$TOKEN" ] && echo COMPOSE_OK || echo COMPOSE_FAIL
  V=$(curl -s -X POST http://$VAL:8092/verify -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\"}" | python -c "import sys,json;print(json.load(sys.stdin).get(\"valid\"))")
  echo VERIFY=$V
  N=$(curl -s -X POST http://$VAL:8092/compose -H "Content-Type: application/json" --data @/in/compose_neg.json | python -c "import sys,json;d=json.load(sys.stdin);print(str(d.get(\"valid\"))+\" \"+str(d.get(\"failure_reason\")))")
  echo NEG=$N
')
echo "$RESULT" | sed "s/^/  /"

echo
echo "=== VERDICT ==="
echo "$RESULT" | grep -q "COMPOSE_OK" && echo "[PASS] /compose over HTTP issued a federation token" || echo "[FAIL] /compose"
echo "$RESULT" | grep -q "VERIFY=True" && echo "[PASS] /verify over HTTP confirmed the token" || echo "[FAIL] /verify"
echo "$RESULT" | grep -q "NEG=False" && echo "[PASS] lying credential rejected over HTTP (fail-closed)" || echo "[FAIL] negative"
cleanup
echo done
