#!/usr/bin/env bash
# Runs ON VM2 (the clean box). Refreshes the existing /opt/algovoi-build/rv-clean staging with the
# 0.2.0 wheel + the 5 new Phase-1 suites, regenerates the in-container clean_install_test.sh, then
# runs the proven gauntlet inside records-vault-test:py311 with an ephemeral MinIO. Reuses the baked
# image + proven MinIO recipe — no fresh infra.
set -u
RVB=/tmp/rvb
CLEAN=/opt/algovoi-build/rv-clean
MINIO=rv-minio-gauntlet

cleanup(){ docker stop "$MINIO" >/dev/null 2>&1; }
trap cleanup EXIT

echo "[*] host: $(hostname)"
rm -rf "$RVB"; mkdir -p "$RVB"
tar -xzf /tmp/rvbundle.tar.gz -C "$RVB" || { echo EXTRACT_FAIL; exit 2; }

echo "[*] refreshing clean-install staging (0.2.0 wheel + all suites) ..."
rm -f "$CLEAN"/dist/algovoi_records_vault-*.whl
cp "$RVB"/wheels/algovoi_records_vault-0.2.0-py3-none-any.whl "$CLEAN"/dist/
cp "$RVB"/tests/test_migrate_e2e.py "$RVB"/tests/test_live_deploy.py \
   "$RVB"/tests/test_vault_facade.py "$RVB"/tests/test_sources.py \
   "$RVB"/tests/test_live_s3_minio.py "$RVB"/tests/test_vault_stream.py \
   "$RVB"/tests/test_timestamp.py "$RVB"/tests/test_access_log.py \
   "$RVB"/tests/test_legal_hold.py "$RVB"/tests/test_phase1_e2e.py "$CLEAN"/tests/
echo "[*] dist:"; ls "$CLEAN"/dist
echo "[*] tests:"; ls "$CLEAN"/tests | tr '\n' ' '; echo

cat > "$CLEAN"/clean_install_test.sh <<'CIS'
#!/bin/bash
set -u
echo "=== SMOKE: install from wheels (no source tree present) ==="
pip install -q /clean/dist/algovoi_doc_archive-0.1.0-py3-none-any.whl /clean/dist/algovoi_records_vault-0.2.0-py3-none-any.whl || { echo PIP_FAIL; exit 2; }
python - <<'PY'
import algovoi_records_vault as rv, inspect
assert "site-packages" in inspect.getfile(rv), inspect.getfile(rv)
print("SMOKE OK: records-vault", rv.__version__, "from", inspect.getfile(rv))
print("SMOKE OK: exports", len(rv.__all__), "names; has", [n for n in ("Timestamper","AccessLog","LegalHoldRegistry","RetentionPolicy","verify_stream") if hasattr(rv,n)])
PY
if [ -n "${MINIO_URL:-}" ]; then
  python - <<'PY'
import os,time,urllib.request
u=os.environ["MINIO_URL"].rstrip("/")+"/minio/health/ready"
for _ in range(60):
    try: urllib.request.urlopen(u,timeout=2); print("MinIO ready"); break
    except Exception: time.sleep(1)
else: print("MinIO not ready after 60s")
PY
fi
echo "=== SUITES against the installed package ==="
SUITES="test_migrate_e2e test_live_deploy test_vault_facade test_sources test_vault_stream test_timestamp test_access_log test_legal_hold test_phase1_e2e test_live_s3_minio"
GP=0; GF=0; FAILS=""
for t in $SUITES; do
  out=$(python "/clean/tests/${t}.py" 2>&1); rc=$?
  line=$(echo "$out" | grep -oE "[0-9]+ passed, [0-9]+ failed" | tail -1)
  echo "  $t -> ${line:-(no result line / skipped)} [rc=$rc]"
  p=$(echo "$line" | grep -oE "^[0-9]+"); f=$(echo "$line" | grep -oE "[0-9]+ failed" | grep -oE "^[0-9]+")
  p=${p:-0}; f=${f:-0}; GP=$((GP+p)); GF=$((GF+f))
  if [ "$rc" != "0" ] || [ "$f" != "0" ]; then FAILS="$FAILS $t"; fi
done
echo "########################################"
echo "CLEAN-INSTALL TOTAL: $GP passed, $GF failed"
if [ -n "$FAILS" ]; then echo "FAILED:$FAILS"; exit 1; fi
echo "ALL_GREEN"
CIS
chmod +x "$CLEAN"/clean_install_test.sh

docker rm -f "$MINIO" >/dev/null 2>&1
echo "[*] starting ephemeral MinIO (127.0.0.1:9000) ..."
docker run -d --rm --name "$MINIO" -p 127.0.0.1:9000:9000 minio/minio server /data >/dev/null || { echo MINIO_FAIL; exit 2; }

echo "[*] running gauntlet in records-vault-test:py311 (--network host, MINIO_URL set) ..."
docker run --rm --network host \
  -e MINIO_URL=http://127.0.0.1:9000 -e MINIO_USER=minioadmin -e MINIO_PASS=minioadmin \
  -v "$CLEAN":/clean records-vault-test:py311 bash /clean/clean_install_test.sh
RC=$?
echo "[*] gauntlet exit: $RC"
exit $RC
