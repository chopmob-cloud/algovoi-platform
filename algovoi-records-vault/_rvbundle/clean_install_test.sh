#!/usr/bin/env bash
# Runs INSIDE an ephemeral python:3.11-slim container. Clean-installs the wheels from PyPI + the
# bundled wheels, proves the import resolves to site-packages (not a src tree), then runs every suite
# against the INSTALLED package. Exits non-zero if any suite fails.
set -u
cd /work

echo "[*] python: $(python --version 2>&1)"
echo "[*] clean pip install from wheels (+ PyPI deps) ..."
pip install --quiet --no-input --no-cache-dir \
  "wheels/algovoi_doc_archive-0.1.1-py3-none-any.whl[serve]" \
  "wheels/algovoi_doc_archive_s3-0.1.0-py3-none-any.whl" \
  "wheels/algovoi_records_vault-0.5.0-py3-none-any.whl[serve]" \
  "wheels/algovoi_command_center-0.3.0-py3-none-any.whl" \
  uvicorn httpx python-multipart
if [ $? -ne 0 ]; then echo "PIP_INSTALL_FAILED"; exit 2; fi

RVPATH=$(python -c "import algovoi_records_vault as r,os;print(os.path.dirname(r.__file__))")
echo "[*] records-vault import path: $RVPATH"
case "$RVPATH" in
  *site-packages*) echo "[*] confirmed clean-installed (site-packages), not a src tree" ;;
  *) echo "NOT_CLEAN_INSTALL: $RVPATH"; exit 3 ;;
esac
python -c "import algovoi_records_vault as r;print('[*] records-vault version', r.__version__)"
python -c "import algovoi_command_center as cc;print('[*] command-center version', cc.__version__)"
python -c "import algovoi_doc_archive_s3, boto3, uvicorn, httpx;print('[*] deps import OK')" || { echo DEP_IMPORT_FAILED; exit 4; }

# optional MinIO readiness wait (the live S3 leg)
if [ -n "${MINIO_URL:-}" ]; then
  echo "[*] waiting for MinIO at $MINIO_URL ..."
  python - <<PYWAIT
import os, time, urllib.request
url = os.environ["MINIO_URL"].rstrip("/") + "/minio/health/ready"
for _ in range(60):
    try:
        urllib.request.urlopen(url, timeout=2); print("[*] MinIO ready"); break
    except Exception:
        time.sleep(1)
else:
    print("[!] MinIO not ready after 60s (s3 leg may fail)")
PYWAIT
fi

SUITES="test_migrate_e2e test_live_deploy test_vault_facade test_sources test_vault_stream test_timestamp test_access_log test_legal_hold test_phase1_e2e test_gdpr_bridge test_keyring test_consent test_custody test_editions test_acl test_redaction test_serve_self_register test_service_bridge test_ccc_rv_e2e"
if [ -n "${MINIO_URL:-}" ]; then SUITES="$SUITES test_live_s3_minio"; else echo "[*] MINIO_URL unset -> SKIP test_live_s3_minio"; fi

GP=0; GF=0; NS=0; FAILS=""
for s in $SUITES; do
  echo "================= $s ================="
  out=$(python "tests/$s.py" 2>&1); rc=$?
  echo "$out"
  line=$(echo "$out" | grep -oE "[0-9]+ passed, [0-9]+ failed" | tail -1)
  p=$(echo "$line" | grep -oE "^[0-9]+")
  f=$(echo "$line" | grep -oE "[0-9]+ failed" | grep -oE "^[0-9]+")
  p=${p:-0}; f=${f:-0}
  GP=$((GP + p)); GF=$((GF + f)); NS=$((NS + 1))
  if [ "$rc" != "0" ] || [ "$f" != "0" ]; then FAILS="$FAILS $s(rc=$rc,fail=$f)"; fi
done

echo "########################################"
echo "CLEAN-INSTALL GAUNTLET TOTAL: $GP passed, $GF failed across $NS suites"
if [ -n "$FAILS" ]; then echo "FAILED_SUITES:$FAILS"; exit 1; fi
echo "ALL_GREEN"
