#!/usr/bin/env bash
# VM2 full reset: clear the records-vault test beds, refresh docker (SCOPED — never `system prune -a`,
# this is a shared box), then a from-scratch clean install + validate/smoke/e2e on a freshly-pulled
# vanilla python:3.11-slim with every dependency installed from PyPI. Touches ONLY the records-vault
# footprint; leaves all other containers/images on this host untouched.
set -u
RVB=/tmp/rvb-clean
MINIO=rv-minio-clean
RUNNER=python:3.11-slim

step(){ echo; echo "########## $1 ##########"; }
cleanup(){ docker rm -f "$MINIO" >/dev/null 2>&1; }
trap cleanup EXIT

step "0. HOST"
echo "host=$(hostname)  $(docker --version)"; df -h / | tail -1

step "1. CLEAR TEST BEDS (records-vault footprint only)"
docker ps -aq --filter name=rv-minio | xargs -r docker rm -f
docker ps -aq --filter name=rv-clean | xargs -r docker rm -f
docker rmi -f records-vault-test:py311 2>/dev/null
rm -rf /tmp/rvb /tmp/rvb-clean /tmp/rvbundle.tar.gz /tmp/rv-clean.tgz /tmp/vm2_run.sh \
       /opt/algovoi-build/rv-clean /opt/algovoi-build/records-vault
echo "cleared: tmp residue, rv-clean + records-vault staging, records-vault-test image, rv-* containers"

step "2. CLEAN DOCKER REFRESH (scoped: dangling images + build cache; re-pull bases)"
docker image prune -f
docker builder prune -f
docker pull -q "$RUNNER"
docker pull -q minio/minio:latest
echo "records-vault-test:py311 remaining = $(docker images -q records-vault-test:py311 | wc -l) (expect 0)"
echo "other host images preserved:"; docker images --format '  {{.Repository}}:{{.Tag}}' | grep -E 'sandbox|federation|zkp|twitter|atb|postgres|maturin' | head

step "3. CLEAN INSTALL + 4. VALIDATE / SMOKE / E2E (vanilla $RUNNER, all deps from PyPI)"
rm -rf "$RVB"; mkdir -p "$RVB"
tar -xzf /tmp/rvbundle-clean.tar.gz -C "$RVB" || { echo EXTRACT_FAIL; exit 2; }
echo "bundle wheels:"; ls "$RVB"/wheels
docker rm -f "$MINIO" >/dev/null 2>&1
echo "starting ephemeral MinIO (127.0.0.1:9000) ..."
docker run -d --rm --name "$MINIO" -p 127.0.0.1:9000:9000 minio/minio server /data >/dev/null || { echo MINIO_FAIL; exit 2; }
echo "running clean-install gauntlet in a fresh $RUNNER (no baked deps) ..."
docker run --rm --network host \
  -e MINIO_URL=http://127.0.0.1:9000 -e MINIO_USER=minioadmin -e MINIO_PASS=minioadmin \
  -v "$RVB":/work -w /work "$RUNNER" bash /work/clean_install_test.sh
RC=$?
echo "GAUNTLET EXIT: $RC"
exit $RC
