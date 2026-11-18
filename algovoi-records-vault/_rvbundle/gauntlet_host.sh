#!/usr/bin/env bash
# Runs ON the ilcdocker host. Spins up a FULLY ISOLATED throwaway environment — a dedicated docker
# network + an ephemeral MinIO + an ephemeral python:3.11-slim runner — runs the clean-install
# gauntlet, then tears everything down. Touches NO production container, network, or volume.
set -u
BUNDLE=/tmp/rvbundle
NET=rv-net-$$
MINIO=rv-minio-$$

cleanup() {
  echo "[*] cleanup ..."
  docker stop "$MINIO" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

echo "[*] host: $(hostname)  docker: $(docker --version)"
echo "[*] pulling base images (idempotent) ..."
docker pull -q python:3.11-slim || { echo IMG_PULL_FAILED; exit 2; }
docker pull -q minio/minio     || { echo MINIO_PULL_FAILED; exit 2; }

echo "[*] creating isolated network $NET ..."
docker network create "$NET" >/dev/null || { echo NET_CREATE_FAILED; exit 2; }

echo "[*] starting ephemeral MinIO ($MINIO) on $NET ..."
docker run -d --rm --name "$MINIO" --network "$NET" \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data >/dev/null || { echo MINIO_RUN_FAILED; exit 2; }

# reach MinIO by container IP (an IP endpoint -> boto3 uses path-style addressing, MinIO-compatible)
MINIO_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$MINIO")
echo "[*] MinIO container IP: $MINIO_IP"

echo "[*] running clean-install gauntlet in ephemeral python:3.11-slim ..."
docker run --rm --network "$NET" \
  -e MINIO_URL="http://$MINIO_IP:9000" \
  -e MINIO_USER=minioadmin -e MINIO_PASS=minioadmin \
  -v "$BUNDLE:/work" -w /work \
  python:3.11-slim bash /work/clean_install_test.sh
RC=$?
echo "[*] gauntlet exit code: $RC"
exit $RC
