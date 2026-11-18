#!/usr/bin/env bash
# Build the sealed Recovery Vault appliance image from a minimal context (the two local packages).
# Usage: IMAGE=algovoi-recovery-vault:0.1.0 ./seal/build.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"          # platform root
IMAGE="${IMAGE:-algovoi-recovery-vault:0.1.0}"
CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
cp -r "$ROOT/algovoi-doc-archive"      "$CTX/algovoi-doc-archive"
cp -r "$ROOT/algovoi-recovery-vault"   "$CTX/algovoi-recovery-vault"
# drop dev cruft + any local vault/key files from the build context
find "$CTX" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$CTX" \( -name '*.vault' -o -name '*.vault.tmp' -o -name '*.sk.b64' \) -delete 2>/dev/null || true
echo "building $IMAGE ..."
docker build -f "$CTX/algovoi-recovery-vault/Dockerfile" -t "$IMAGE" "$CTX"
echo "built $IMAGE"
