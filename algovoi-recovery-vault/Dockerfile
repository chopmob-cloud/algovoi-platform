# Sealed Recovery Vault appliance.
#
# Build context = platform root:   docker build -f algovoi-recovery-vault/Dockerfile -t algovoi-recovery-vault .
#
# BUILD PREREQUISITE: recovery-vault depends on substrate2, which is NOT on public PyPI. Place the
# substrate2 wheel in a `vendor/` dir at the build-context root before building, e.g.:
#     mkdir -p vendor && cp /path/to/substrate2-*-py3-none-any.whl vendor/
# The install below resolves substrate2 from there (--find-links) and the rest from PyPI.
#
# The crypto + custody modules are Nuitka-compiled to native .so and their .py sources are removed,
# so the running image contains no readable source for the sensitive logic. The thin service/runner
# stays as bytecode. Not unbreakable, but raises the bar from "open the file" to "reverse a binary".

# ---- builder: install, compile sensitive modules, strip sources -------------------------------
FROM python:3.11-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential patchelf ccache && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "nuitka>=2.0"

WORKDIR /build
COPY algovoi-doc-archive /build/algovoi-doc-archive
COPY algovoi-recovery-vault /build/algovoi-recovery-vault
COPY vendor /build/vendor
RUN pip install --no-cache-dir --pre --find-links /build/vendor substrate2 \
 && pip install --no-cache-dir --find-links /build/vendor ./algovoi-doc-archive ./algovoi-recovery-vault

# Compile each sensitive module to a native extension in place, then delete its .py/.pyc.
ENV SEAL="algovoi_doc_archive/signing.py \
          algovoi_doc_archive/encryption.py \
          algovoi_doc_archive/recovery.py \
          algovoi_recovery_vault/vault.py"
RUN set -eux; \
    SITE=/usr/local/lib/python3.11/site-packages; \
    WORK=/tmp/seal; \
    mkdir -p "$WORK"; \
    for rel in $SEAL; do \
        pkgdir="$SITE/$(dirname "$rel")"; \
        base="$(basename "$rel")"; \
        mod="${base%.py}"; \
        cp "$pkgdir/$base" "$WORK/$base"; \
        ( cd "$WORK" && python -m nuitka --module "$base" --output-dir="$WORK" --remove-output --quiet ); \
        cp "$WORK/$mod".*.so "$pkgdir/"; \
        rm -f "$pkgdir/$base" "$pkgdir/${base}c" "$WORK/$base"; \
    done; \
    find "$SITE" -depth -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true; \
    rm -rf "$WORK"; \
    for rel in $SEAL; do \
        test ! -f "$SITE/$rel" || { echo "SOURCE STILL PRESENT: $rel" >&2; exit 1; }; \
        ls "$SITE/$(dirname "$rel")/$(basename "${rel%.py}")".*.so >/dev/null; \
    done; \
    python -c "import algovoi_recovery_vault.vault, algovoi_doc_archive.recovery; print('compiled modules import OK')"

# ---- runtime: only the (sealed) site-packages + a non-root user ------------------------------
FROM python:3.11-slim AS runtime
RUN useradd -r -u 10001 -m vault
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn

ENV VAULT_PATH=/data/recovery.vault \
    VAULT_BIND=127.0.0.1 \
    VAULT_PORT=8077 \
    PYTHONDONTWRITEBYTECODE=1
RUN mkdir -p /data && chown vault:vault /data
VOLUME ["/data"]
USER vault
EXPOSE 8077
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"VAULT_PORT\"]}/healthz')"
# VAULT_UNLOCK_SECRET and VAULT_API_TOKEN must be supplied at run time (KMS/secret manager) — never baked.
CMD ["python", "-m", "algovoi_recovery_vault.service"]
