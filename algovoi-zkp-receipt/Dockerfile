# ZKP Receipt Service
# Stateless FastAPI microservice — ZKP-bound payment receipt attestation.
#
# POST /build   — construct unsigned ZKP receipt payload
# POST /verify  — verify a signed ZKP receipt envelope
# GET  /health  — liveness probe
#
# Build context: algovoi-zkp-receipt/ (not the monorepo root)
# docker build -t algovoi-zkp-receipt:0.1.0 .

FROM python:3.11-slim

LABEL org.opencontainers.image.title="AlgoVoi ZKP Receipt"
LABEL org.opencontainers.image.description="ZKP-bound payment receipt attestation. IETF: draft-hopley-x402-pqc-credential-binding-00"
LABEL org.opencontainers.image.vendor="AlgoVoi"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="0.1.0"

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md CHANGELOG.md LICENSE ./
COPY src ./src
COPY app ./app
COPY wheels/ ./wheels/

# --find-links vendors the private algovoi-bpverify wheel (real ZK verification);
# pqcrypto + rfc8785 still resolve from PyPI.
RUN pip install --no-cache-dir --find-links=./wheels -e ".[serve,verify]"

RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV ZKP_RECEIPT_BIND=0.0.0.0:8093

EXPOSE 8093

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8093/health || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host $(echo $ZKP_RECEIPT_BIND | cut -d: -f1) --port $(echo $ZKP_RECEIPT_BIND | cut -d: -f2) --log-level info"]
