# Federation Validator Service
# Stateless FastAPI microservice — cross-issuer ZKP credential composition.
#
# POST /compose  — verify N PQC credentials, return composite federation token
# POST /verify   — verify a federation token HMAC + expiry
# GET  /health   — liveness probe
#
# Build context: algovoi-federation-validator/ (not the monorepo root)
# docker build -t algovoi-federation-validator:0.1.0 .

FROM python:3.11-slim

LABEL org.opencontainers.image.title="AlgoVoi Federation Validator"
LABEL org.opencontainers.image.description="Cross-issuer ZKP credential composition without shared trust root. IETF: draft-hopley-x402-federation-zkp-00"
LABEL org.opencontainers.image.vendor="AlgoVoi"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="0.1.0"

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package first for layer caching
COPY pyproject.toml README.md CHANGELOG.md LICENSE ./
COPY src ./src
COPY app ./app
COPY wheels/ ./wheels/

# Install the package with serve + verify extras (Falcon-1024 crypto + FastAPI).
# --find-links vendors the private algovoi-bpverify wheel (real ZK verification).
RUN pip install --no-cache-dir --find-links=./wheels -e ".[serve,verify]"

RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV FEDERATION_BIND=0.0.0.0:8092

EXPOSE 8092

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8092/health || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host $(echo $FEDERATION_BIND | cut -d: -f1) --port $(echo $FEDERATION_BIND | cut -d: -f2) --log-level info"]
